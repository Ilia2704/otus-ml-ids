"""Actual PCAP capture/replay and a small ground-truth-only quality gate."""
from __future__ import annotations

import json
import logging
import os
import subprocess
import time
import uuid
from pathlib import Path

import yaml

from ids_ml_lab.features import extract_event_id
from ids_ml_lab.rule_generation import read_jsonl

LOG = logging.getLogger(__name__)


def command(argv: list[str], output: Path | None = None, env=None, timeout=300) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(argv, text=True, capture_output=True, env=env, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"Cannot run {argv[0]}: {error}") from error
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("Command: " + json.dumps(argv) + "\n" + result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"{argv[0]} failed ({result.returncode}): {(result.stderr + result.stdout)[-2500:]}")
    return result


def normalize_zeek_logs(directory: Path) -> None:
    """Zeek rotates logs on shutdown. Preserve originals and collect canonical inputs."""
    for source in ("dns", "http"):
        files = list((directory / "raw").glob(source + "*.log"))
        if not files:
            continue
        records = {}
        for path in files:
            for record in read_jsonl(path):
                records[json.dumps(record, sort_keys=True)] = record
        ordered = sorted(records.values(), key=lambda record: float(record.get("ts", 0)))
        (directory / "raw" / f"{source}.log").write_text(
            "".join(json.dumps(record, sort_keys=True) + "\n" for record in ordered))


def capture(run_dir: Path, settings: dict, resume: bool = False,
            scenarios: tuple[str, ...] = ("A",), build: bool = True) -> None:
    """Separate project, existing container definitions, real generator requests and Zeek -w."""
    run_dir = run_dir.resolve()
    if run_dir.exists() and any(run_dir.iterdir()) and not resume:
        raise ValueError(f"Capture directory must be empty: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)
    if resume and ((not (run_dir / "settings.json").exists())
                   or json.loads((run_dir / "settings.json").read_text()) != settings):
        raise ValueError("Resume requires existing capture with exactly matching settings")
    (run_dir / "settings.json").write_text(json.dumps(settings, indent=2))
    project = "ids-rules-" + uuid.uuid4().hex[:10]
    compose = ["docker", "compose", "-p", project, "-f", "docker-compose.yml", "-f", "docker-compose.rules.yml"]
    built = not build
    for scenario in ("baseline", *scenarios):
        directory = run_dir / scenario
        if resume and (directory / "generation.json").exists():
            normalize_zeek_logs(directory)
            if (directory / "raw/traffic.pcap").exists() and (directory / "raw/dns.log").exists():
                LOG.info("[capture] %s: reusing completed capture", scenario)
                continue
            raise ValueError(f"Incomplete capture in {directory}; use a fresh run directory")
        if directory.exists() and any(directory.iterdir()):
            raise ValueError(f"Incomplete capture in {directory}; use a fresh run directory")
        (directory / "raw").mkdir(parents=True)
        env = dict(os.environ, RULE_RUN_DIR=str(directory))
        (directory / "lecture_config.yaml").write_text(yaml.safe_dump(settings))
        try:
            LOG.info("[capture] %s: starting existing generator namespace and Zeek", scenario)
            if not built:
                command([*compose, "build", "generator"], directory / "capture_build.txt", env, timeout=600)
            command([*compose, "up", "--no-build", "-d", "lab-service", "generator", "zeek"],
                    directory / "capture_start.txt", env, timeout=600)
            built = True
            # Wait for actual Zeek initialization, not an arbitrary assumption about startup.
            deadline = time.monotonic() + 30
            while True:
                logs = command([*compose, "logs", "--no-color", "zeek"], env=env).stdout
                (directory / "capture_logs.txt").write_text(logs)
                if (directory / "raw/capture.ready").exists():
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError("Zeek capture did not initialize within 30 seconds")
                time.sleep(.5)
            command([*compose, "exec", "-T", "generator", "/app/.venv/bin/ids-generate",
                     "--lecture-config", "/lecture/lecture_config.yaml", "--scenario", scenario,
                     "--run-dir", "/lecture"], directory / "generator.txt", env,
                    timeout=int(settings["generator"]["duration_seconds"]) + 120)
            time.sleep(1)
            command([*compose, "stop", "-t", "30", "zeek"], directory / "capture_stop.txt", env)
            normalize_zeek_logs(directory)
            if not (directory / "raw/traffic.pcap").exists() or not (directory / "raw/dns.log").exists():
                raise RuntimeError("Zeek did not save PCAP/DNS telemetry")
        finally:
            # Removes only this invocation's project, never the user's default live stack.
            command([*compose, "down", "-v", "--remove-orphans"], directory / "capture_cleanup.txt", env)


def dns_names(event: dict) -> list[str]:
    dns = event.get("dns", {})
    return ([dns["rrname"]] if dns.get("rrname") else []) + [q["rrname"] for q in dns.get("queries", []) if q.get("rrname")]


def event_ids(event: dict) -> set[str]:
    names = dns_names(event)
    http = event.get("http", {})
    values = names + [http.get("url", ""), http.get("hostname", "")]
    return {event_id for value in values if (event_id := extract_event_id({"query": value}))}


def quality_report(truth: list[dict], telemetry: list[dict], eve: list[dict], syntax_valid: bool,
                   settings: dict, rule: str) -> dict:
    expected = {r["event_id"]: r for r in truth if r.get("delivered", True)}
    observed = {event_id for r in telemetry if (event_id := extract_event_id(r))}
    replayed = set()
    transaction_ids: dict[tuple, set[str]] = {}
    for event in eve:
        if event.get("event_type") in {"dns", "http"}:
            ids = event_ids(event)
            replayed.update(ids)
            tx = event.get("tx_id", event.get("dns", {}).get("tx_id"))
            transaction_ids.setdefault((event.get("flow_id"), tx), set()).update(ids)
    matches = set()
    unknown_alerts = 0
    alerts = [e for e in eve if e.get("event_type") == "alert"
              and 9900000 <= e.get("alert", {}).get("signature_id", 0) <= 9999999]
    for alert in alerts:
        ids = event_ids(alert)
        tx = alert.get("tx_id", alert.get("dns", {}).get("tx_id"))
        # Never join by flow alone: persistent UDP sessions have many transactions.
        if not ids and tx is not None:
            ids = transaction_ids.get((alert.get("flow_id"), tx), set())
        known = ids & expected.keys()
        if len(known) != 1:
            unknown_alerts += 1
        else:
            matches.update(known)
    attack = {key for key, value in expected.items() if value["label"] == 1}
    benign = set(expected) - attack
    tp, fp = len(matches & attack), len(matches & benign)
    coverage_missing = len(set(expected) - observed)
    replay_missing = len(set(expected) - replayed)
    attack_recall = tp / len(attack) if attack else None
    benign_rate = fp / len(benign) if benign else None
    complete = not coverage_missing and not replay_missing and not unknown_alerts
    if not syntax_valid:
        decision = "REJECT"
    elif not attack or not benign or not complete:
        decision = "REQUIRES_REVIEW"
    elif attack_recall < settings["min_detection_rate"] or benign_rate > settings["max_benign_match_rate"]:
        decision = "REJECT"
    else:
        decision = "ACCEPT_CANDIDATE"
    return {"generated_rule": rule, "syntax_valid": syntax_valid,
            "expected_attack_events": len(attack), "detected_attack_events": tp,
            "missed_attack_events": len(attack) - tp, "benign_events": len(benign),
            "benign_matches": fp, "alerts_total": len(alerts), "matched_events": len(matches),
            "alerts_per_1000_events": 1000 * len(alerts) / len(expected) if expected else None,
            "precision": tp / (tp + fp) if tp + fp else None,
            "capture_missing_events": coverage_missing, "replay_missing_events": replay_missing,
            "unmatched_or_ambiguous_alerts": unknown_alerts, "decision": decision,
            "status": {"ACCEPT_CANDIDATE": "accepted_candidate", "REJECT": "rejected",
                       "REQUIRES_REVIEW": "manual_review"}[decision],
            "deployment": "none; human approval required",
            "quality_gate": {k: settings[k] for k in ("min_detection_rate", "max_benign_match_rate")}}


def suricata(run_dir: Path, settings: dict, rule_path: Path, output: Path) -> bool:
    output.mkdir(parents=True, exist_ok=False)
    base = ["docker", "run", "--rm", "--network", "none", "--entrypoint", "suricata",
            "-v", f"{run_dir.resolve()}:/lecture", settings["suricata_image"],
            "-c", "/etc/suricata/suricata.yaml", "-S", "/lecture/" + str(rule_path.relative_to(run_dir)),
            "--set", "app-layer.protocols.dns.udp.detection-ports.dp=53,5353",
            "--set", "app-layer.protocols.mdns.enabled=no"]
    # Image-provided default config supplies DNS/HTTP telemetry. Record exact version/image.
    command(["docker", "run", "--rm", "--network", "none", "--entrypoint", "suricata",
             settings["suricata_image"], "--build-info"], output / "build_info.txt")
    image = command(["docker", "image", "inspect", settings["suricata_image"]]).stdout
    (output / "image.json").write_text(image)
    try:
        command([*base, "-T", "-l", "/lecture/" + str(output.relative_to(run_dir))], output / "syntax_check.txt")
    except RuntimeError:
        LOG.info("[suricata] syntax validation: FAIL")
        return False
    LOG.info("[suricata] syntax validation: PASS")
    command([*base, "--runmode", "single", "-k", "none", "-r", "/lecture/raw/traffic.pcap",
             "-l", "/lecture/" + str(output.relative_to(run_dir))], output / "replay.txt")
    return True


def evaluate_run(directory: Path, settings: dict, broad: bool = True) -> dict:
    rule_path = directory / "rules/candidate.rules"
    output = directory / "replay"
    valid = suricata(directory, settings, rule_path, output)
    truth = read_jsonl(directory / "ground_truth.jsonl")
    telemetry = read_jsonl(directory / "raw/dns.log")
    http_path = directory / "raw/http.log"
    if http_path.exists():
        telemetry.extend(read_jsonl(http_path))
    eve = read_jsonl(output / "eve.json") if valid else []
    report = quality_report(truth, telemetry, eve, valid, settings, rule_path.read_text())
    (directory / "quality_report.json").write_text(json.dumps(report, indent=2))
    LOG.info("[replay] detected %d/%d, benign matches %d; %s",
             report["detected_attack_events"], report["expected_attack_events"],
             report["benign_matches"], report["decision"])
    if broad:
        # Deliberately broad negative control, explicitly not an LLM-generated candidate.
        bad_path = directory / "rules/broad_negative_control.rules"
        bad_path.write_text('alert dns any any -> any any (msg:"LOCAL overly broad negative control"; '
                            'dns.query; content:".test"; endswith; sid:9900002; rev:1;)\n')
        bad_output = directory / "broad_replay"
        bad_valid = suricata(directory, settings, bad_path, bad_output)
        bad_eve = read_jsonl(bad_output / "eve.json") if bad_valid else []
        bad_report = quality_report(truth, telemetry, bad_eve, bad_valid, settings, bad_path.read_text())
        (directory / "broad_quality_report.json").write_text(json.dumps(bad_report, indent=2))
    return report
