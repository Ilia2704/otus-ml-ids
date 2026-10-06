"""Small lecture pipeline: discovery, constrained specification and deterministic rendering."""
from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pandas as pd
import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sklearn.ensemble import IsolationForest

from ids_ml_lab.features import DNS_WINDOW_FEATURES, clean_qname, dns_windows

LOG = logging.getLogger(__name__)
NATIVE_FIELDS = {"dns.query", "http.uri", "http.host", "http.user_agent"}
BEHAVIORAL_FIELDS = set(DNS_WINDOW_FEATURES)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class Condition(StrictModel):
    field: Literal[
        "dns.query", "http.uri", "http.host", "http.user_agent",
        "dns_requests", "unique_qnames", "unique_base_domains", "unique_subdomains",
        "avg_qname_length", "max_qname_length", "nxdomain_ratio", "avg_label_entropy",
        "peak_requests_per_second",
    ]
    operator: Literal["contains", "equals", "endswith", "gt", "gte"]
    value: str | float | int


class TestPlan(StrictModel):
    positive_cases: list[str] = Field(min_length=1, max_length=10)
    negative_cases: list[str] = Field(min_length=1, max_length=10)


class DetectionSpec(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=1500)
    evidence: list[str] = Field(min_length=1, max_length=12)
    hypothesis: str = Field(min_length=1, max_length=1500)
    rule_type: Literal["signature", "ioc", "behavioral"]
    protocol: Literal["dns", "http", "tcp", "udp", "tls", "other"]
    source_scope: Literal["any"]
    destination_scope: Literal["any"]
    conditions: list[Condition] = Field(min_length=1, max_length=8)
    severity: Literal["low", "medium", "high"]
    suricata_compatible: bool
    requires_correlation: bool
    correlation_entity: str | None
    window_seconds: float | int | None
    limitations: list[str] = Field(min_length=1, max_length=10)
    test_plan: TestPlan

    @model_validator(mode="after")
    def consistent_capabilities(self):
        behavioral = self.rule_type == "behavioral" or any(
            c.field in BEHAVIORAL_FIELDS or c.operator in {"gt", "gte"} for c in self.conditions
        )
        if behavioral:
            if self.rule_type != "behavioral" or self.suricata_compatible or not self.requires_correlation:
                raise ValueError("Aggregations require behavioral, requires_correlation=true, suricata_compatible=false")
            if not self.correlation_entity or self.window_seconds is None or self.window_seconds <= 0:
                raise ValueError("Behavioral specification requires entity and positive window_seconds")
            if any(c.field not in BEHAVIORAL_FIELDS or c.operator not in {"gt", "gte"}
                   or isinstance(c.value, (str, bool)) or c.value < 0 for c in self.conditions):
                raise ValueError("Behavioral conditions require whitelisted aggregate fields and nonnegative numeric gt/gte")
        elif self.requires_correlation or not self.suricata_compatible:
            raise ValueError("Native specification must be compatible without correlation")
        elif self.correlation_entity is not None or self.window_seconds is not None:
            raise ValueError("Native conditions cannot have a correlation window")
        elif self.protocol not in {"dns", "http"} or any(
            not c.field.startswith(self.protocol + ".") or c.operator not in {"contains", "equals", "endswith"}
            or not isinstance(c.value, str) or not c.value or len(c.value) > 256 for c in self.conditions
        ):
            raise ValueError("Native conditions require whitelisted protocol buffers and nonempty string contains/equals/endswith")
        return self


def render_rule(spec: DetectionSpec, sid: int = 9900001) -> str:
    """Locally controlled header/action/SID; plain safe IOC text, otherwise hex bytes."""
    if not 9900000 <= sid <= 9999999:
        raise ValueError("SID must be in the local candidate range 9900000..9999999")
    if not spec.suricata_compatible or spec.requires_correlation:
        raise ValueError("Behavioral specification requires correlation, not a Suricata signature")
    if spec.protocol not in {"dns", "http"}:
        raise ValueError("Only DNS and HTTP application buffers are supported")
    parts = ['msg:"LOCAL GENERATED candidate";']
    for condition in spec.conditions:
        if condition.field not in NATIVE_FIELDS or not condition.field.startswith(spec.protocol + "."):
            raise ValueError(f"Unsupported field {condition.field!r} for {spec.protocol}")
        if condition.operator not in {"contains", "equals", "endswith"}:
            raise ValueError(f"Unsupported operator {condition.operator}")
        if not isinstance(condition.value, str) or not condition.value or len(condition.value) > 256:
            raise ValueError("Native content requires a nonempty string of at most 256 characters")
        encoded = condition.value.encode("utf-8")
        content = condition.value if re.fullmatch(r"[A-Za-z0-9._/-]+", condition.value) else f'|{encoded.hex(" ").upper()}|'
        parts.extend([f"{condition.field};", f'content:"{content}";'])
        if spec.protocol == "dns" or condition.field == "http.host":
            parts.append("nocase;")
        if condition.operator == "equals":
            parts.append(f"bsize:{len(encoded)};")
        elif condition.operator == "endswith":
            parts.append("endswith;")
    parts.extend([f"sid:{sid};", "rev:1;"])
    return f"alert {spec.protocol} any any -> any any ({' '.join(parts)})\n"


def write_candidate(spec: DetectionSpec, directory: Path, sid: int = 9900001) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for existing in directory.glob("*.rules"):
        if re.search(rf"\bsid\s*:\s*{sid}\s*;", existing.read_text()):
            raise ValueError(f"Duplicate local SID {sid}")
    rule = render_rule(spec, sid)
    path = directory / "candidate.rules"
    with path.open("x", encoding="utf-8") as stream:
        stream.write(rule)
    return path


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        raise ValueError(f"Missing input {path}; capture actual generator traffic first")
    return [json.loads(line) for line in path.read_text().splitlines() if line and not line.startswith("#")]


def safe_dns_events(records: list[dict]) -> list[dict]:
    """Construct evidence using an allowlist, never forward arbitrary input columns."""
    return [{
        "ts": float(r["ts"]), "client": f"{r.get('id.orig_h', '')}:{r.get('id.orig_p', '')}",
        "query": clean_qname(str(r["query"])), "rcode_name": str(r.get("rcode_name", "")),
    } for r in records if r.get("query")]


def ioc_evidence(records: list[dict], baseline: list[dict] | None = None) -> dict:
    events = safe_dns_events(records)
    if not events:
        raise ValueError("No DNS telemetry")
    counts = pd.Series([e["query"] for e in events]).value_counts()
    names = sorted(counts.index, key=lambda name: (-len(name), name))[:12]
    if baseline is not None:
        baseline_names = {event["query"] for event in safe_dns_events(baseline)}
        names = [name for name in names if name not in baseline_names]
        if not names:
            raise ValueError("No novel DNS names relative to baseline; insufficient IOC evidence")
    return {"evidence_type": "dns_ioc", "task": "Form a narrow native DNS IOC candidate from unusual stable names.",
            "total_dns_requests": len(events),
            "observed_names": [{"query": name, "count": int(counts[name])} for name in names],
            "examples": [next(e for e in events if e["query"] == name) for name in names],
            "instrumentation": "Actual wire names have an evt-<opaque-id>. prefix. Do not use its value.",
            "selection": "Names absent from a separate baseline capture" if baseline is not None else "Longest observed names"}


def discover(baseline: list[dict], records: list[dict], settings: dict, output: Path) -> dict:
    window = settings["feature_window_seconds"]
    # Anchor each captured period independently; no label-derived selection or fitting.
    baseline_origin = min(float(r["ts"]) for r in baseline)
    origin = min(float(r["ts"]) for r in records)
    fit = dns_windows(baseline, window, baseline_origin)
    score = dns_windows(records, window, origin)
    if len(fit) < 8 or score.empty:
        raise ValueError("Insufficient DNS baseline windows (need >=8) or no scoring windows")
    model = IsolationForest(n_estimators=200, contamination="auto",
                            random_state=settings["isolation_forest_random_state"], n_jobs=1)
    model.fit(fit[DNS_WINDOW_FEATURES])
    score["anomaly_score"] = -model.score_samples(score[DNS_WINDOW_FEATURES])
    score = score.sort_values("anomaly_score", ascending=False).reset_index(drop=True)
    score["rank"] = score.index + 1
    top = score.head(settings["top_anomalies"])
    output.mkdir(parents=True, exist_ok=True)
    fit.to_parquet(output / "baseline_features.parquet", index=False)
    score[["window_start", "client", *DNS_WINDOW_FEATURES]].to_parquet(output / "features.parquet", index=False)
    score.to_parquet(output / "isolation_forest_scores.parquet", index=False)
    safe = safe_dns_events(records)
    examples = []
    for row in top.to_dict("records"):
        candidates = [e for e in safe if e["client"] == row["client"]
                      and row["window_start"] <= e["ts"] < row["window_start"] + window]
        examples.extend(sorted(candidates, key=lambda e: -len(e["query"]))[:2])
    LOG.info("[iforest] %d baseline windows; top anomalies: %d", len(fit), len(top))
    baseline_stats = {name: {"median": round(float(fit[name].median()), 4),
                             "p95": round(float(fit[name].quantile(.95)), 4)} for name in DNS_WINDOW_FEATURES}
    # A small model selects among evidence-grounded predicates. Never offer a constant feature
    # or a threshold that excludes every anomalous window. No labels inform these limits.
    candidates = []
    for name in ("unique_subdomains", "avg_qname_length", "nxdomain_ratio", "avg_label_entropy", "peak_requests_per_second"):
        p95 = baseline_stats[name]["p95"]
        maximum = float(top[name].max())
        if maximum > p95:
            candidates.append({"field": name, "operator": "gt", "value": round((p95 + maximum) / 2, 4)})
    if len(candidates) < 2:
        raise ValueError("Insufficient elevated behavioral features for a grounded hypothesis")
    return {"evidence_type": "dns_windows", "task": "Interpret anomalous DNS windows as a cautious behavioral hypothesis.",
            "entity": "source IP and persistent UDP source port", "window_seconds": window,
            "baseline": baseline_stats, "candidate_conditions": candidates,
            "top_windows": top.round(4).to_dict("records"), "examples": examples[:5]}


def load_settings(path: Path, demo: bool = False) -> dict:
    settings = yaml.safe_load(path.read_text(encoding="utf-8"))
    if demo or settings.get("demo_profile"):
        settings.update(settings.pop("demo"))
        settings["demo_profile"] = True
    for key in ("generator_seed", "isolation_forest_random_state", "top_anomalies"):
        if not isinstance(settings[key], int) or settings[key] < 0:
            raise ValueError(f"Invalid {key}")
    if settings["top_anomalies"] == 0 or settings["feature_window_seconds"] <= 0:
        raise ValueError("Positive top_anomalies and feature_window_seconds required")
    generator = settings["generator"]
    if generator["events"] < 1 or generator["duration_seconds"] <= 0 or not 0 <= generator["attack_rate"] <= 1:
        raise ValueError("Invalid generator settings")
    return settings


def review_behavioral_spec(spec: DetectionSpec, baseline: pd.DataFrame, top: pd.DataFrame) -> dict:
    """Evidence-only sanity check; no attack labels or automated approval."""
    def matches(frame):
        mask = pd.Series(True, index=frame.index)
        for condition in spec.conditions:
            values = frame[condition.field]
            mask &= values > condition.value if condition.operator == "gt" else values >= condition.value
        return int(mask.sum())
    ranges = [{"field": condition.field, "threshold": condition.value,
               "baseline_p95": round(float(baseline[condition.field].quantile(.95)), 4),
               "top_max": round(float(top[condition.field].max()), 4)} for condition in spec.conditions]
    return {"baseline_windows_matching": matches(baseline), "baseline_windows": len(baseline),
            "top_windows_matching": matches(top), "top_windows": len(top),
            "threshold_evidence": ranges,
            "limitations": "Only an evidence sanity check, not a correlation engine or proof of attack."}


def generate_candidates(run_dir: Path, settings: dict, prompt_path: Path,
                        scenarios: tuple[str, ...] = ("A",)) -> dict:
    from ids_ml_lab.ollama import OllamaAdapter
    from ids_ml_lab.rule_validation import evaluate_run

    adapter = OllamaAdapter(settings)
    results = {}
    try:
        baseline = read_jsonl(run_dir / "baseline/raw/dns.log")
        for scenario in scenarios:
            directory = run_dir / scenario
            records = read_jsonl(directory / "raw/dns.log")
            evidence = ioc_evidence(records, baseline) if scenario == "A" else discover(baseline, records, settings, directory)
            spec = adapter.generate(evidence, prompt_path, directory / "llm")
            if scenario == "B" and spec.suricata_compatible:
                raise ValueError("Behavioral evidence unexpectedly returned a native signature; requires analyst review")
            if spec.suricata_compatible:
                write_candidate(spec, directory / "rules")
                results[scenario] = evaluate_run(directory, settings)
            else:
                results[scenario] = {"decision": "REQUIRES_REVIEW", "status": "manual_review",
                                     "suricata_compatible": False, "requires_correlation": True,
                                     "reason": "Window aggregation needs a correlation detector",
                                     "specification": spec.model_dump()}
                baseline_features = pd.read_parquet(directory / "baseline_features.parquet")
                ranked = pd.read_parquet(directory / "isolation_forest_scores.parquet")
                results[scenario]["evidence_review"] = review_behavioral_spec(
                    spec, baseline_features, ranked.head(settings["top_anomalies"]))
                (directory / "quality_report.json").write_text(json.dumps(results[scenario], indent=2))
    finally:
        adapter.close()
    return results


def copy_capture(source: Path, destination: Path, scenarios: tuple[str, ...] = ("A",)) -> None:
    """Reuse raw traffic only; each demo gets fresh LLM responses and Suricata outputs."""
    if destination.exists():
        raise ValueError(f"Use a new output directory: {destination}")
    parts = ("baseline", *scenarios)
    required = [source / "settings.json"]
    for part in parts:
        required.extend([source / part / "raw/dns.log", source / part / "raw/traffic.pcap"])
        if part != "baseline":
            required.append(source / part / "ground_truth.jsonl")
    for path in required:
        if not path.is_file():
            raise ValueError(f"Missing prepared capture: {path}")
    destination.mkdir(parents=True)
    shutil.copy2(source / "settings.json", destination / "settings.json")
    for part in parts:
        shutil.copytree(source / part / "raw", destination / part / "raw")
        if part != "baseline":
            shutil.copy2(source / part / "ground_truth.jsonl", destination / part / "ground_truth.jsonl")


def main() -> None:
    parser = argparse.ArgumentParser(description="Local automatic rule generation lecture")
    parser.add_argument("command", choices=["capture", "generate", "all", "health"])
    parser.add_argument("--config", type=Path, default=Path("config/rule_generation.yaml"))
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--resume", action="store_true", help="Reuse completed capture periods with matching settings")
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--source", type=Path, help="Prepared capture; generate fresh LLM/replay results in --run-dir")
    parser.add_argument("--scenario", choices=["A", "B", "both"], default="A")
    parser.add_argument("--no-build", action="store_true", help="Use the already built common Python image")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    settings = load_settings(args.config, args.demo)
    scenarios = ("A", "B") if args.scenario == "both" else (args.scenario,)
    if args.source and args.command != "generate":
        parser.error("--source is supported only with generate")
    if args.command == "health":
        from ids_ml_lab.ollama import OllamaAdapter
        adapter = OllamaAdapter(settings)
        try:
            print(json.dumps(adapter.health(), indent=2))
        finally:
            adapter.close()
        return
    run_dir = args.run_dir or Path("artifacts/rule_generation") / datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    try:
        if args.source:
            copy_capture(args.source, run_dir, scenarios)
        if args.command in {"capture", "all"}:
            from ids_ml_lab.rule_validation import capture
            capture(run_dir, settings, resume=args.resume, scenarios=scenarios, build=not args.no_build)
        if args.command in {"generate", "all"}:
            # Saved settings define the time windows and seeds for this capture.
            saved = run_dir / "settings.json"
            if saved.exists():
                settings = json.loads(saved.read_text())
            print(json.dumps(generate_candidates(run_dir, settings, Path("prompts/detection_rule_system.txt"), scenarios), indent=2))
        print(f"Artifacts: {run_dir}")
    except (ValueError, OSError, RuntimeError) as error:
        raise SystemExit(f"[rule-generation] {error}") from error


if __name__ == "__main__":
    main()
