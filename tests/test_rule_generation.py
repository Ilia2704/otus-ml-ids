import json
import os
from pathlib import Path

import httpx
import pandas as pd
import pytest
from dnslib import DNSRecord
from pydantic import ValidationError

from ids_ml_lab.features import DNS_WINDOW_FEATURES, clean_qname, dns_windows
from ids_ml_lab.generator import GeneratorConfig, TrafficGenerator
from ids_ml_lab.ollama import OllamaAdapter, evidence_schema, parse_response, select_model
from ids_ml_lab.rule_generation import (
    Condition,
    DetectionSpec,
    discover,
    ioc_evidence,
    load_settings,
    render_rule,
    write_candidate,
)
from ids_ml_lab.rule_validation import normalize_zeek_logs, quality_report, suricata


def native_spec(**overrides):
    data = {
        "name": "Synthetic IOC", "description": "Local teaching indicator",
        "evidence": ["Repeated unusual name"], "hypothesis": "May be automated beaconing",
        "rule_type": "ioc", "protocol": "dns", "source_scope": "any", "destination_scope": "any",
        "conditions": [{"field": "dns.query", "operator": "endswith", "value": ".bad-example.test"}],
        "severity": "medium", "suricata_compatible": True, "requires_correlation": False,
        "correlation_entity": None, "window_seconds": None,
        "limitations": ["Synthetic IOC is not evidence of compromise"],
        "test_plan": {"positive_cases": ["IOC query"], "negative_cases": ["Normal query"]},
    }
    data.update(overrides)
    return DetectionSpec.model_validate(data)


@pytest.fixture
def settings():
    return load_settings(Path("config/rule_generation.yaml"), demo=True)


def plans_to_records(plans, origin=100):
    """Unit-only network adapter; end-to-end demo exclusively uses captured Zeek logs."""
    return [{"ts": origin + e["offset"], "id.orig_h": "192.0.2.1", "id.orig_p": 20000 + e["client"],
             "query": e["query"], "rcode_name": "NXDOMAIN" if e["label"] or "missing." in e["query"] else "NOERROR"}
            for e in plans if e["protocol"] == "dns"]


def test_generator_reproducible_seed(tmp_path, settings):
    generator = TrafficGenerator(GeneratorConfig(normal_domains=["normal.test"], normal_paths=["/"]), tmp_path / "truth")
    try:
        for scenario in ["baseline", "A", "B"]:
            first = generator.lecture_plan(scenario, settings["generator"])
            second = generator.lecture_plan(scenario, settings["generator"])
            assert first == second
            assert len(first) == settings["generator"]["events"]
            assert all(len(DNSRecord.question(e["query"]).pack()) for e in first)
            if scenario != "baseline":
                assert sum(e["label"] for e in first) == round(len(first) * settings["generator"]["attack_rate"])
    finally:
        generator.http.close()


def test_ground_truth_not_in_features():
    records = [{"ts": 1, "query": "evt-" + "a" * 32 + ".www.office.test", "label": 1,
                "scenario_name": "secret", "is_attack": True, "id.orig_h": "192.0.2.1", "id.orig_p": 20000}]
    first = dns_windows(records)
    records.append({**records[0], "query": "evt-" + "b" * 32 + ".www.office.test"})
    features = dns_windows(records)
    assert set(features.columns) == {"window_start", "client", *DNS_WINDOW_FEATURES}
    assert features.iloc[0]["unique_qnames"] == 1
    assert features.iloc[0]["avg_label_entropy"] == first.iloc[0]["avg_label_entropy"]
    assert clean_qname(records[0]["query"]) == "www.office.test"


def test_ground_truth_not_sent_to_llm(settings, tmp_path):
    records = [{"ts": 1, "query": "evt-" + "a" * 32 + ".www.office.test", "label": "SECRET_LABEL",
                "scenario_name": "SECRET_SCENARIO", "is_attack": "SECRET_ATTACK"}]
    evidence = ioc_evidence(records)
    seen = []
    def handle(request):
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "hf.co/Qwen/Qwen3-0.6B-GGUF:Q8_0", "digest": "abc"}]})
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "test"})
        if request.url.path == "/api/show":
            return httpx.Response(200, json={"capabilities": []})
        seen.append(request.content.decode())
        mock_spec = native_spec(conditions=[{"field": "dns.query", "operator": "endswith", "value": ".www.office.test"}])
        return httpx.Response(200, json={"done": True, "response": mock_spec.model_dump_json()})
    adapter = OllamaAdapter(settings, transport=httpx.MockTransport(handle))
    try:
        adapter.generate(evidence, Path("prompts/detection_rule_system.txt"), tmp_path)
    finally:
        adapter.close()
    assert len(seen) == 1
    assert all(secret not in seen[0] for secret in ["SECRET_LABEL", "SECRET_SCENARIO", "SECRET_ATTACK", "a" * 32])


def test_detection_spec_validation():
    with pytest.raises(ValidationError):
        native_spec(action="drop")
    with pytest.raises(ValidationError):
        native_spec(conditions=[{"field": "unique_subdomains", "operator": "gt", "value": 300}])
    spec = native_spec(rule_type="behavioral", suricata_compatible=False, requires_correlation=True,
                       correlation_entity="src_ip", window_seconds=60,
                       conditions=[{"field": "unique_subdomains", "operator": "gt", "value": 300}])
    with pytest.raises(ValueError, match="correlation"):
        render_rule(spec)
    with pytest.raises(ValidationError):
        native_spec(severity="critical")


def test_renderer_rejects_unsupported_fields():
    # Defense in depth: renderer must reject unsupported fields even if validation is bypassed.
    spec = native_spec().model_copy(update={"conditions": [Condition.model_construct(
        field="dns.made_up", operator="contains", value="x")]})
    with pytest.raises(ValueError, match="Unsupported field"):
        render_rule(spec)
    with pytest.raises(ValueError):
        render_rule(native_spec().model_copy(update={"protocol": "tcp"}))


@pytest.mark.parametrize("value", ['x"; drop tcp any any -> any any (sid:1;) #', "abc|00|\\;\nreject", "pass"])
def test_renderer_never_generates_drop(value):
    rule = render_rule(native_spec(conditions=[{"field": "dns.query", "operator": "contains", "value": value}]))
    assert rule.startswith("alert dns ") and rule.count("\n") == 1
    assert rule.split("(", 1)[0].split()[0] == "alert"
    if any(character in value for character in ['"', ';', '\\', '\n']):
        assert "drop" not in rule and "reject" not in rule
    assert rule.count("sid:") == 1


def test_renderer_produces_valid_candidate_rule(tmp_path):
    spec = native_spec()
    rule = render_rule(spec)
    assert "dns.query;" in rule and "endswith;" in rule and "sid:9900001;" in rule
    assert rule == render_rule(spec)
    path = write_candidate(spec, tmp_path)
    assert path.read_text() == rule
    with pytest.raises(ValueError, match="Duplicate"):
        write_candidate(spec, tmp_path)
    with pytest.raises(ValueError, match="SID"):
        render_rule(spec, sid=1)


def test_ollama_response_parser():
    assert parse_response({"done": True, "response": native_spec().model_dump_json()}).protocol == "dns"
    for payload in [{"done": True, "response": "```json\n{}\n```"}, {"response": "{}"},
                    {"done": True, "response": "{}", "done_reason": "length"}]:
        with pytest.raises(ValueError):
            parse_response(payload)


def test_model_discovery_no_download():
    models = [{"name": "qwen3:14b"}, {"name": "hf.co/Qwen/Qwen3-4B-GGUF:Q4_K_M"}, {"name": "hf.co/Qwen/Qwen3-0.6B-GGUF:Q8_0"}, {"name": "qwen:0.4b"}]
    assert select_model(models)["name"] == models[2]["name"]
    assert select_model(models, "qwen3:14b")["name"] == "qwen3:14b"
    with pytest.raises(ValueError, match="not installed"):
        select_model(models, "missing")
    with pytest.raises(ValueError, match="No installed"):
        select_model([models[0], models[1], models[3]])


def test_schema_constrains_observed_evidence_capabilities():
    native = evidence_schema({"evidence_type": "dns_ioc"})
    assert native["$defs"]["Condition"]["properties"]["field"]["enum"] == ["dns.query"]
    assert native["properties"]["requires_correlation"]["const"] is False
    behavioral = evidence_schema({"evidence_type": "dns_windows", "entity": "src", "window_seconds": 60})
    assert behavioral["properties"]["suricata_compatible"]["const"] is False
    assert behavioral["properties"]["window_seconds"]["const"] == 60


def test_ollama_one_controlled_retry(settings, tmp_path):
    calls = []
    def handle(request):
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "hf.co/Qwen/Qwen3-0.6B-GGUF:Q8_0"}]})
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "test"})
        if request.url.path == "/api/show":
            return httpx.Response(200, json={"capabilities": []})
        calls.append(json.loads(request.content))
        return httpx.Response(200, json={"done": True, "response": "{}"})
    adapter = OllamaAdapter(settings, transport=httpx.MockTransport(handle))
    try:
        with pytest.raises(ValueError, match="one controlled retry"):
            adapter.generate({"examples": []}, Path("prompts/detection_rule_system.txt"), tmp_path)
    finally:
        adapter.close()
    assert len(calls) == 2
    assert "validation error" in calls[1]["prompt"]
    assert (tmp_path / "raw_response_2.json").exists()


def test_local_ollama_only(settings):
    with pytest.raises(ValueError, match="local HTTP"):
        OllamaAdapter({**settings, "ollama_base_url": "https://external.example"})


def test_isolation_forest_scores_anomalous_profile_higher_than_baseline(tmp_path, settings):
    generator = TrafficGenerator(GeneratorConfig(normal_domains=["normal.test"], normal_paths=["/"]), tmp_path / "truth")
    try:
        baseline = plans_to_records(generator.lecture_plan("baseline", settings["generator"]))
        mixed_plans = generator.lecture_plan("B", settings["generator"])
        mixed = plans_to_records(mixed_plans, origin=200)
    finally:
        generator.http.close()
    discover(baseline, mixed, settings, tmp_path / "b")
    scores = pd.read_parquet(tmp_path / "b/isolation_forest_scores.parquet")
    anomalous = scores[scores.unique_subdomains > 20]
    regular = scores[scores.unique_subdomains < 10]
    assert not anomalous.empty and not regular.empty
    assert anomalous.anomaly_score.max() > regular.anomaly_score.median()
    # Anomaly discovery ranks several candidates; harmless unusual windows are expected.
    assert scores.head(settings["top_anomalies"]).unique_subdomains.max() > 20


def test_quality_report_counts_missing_alerts_and_deduplicates(settings):
    a, b, c = "a" * 32, "b" * 32, "c" * 32
    truth = [{"event_id": a, "label": 1}, {"event_id": b, "label": 1}, {"event_id": c, "label": 0}]
    telemetry = [{"query": f"evt-{key}.example.test"} for key in [a, b, c]]
    eve = [{"event_type": "dns", "dns": {"queries": [{"rrname": r["query"]}]}} for r in telemetry]
    alert = {"event_type": "alert", "alert": {"signature_id": 9900001},
             "dns": {"queries": [{"rrname": telemetry[0]["query"]}]}}
    report = quality_report(truth, telemetry, [*eve, alert, alert], True, settings, "alert dns")
    assert report["detected_attack_events"] == 1 and report["missed_attack_events"] == 1
    assert report["alerts_total"] == 2 and report["matched_events"] == 1
    assert report["decision"] == "REJECT"
    report = quality_report(truth, [], [*eve, alert], True, settings, "alert dns")
    assert report["decision"] == "REQUIRES_REVIEW" and report["capture_missing_events"] == 3


def test_quality_report_broad_valid_rule_rejected(settings):
    ids = ["a" * 32, "b" * 32]
    truth = [{"event_id": key, "label": int(index == 0)} for index, key in enumerate(ids)]
    telemetry = [{"query": f"evt-{key}.example.test"} for key in ids]
    eve = [{"event_type": "dns", "dns": {"queries": [{"rrname": row["query"]}]}} for row in telemetry]
    eve += [{"event_type": "alert", "alert": {"signature_id": 9900001},
             "dns": {"queries": [{"rrname": row["query"]}]}} for row in telemetry]
    report = quality_report(truth, telemetry, eve, True, settings, "alert dns")
    assert report["syntax_valid"] and report["benign_matches"] == 1 and report["decision"] == "REJECT"


def test_rotated_zeek_logs_are_collected_without_duplication(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "dns.2026-10-05.log").write_text(json.dumps({"ts": 1, "query": "first.test"}) + "\n")
    (raw / "dns.log").write_text(json.dumps({"ts": 2, "query": "second.test"}) + "\n")
    normalize_zeek_logs(tmp_path)
    normalize_zeek_logs(tmp_path)
    rows = [json.loads(line) for line in (raw / "dns.log").read_text().splitlines()]
    assert [row["query"] for row in rows] == ["first.test", "second.test"]
    assert (raw / "dns.2026-10-05.log").exists()


@pytest.mark.integration
@pytest.mark.skipif(os.getenv("RUN_OLLAMA_INTEGRATION") != "1", reason="Opt-in local Qwen")
def test_local_qwen_integration(settings, tmp_path):
    adapter = OllamaAdapter(settings)
    evidence = ioc_evidence([{"ts": 1, "query": "evt-" + "a" * 32 + ".telemetry-update.bad-example.test"}])
    try:
        spec = adapter.generate(evidence, Path("prompts/detection_rule_system.txt"), tmp_path)
    finally:
        adapter.close()
    assert spec.suricata_compatible and render_rule(spec).startswith("alert dns")


@pytest.mark.integration
@pytest.mark.skipif(os.getenv("RUN_SURICATA_INTEGRATION") != "1", reason="Opt-in real captured replay")
def test_suricata_integration(settings, tmp_path):
    # Capture is deliberately separate; integration never invents a second packet generator.
    run_dir = Path(os.environ["RULE_RUN_DIR"]).resolve()
    rule = run_dir / "rules/integration.rules"
    rule.parent.mkdir(exist_ok=True)
    rule.write_text(render_rule(native_spec(), sid=9900003))
    output = run_dir / ("integration_replay_" + tmp_path.name)
    assert suricata(run_dir, settings, rule, output)
    assert (output / "eve.json").stat().st_size > 0


def test_copy_capture_does_not_reuse_llm_or_replay(tmp_path):
    from ids_ml_lab.rule_generation import copy_capture

    source = tmp_path / "source"
    source.mkdir()
    (source / "settings.json").write_text('{}')
    for part in ("baseline", "A"):
        (source / part / "raw").mkdir(parents=True)
        (source / part / "raw/dns.log").write_text('{}\n')
        (source / part / "raw/traffic.pcap").write_bytes(b'pcap')
    (source / "A/ground_truth.jsonl").write_text('{}\n')
    (source / "A/llm").mkdir()
    (source / "A/llm/detection_spec.json").write_text('old response')
    destination = tmp_path / "fresh"
    copy_capture(source, destination)
    assert (destination / "A/raw/traffic.pcap").read_bytes() == b'pcap'
    assert not (destination / "A/llm").exists()
    assert not (destination / "B").exists()
    with pytest.raises(ValueError, match="new output directory"):
        copy_capture(source, destination)
    with pytest.raises(ValueError, match="Missing prepared capture"):
        copy_capture(source, tmp_path / "both", ("A", "B"))
    assert not (tmp_path / "both").exists()
