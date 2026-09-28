import json

from dnslib import DNSRecord

from ids_ml_lab.generator import GeneratorConfig, TrafficGenerator, build_dns_attack_query


def _config(**overrides: object) -> GeneratorConfig:
    values: dict[str, object] = {
        "normal_domains": ["www.lab.internal"],
        "normal_paths": ["/"],
        "startup_delay_seconds": 0,
    }
    values.update(overrides)
    return GeneratorConfig.model_validate(values)


def test_dns_attack_query_respects_dns_label_limit() -> None:
    query = build_dns_attack_query("a" * 32, token="b" * 72)
    assert max(map(len, query.split("."))) <= 63
    assert len(DNSRecord.question(query).pack()) > 0


def test_dns_failure_is_recorded_without_raising(tmp_path, monkeypatch) -> None:
    class FailedRequest:
        def send(self, *_args: object, **_kwargs: object) -> None:
            raise UnicodeError("invalid DNS query")

    monkeypatch.setattr(DNSRecord, "question", lambda _query: FailedRequest())
    truth_path = tmp_path / "truth.jsonl"
    generator = TrafficGenerator(_config(), truth_path)
    try:
        generator._dns("a" * 32, attack=True)
    finally:
        generator.http.close()

    record = json.loads(truth_path.read_text(encoding="utf-8"))
    assert record["label"] == 1
    assert record["attack_type"] == "dns_tunnel"
    assert record["delivered"] is False


def test_normal_and_attack_emit_expected_event_counts(tmp_path, monkeypatch) -> None:
    generator = TrafficGenerator(
        _config(dns_probability=1.0, attack_burst_size=4), tmp_path / "truth.jsonl"
    )
    emitted: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        generator, "_dns", lambda event_id, attack: emitted.append((event_id, attack))
    )
    try:
        generator.emit(attack=False)
        generator.emit(attack=True)
    finally:
        generator.http.close()

    assert [attack for _, attack in emitted] == [False, True, True, True, True]
    assert len({event_id for event_id, _ in emitted}) == 5
