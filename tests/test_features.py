from ids_ml_lab.features import FEATURES, LiveFeatureExtractor, extract_event_id


def test_extract_event_id_from_dns_and_http() -> None:
    event_id = "0123456789abcdef0123456789abcdef"
    assert extract_event_id({"query": f"evt-{event_id}.www.lab.internal"}) == event_id
    assert extract_event_id({"uri": f"/event/evt-{event_id}"}) == event_id
    assert extract_event_id({"query": "www.example.org"}) is None


def test_live_features_follow_training_schema() -> None:
    extractor = LiveFeatureExtractor(window_seconds=2.0)
    features = extractor.transform(
        {
            "ts": 10.0,
            "query": "www.lab.internal",
            "rcode_name": "NOERROR",
            "answers": ["A 1.2.3.4"],
        },
        "dns",
    )
    assert list(features) == FEATURES
    assert features["protocol_type"] == "udp"
    assert features["service"] == "domain_u"
    assert features["count"] == 1
    assert features["serror_rate"] == 0.0


def test_live_window_drops_old_events() -> None:
    extractor = LiveFeatureExtractor(window_seconds=2.0)
    extractor.transform({"ts": 1.0, "query": "a", "rcode_name": "NOERROR"}, "dns")
    second = extractor.transform({"ts": 4.0, "query": "b", "rcode_name": "NOERROR"}, "dns")
    assert second["count"] == 1
