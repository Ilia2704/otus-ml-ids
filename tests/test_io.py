import json

from ids_ml_lab.io import JsonlTailer, append_jsonl


def test_append_and_tail_jsonl(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    append_jsonl(path, {"event_id": "one", "label": 0})
    tailer = JsonlTailer([path])
    assert tailer.poll()[0][1]["event_id"] == "one"
    assert tailer.poll() == []
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"event_id": "two"}) + "\n")
    assert tailer.poll()[0][1]["event_id"] == "two"
