from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")
        stream.flush()


class JsonlTailer:
    """Small polling tailer that also survives log rotation/truncation."""

    def __init__(self, paths: list[Path]) -> None:
        self.paths = paths
        self._positions: dict[Path, int] = {path: 0 for path in paths}

    def poll(self) -> list[tuple[Path, dict[str, Any]]]:
        records: list[tuple[Path, dict[str, Any]]] = []
        for path in self.paths:
            if not path.exists():
                continue
            size = path.stat().st_size
            position = self._positions[path]
            if size < position:
                position = 0
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                stream.seek(position)
                while line := stream.readline():
                    try:
                        records.append((path, json.loads(line)))
                    except json.JSONDecodeError:
                        continue
                self._positions[path] = stream.tell()
        return records
