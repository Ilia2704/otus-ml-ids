from __future__ import annotations

import re
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any

from dataset_builder.schema import CATEGORICAL_FEATURES, FEATURES, NUMERIC_FEATURES

EVENT_ID_RE = re.compile(r"evt-([0-9a-f]{32})", re.IGNORECASE)


def extract_event_id(record: dict[str, Any]) -> str | None:
    haystack = " ".join(str(record.get(key, "")) for key in ("query", "uri", "host"))
    match = EVENT_ID_RE.search(haystack)
    return match.group(1).lower() if match else None


@dataclass
class LiveFeatureExtractor:
    window_seconds: float = 2.0
    events: deque[tuple[float, str, bool]] = field(default_factory=deque)
    destination_events: Counter[str] = field(default_factory=Counter)

    def _trim(self, now: float) -> None:
        while self.events and now - self.events[0][0] > self.window_seconds:
            _, service, _ = self.events.popleft()
            self.destination_events[service] -= 1

    def transform(self, record: dict[str, Any], source: str) -> dict[str, Any]:
        now = float(record.get("ts", 0.0))
        service = "domain_u" if source == "dns" else "http"
        protocol = "udp" if source == "dns" else "tcp"
        if source == "dns":
            failed = str(record.get("rcode_name", "NOERROR")) not in {"NOERROR", "0"}
            src_bytes = len(str(record.get("query", "")))
            answers = record.get("answers", []) or []
            dst_bytes = sum(len(str(answer)) for answer in answers)
        else:
            status = int(record.get("status_code", 200) or 200)
            failed = status >= 400
            src_bytes = int(record.get("request_body_len", 0) or 0) + len(
                str(record.get("uri", ""))
            )
            dst_bytes = int(record.get("response_body_len", 0) or 0)

        self._trim(now)
        self.events.append((now, service, failed))
        self.destination_events[service] += 1
        count = len(self.events)
        srv_count = sum(event_service == service for _, event_service, _ in self.events)
        errors = sum(event_failed for _, _, event_failed in self.events)
        srv_errors = sum(
            event_failed
            for _, event_service, event_failed in self.events
            if event_service == service
        )

        features: dict[str, Any] = {
            "protocol_type": protocol,
            "service": service,
            "flag": "REJ" if failed else "SF",
            "duration": float(record.get("rtt", 0.0) or 0.0),
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": errors / count,
            "srv_serror_rate": srv_errors / srv_count,
            "rerror_rate": float(failed),
            "same_srv_rate": srv_count / count,
            "diff_srv_rate": 1.0 - (srv_count / count),
            "dst_host_count": count,
            "dst_host_srv_count": self.destination_events[service],
            "dst_host_same_srv_rate": srv_count / count,
        }
        return {name: features[name] for name in FEATURES}


__all__ = [
    "CATEGORICAL_FEATURES",
    "FEATURES",
    "NUMERIC_FEATURES",
    "LiveFeatureExtractor",
    "extract_event_id",
]
