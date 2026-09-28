from __future__ import annotations

import logging
import os
import random
import secrets
import time
import uuid
from pathlib import Path
from typing import Literal

import httpx
import yaml
from dnslib import DNSError, DNSRecord
from prometheus_client import Counter, Gauge, start_http_server
from pydantic import BaseModel, Field

from ids_ml_lab.io import append_jsonl

LOG = logging.getLogger(__name__)
EVENTS = Counter(
    "ids_generator_events_total", "Generated network events", ["label", "service", "attack_type"]
)
ERRORS = Counter("ids_generator_errors_total", "Generator request failures", ["service"])
LAST_EVENT = Gauge("ids_generator_last_event_timestamp_seconds", "Unix time of the last event")
DNS_LABEL_MAX_LENGTH = 63


def build_dns_attack_query(event_id: str, token: str | None = None) -> str:
    """Build a DNS-tunnel-like query without exceeding the DNS label limit."""
    payload = token or secrets.token_hex(36)
    payload_labels = ".".join(
        payload[offset : offset + DNS_LABEL_MAX_LENGTH]
        for offset in range(0, len(payload), DNS_LABEL_MAX_LENGTH)
    )
    return f"evt-{event_id}.{payload_labels}.tunnel.lab.internal"


class GeneratorConfig(BaseModel):
    mode: Literal["normal", "mixed"] = "mixed"
    seed: int = 42
    events_per_second: float = Field(default=2.0, gt=0)
    attack_probability: float = Field(default=0.25, ge=0, le=1)
    dns_probability: float = Field(default=0.55, ge=0, le=1)
    http_base_url: str = "http://lab-service:8080"
    dns_host: str = "lab-service"
    dns_port: int = 5353
    normal_domains: list[str]
    normal_paths: list[str]
    attack_burst_size: int = Field(default=4, ge=1, le=100)
    request_timeout_seconds: float = 2.0
    startup_delay_seconds: float = Field(default=3.0, ge=0)
    metrics_port: int = 9101


def load_config(path: Path) -> GeneratorConfig:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if mode := os.getenv("GENERATOR_MODE"):
        payload["mode"] = mode
    return GeneratorConfig.model_validate(payload)


class TrafficGenerator:
    def __init__(self, config: GeneratorConfig, truth_path: Path) -> None:
        self.config = config
        self.truth_path = truth_path
        self.random = random.Random(config.seed)
        self.http = httpx.Client(timeout=config.request_timeout_seconds)

    def _record(
        self,
        event_id: str,
        label: int,
        service: str,
        attack_type: str,
        delivered: bool,
    ) -> None:
        now = time.time()
        append_jsonl(
            self.truth_path,
            {
                "event_id": event_id,
                "ts": now,
                "label": label,
                "service": service,
                "attack_type": attack_type,
                "generator_mode": self.config.mode,
                "delivered": delivered,
            },
        )
        if delivered:
            EVENTS.labels(str(label), service, attack_type).inc()
            LAST_EVENT.set(now)

    def _dns(self, event_id: str, attack: bool) -> None:
        if attack:
            query = build_dns_attack_query(event_id)
            attack_type = "dns_tunnel"
        else:
            domain = self.random.choice(self.config.normal_domains)
            query = f"evt-{event_id}.{domain}"
            attack_type = "none"
        delivered = False
        try:
            DNSRecord.question(query).send(
                self.config.dns_host,
                self.config.dns_port,
                timeout=self.config.request_timeout_seconds,
            )
            delivered = True
        except (DNSError, OSError, UnicodeError):
            ERRORS.labels("dns").inc()
            LOG.exception("DNS request failed")
        self._record(event_id, int(attack), "dns", attack_type, delivered)

    def _http(self, event_id: str, attack: bool) -> None:
        if attack:
            path = f"/event/evt-{event_id}/burst?token={secrets.token_hex(24)}"
            attack_type = "http_burst"
        else:
            base = self.random.choice(self.config.normal_paths).rstrip("/")
            path = f"{base}/event/evt-{event_id}" if base else f"/event/evt-{event_id}"
            attack_type = "none"
        delivered = False
        try:
            self.http.get(f"{self.config.http_base_url}{path}")
            delivered = True
        except httpx.HTTPError:
            ERRORS.labels("http").inc()
            LOG.exception("HTTP request failed")
        self._record(event_id, int(attack), "http", attack_type, delivered)

    def emit(self, attack: bool = False) -> None:
        count = self.config.attack_burst_size if attack else 1
        for _ in range(count):
            event_id = uuid.uuid4().hex
            if self.random.random() < self.config.dns_probability:
                self._dns(event_id, attack)
            else:
                self._http(event_id, attack)

    def run(self) -> None:
        interval = 1.0 / self.config.events_per_second
        LOG.info("Traffic generator started in %s mode", self.config.mode)
        if self.config.startup_delay_seconds:
            time.sleep(self.config.startup_delay_seconds)
        while True:
            started = time.monotonic()
            attack = self.config.mode == "mixed" and (
                self.random.random() < self.config.attack_probability
            )
            self.emit(attack=attack)
            time.sleep(max(0.0, interval - (time.monotonic() - started)))


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    root = Path.cwd()
    config_path = Path(os.getenv("GENERATOR_CONFIG", root / "config/generator.yaml"))
    truth_path = Path(os.getenv("TRUTH_PATH", root / "runtime/truth/events.jsonl"))
    config = load_config(config_path)
    start_http_server(config.metrics_port)
    TrafficGenerator(config, truth_path).run()


if __name__ == "__main__":
    main()
