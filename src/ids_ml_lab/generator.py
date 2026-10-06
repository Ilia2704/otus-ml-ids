from __future__ import annotations

import argparse
import json
import logging
import os
import random
import secrets
import socket
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

    def lecture_plan(self, scenario: str, settings: dict) -> list[dict]:
        """Seeded request schedule; truth stays in the execution sidecar only."""
        rng = random.Random(self.config.seed)
        count = int(settings["events"])
        duration = float(settings["duration_seconds"])
        rate = float(settings["attack_rate"])
        suspicious_count = round(count * rate)
        if scenario == "A":
            suspicious = set(rng.sample(range(count), suspicious_count))
        elif scenario == "B":
            # One concentrated episode, rather than independent random anomalies.
            start = count * 3 // 4
            suspicious = set(range(start, min(count, start + suspicious_count)))
        elif scenario == "baseline":
            suspicious = set()
        else:
            raise ValueError("scenario must be A, B or baseline")
        plans = []
        profiles = ["office", "developer", "backend", "service"]
        domains = ["www.office.test", "api.dev.test", "db.backend.test", "health.service.test"]
        for index in range(count):
            is_suspicious = index in suspicious
            client = 1 if scenario == "B" and is_suspicious else rng.choices(range(4), weights=[4, 3, 2, 1])[0]
            event_id = f"{rng.getrandbits(128):032x}"
            protocol = "dns" if is_suspicious or rng.random() < 0.9 else "http"
            domain = domains[client] if rng.random() < 0.8 else "updates.shared.test"
            if is_suspicious and scenario == "A":
                domain = "telemetry-update.bad-example.test"
            elif is_suspicious and scenario == "B":
                token = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=48))
                # No single anomaly-only suffix: same services as baseline.
                domain = f"{token}.{domains[client]}"
            elif rng.random() < 0.02:
                domain = f"missing.{domain}"
            # Labels and this identifier are never used as model inputs.
            query = f"evt-{event_id}.{domain}"
            path = rng.choice(["/", "/health", "/api/catalog", "/static/app.js", "/login"])
            # Four activity sessions with idle intervals and small intra-session jitter.
            progress = (index + 0.25 * rng.random()) / count * 4
            session = int(progress)
            offset = duration / 4 * (session + 0.8 * (progress - session))
            plans.append({
                "event_id": event_id, "client": client, "persona": profiles[client],
                "protocol": protocol, "query": query, "uri": f"{path}/event/evt-{event_id}",
                "offset": offset,
                "label": int(is_suspicious), "scenario": scenario,
            })
        # Compress the suspicious episode into a short burst; background remains session-like.
        if scenario == "B" and suspicious:
            first = min(suspicious)
            anchor = plans[first]["offset"]
            for number, index in enumerate(sorted(suspicious)):
                plans[index]["offset"] = anchor + number * 0.003
        return sorted(plans, key=lambda event: event["offset"])

    def run_lecture(self, scenario: str, settings: dict, run_dir: Path) -> None:
        """Send actual requests with persistent UDP client sessions, not fabricated telemetry."""
        plans = self.lecture_plan(scenario, settings)
        sockets = []
        run_dir.mkdir(parents=True, exist_ok=True)
        started = time.time()
        monotonic_start = time.monotonic()
        try:
            for client in range(4):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("0.0.0.0", 20000 + client))
                sock.settimeout(self.config.request_timeout_seconds)
                sockets.append(sock)
            for event in plans:
                time.sleep(max(0, monotonic_start + event["offset"] - time.monotonic()))
                sent_at = time.time()
                delivered = False
                try:
                    if event["protocol"] == "dns":
                        sock = sockets[event["client"]]
                        question = DNSRecord.question(event["query"])
                        question.header.id = int(event["event_id"][:4], 16)
                        sock.sendto(question.pack(), (self.config.dns_host, self.config.dns_port))
                        response = DNSRecord.parse(sock.recvfrom(4096)[0])
                        delivered = response.header.id == question.header.id
                    else:
                        delivered = self.http.get(self.config.http_base_url + event["uri"]).is_success
                except (OSError, DNSError, httpx.HTTPError):
                    LOG.exception("Lecture request failed")
                append_jsonl(run_dir / "ground_truth.jsonl", {
                    "event_id": event["event_id"], "ts": sent_at,
                    "label": event["label"], "scenario": scenario,
                    "service": event["protocol"], "delivered": delivered,
                })
            time.sleep(max(0, monotonic_start + settings["duration_seconds"] - time.monotonic()))
            ended = time.time()
            (run_dir / "generation.json").write_text(json.dumps({
                "scenario": scenario, "seed": self.config.seed, "started": started,
                "ended": ended, "events": len(plans),
                "suspicious_fraction": sum(e["label"] for e in plans) / len(plans),
                "personas": ["office", "developer", "backend", "service"],
                "client_entity": "source IP and persistent UDP source port",
            }, indent=2), encoding="utf-8")
            LOG.info("[generator] %s: %d requests, suspicious %.3f%%", scenario,
                     len(plans), 100 * sum(e["label"] for e in plans) / len(plans))
        finally:
            for sock in sockets:
                sock.close()


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    root = Path.cwd()
    parser = argparse.ArgumentParser()
    parser.add_argument("--lecture-config", type=Path)
    parser.add_argument("--scenario", choices=["A", "B", "baseline"])
    parser.add_argument("--run-dir", type=Path)
    args = parser.parse_args()
    config_path = Path(os.getenv("GENERATOR_CONFIG", root / "config/generator.yaml"))
    truth_path = Path(os.getenv("TRUTH_PATH", root / "runtime/truth/events.jsonl"))
    config = load_config(config_path)
    if args.lecture_config:
        if not args.scenario or not args.run_dir:
            parser.error("--scenario and --run-dir are required for the lecture")
        settings = yaml.safe_load(args.lecture_config.read_text(encoding="utf-8"))
        config.seed = settings["generator_seed"]
        generator = TrafficGenerator(config, truth_path)
        try:
            generator.run_lecture(args.scenario, settings["generator"], args.run_dir)
        finally:
            generator.http.close()
        return
    start_http_server(config.metrics_port)
    TrafficGenerator(config, truth_path).run()


if __name__ == "__main__":
    main()
