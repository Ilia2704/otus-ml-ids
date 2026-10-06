"""Local-only Ollama HTTP calls; no download, cloud fallback or SDK."""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx
from pydantic import ValidationError

from ids_ml_lab.rule_generation import BEHAVIORAL_FIELDS, DetectionSpec

LOG = logging.getLogger(__name__)


def evidence_schema(evidence: dict) -> dict:
    """Constrain capabilities to the observed evidence format, never its ground truth."""
    schema = DetectionSpec.model_json_schema()
    kind = evidence.get("evidence_type")
    if kind not in {"dns_ioc", "dns_windows"}:
        return schema
    properties = schema["properties"]
    properties["protocol"] = {"const": "dns", "type": "string"}
    behavioral = kind == "dns_windows"
    properties["rule_type"] = {"enum": ["behavioral"] if behavioral else ["ioc", "signature"], "type": "string"}
    properties["suricata_compatible"] = {"const": not behavioral, "type": "boolean"}
    properties["requires_correlation"] = {"const": behavioral, "type": "boolean"}
    condition = schema["$defs"]["Condition"]["properties"]
    condition["field"] = {"enum": sorted(BEHAVIORAL_FIELDS) if behavioral else ["dns.query"], "type": "string"}
    condition["operator"] = {"enum": ["gt", "gte"] if behavioral else ["contains", "equals", "endswith"], "type": "string"}
    condition["value"] = {"type": "number", "minimum": 0} if behavioral else {"type": "string", "minLength": 1, "maxLength": 256}
    if behavioral:
        properties["window_seconds"] = {"const": evidence["window_seconds"], "type": "number"}
        properties["correlation_entity"] = {"const": evidence["entity"], "type": "string"}
        choices = evidence.get("candidate_conditions")
        if choices:
            schema["$defs"]["Condition"] = {"oneOf": [
                {"type": "object", "additionalProperties": False,
                 "properties": {key: {"const": value} for key, value in choice.items()},
                 "required": ["field", "operator", "value"]} for choice in choices]}
            properties["conditions"]["minItems"] = 2
            properties["conditions"]["maxItems"] = min(3, len(choices))
    else:
        properties["window_seconds"] = {"type": "null"}
        properties["correlation_entity"] = {"type": "null"}
        properties["conditions"]["maxItems"] = 1
        condition["operator"] = {"const": "endswith", "type": "string"}
        names = evidence.get("observed_names", [])
        if names:
            condition["value"]["enum"] = ["." + event["query"] for event in names]
    return schema


def select_model(models: list[dict], requested: str | None = None) -> dict:
    if requested:
        for model in models:
            if requested in {model.get("name"), model.get("model")}:
                return model
        raise ValueError(f"OLLAMA_MODEL={requested!r} is not installed. No model will be downloaded.")
    candidates = [model for model in models if "qwen" in model["name"].lower()
                  and re.search(r"(?<![\d.])0\.6b(?!\d)", model["name"].lower())]
    if not candidates:
        raise ValueError("No installed Qwen 0.6B model. Set OLLAMA_MODEL to an installed local model; no 4B/cloud fallback.")
    return sorted(candidates, key=lambda model: model["name"])[0]


def parse_response(payload: dict) -> DetectionSpec:
    if payload.get("done") is not True or payload.get("done_reason") == "length":
        raise ValueError("Ollama generation did not complete")
    response = payload.get("response")
    if not isinstance(response, str):
        raise ValueError("Ollama response must contain a JSON string")
    return DetectionSpec.model_validate_json(response)


class OllamaAdapter:
    def __init__(self, settings: dict, transport=None):
        self.settings = settings
        base = os.getenv("OLLAMA_BASE_URL", settings["ollama_base_url"])
        url = urlparse(base)
        if url.scheme != "http" or url.hostname not in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}:
            raise ValueError("OLLAMA_BASE_URL must be a local HTTP Ollama endpoint")
        self.client = httpx.Client(base_url=base, timeout=settings.get("llm_timeout_seconds", 240),
                                   transport=transport, trust_env=False)
        self.model = None

    def close(self) -> None:
        self.client.close()

    def health(self) -> dict:
        try:
            response = self.client.get("/api/tags")
            response.raise_for_status()
            self.model = select_model(response.json().get("models", []),
                                      os.getenv("OLLAMA_MODEL") or self.settings.get("ollama_model"))
            version = self.client.get("/api/version")
            version.raise_for_status()
        except (httpx.HTTPError, json.JSONDecodeError) as error:
            raise RuntimeError(f"Ollama health check failed at {self.client.base_url}: {error}") from error
        LOG.info("[ollama] model: %s", self.model["name"])
        return {"model": self.model["name"], "digest": self.model.get("digest"),
                "ollama_version": version.json().get("version"), "local_only": True}

    def generate(self, evidence: dict, prompt_path: Path, output: Path) -> DetectionSpec:
        metadata = self.health()
        output.mkdir(parents=True, exist_ok=True)
        system = prompt_path.read_text(encoding="utf-8")
        prompt = json.dumps(evidence, indent=2)
        schema = evidence_schema(evidence)
        options = {"temperature": self.settings["llm_temperature"],
                   "seed": self.settings["generator_seed"], "num_predict": 1800,
                   "num_ctx": self.settings.get("llm_context_tokens", 4096)}
        request = {"model": self.model["name"], "system": system,
                   "prompt": prompt + "\n/no_think", "stream": False, "format": schema,
                   "options": options, "keep_alive": 0}
        # Only request think=false if the installed model advertises that capability.
        try:
            show = self.client.post("/api/show", json={"model": self.model["name"]})
            show.raise_for_status()
            if "thinking" in show.json().get("capabilities", []):
                request["think"] = False
        except httpx.HTTPError as error:
            raise RuntimeError(f"Cannot inspect local Ollama model: {error}") from error
        metadata.update({"timestamp": datetime.now(UTC).isoformat(), "parameters": options,
                         "prompt_version": system.splitlines()[0].removeprefix("Prompt version: "),
                         "keep_alive": 0, "schema": schema})
        (output / "prompt.txt").write_text(system + "\n\n" + prompt, encoding="utf-8")
        (output / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        (output / "evidence.json").write_text(prompt, encoding="utf-8")
        for attempt in range(2):
            (output / f"request_{attempt + 1}.json").write_text(json.dumps(request, indent=2))
            try:
                response = self.client.post("/api/generate", json=request)
                response.raise_for_status()
                payload = response.json()
            except (httpx.HTTPError, json.JSONDecodeError) as error:
                raise RuntimeError(f"Local Ollama generation failed: {error}") from error
            (output / f"raw_response_{attempt + 1}.json").write_text(json.dumps(payload, indent=2))
            try:
                spec = parse_response(payload)
                if evidence.get("evidence_type") == "dns_ioc":
                    names = {"." + event["query"] for event in evidence["observed_names"]}
                    if len(spec.conditions) != 1 or spec.conditions[0].operator != "endswith" or spec.conditions[0].value not in names:
                        raise ValueError("DNS IOC must be one endswith condition on one observed stable suffix")
                if evidence.get("candidate_conditions"):
                    if any(condition.model_dump() not in evidence["candidate_conditions"] for condition in spec.conditions):
                        raise ValueError("Behavioral conditions must be selected from the supplied evidence-grounded candidate_conditions")
                    if len({condition.field for condition in spec.conditions}) != len(spec.conditions):
                        raise ValueError("Select distinct behavioral fields")
                (output / "detection_spec.json").write_text(spec.model_dump_json(indent=2))
                LOG.info("[ollama] DetectionSpec validated")
                return spec
            except (ValueError, ValidationError) as error:
                (output / f"validation_error_{attempt + 1}.txt").write_text(str(error))
                if attempt == 1:
                    raise ValueError(f"Invalid DetectionSpec after one controlled retry: {error}") from error
                request["prompt"] = (prompt + "\nPrevious JSON: " + str(payload.get("response", ""))
                                     + "\nCorrect this validation error and return schema JSON only: " + str(error)
                                     + "\n/no_think")
        raise AssertionError("unreachable")
