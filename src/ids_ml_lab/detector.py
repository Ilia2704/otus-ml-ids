from __future__ import annotations

import json
import logging
import math
import os
import time
from pathlib import Path

import joblib
import pandas as pd
import yaml
from prometheus_client import Counter, Gauge, Histogram, start_http_server
from pydantic import BaseModel, Field

from ids_ml_lab.features import FEATURES, LiveFeatureExtractor, extract_event_id
from ids_ml_lab.io import JsonlTailer, append_jsonl
from ids_ml_lab.modeling import anomaly_scores

LOG = logging.getLogger(__name__)
PREDICTIONS = Counter(
    "ids_detector_predictions_total", "Detector predictions", ["prediction", "source"]
)
SKIPPED = Counter("ids_detector_skipped_total", "Zeek records without an event id", ["source"])
SCORE = Histogram(
    "ids_detector_anomaly_score",
    "Distribution of Isolation Forest anomaly scores",
    buckets=(-0.5, -0.25, -0.1, 0, 0.05, 0.1, 0.2, 0.4, 0.8, 2.0),
)
LAST_EVENT = Gauge("ids_detector_last_event_timestamp_seconds", "Unix time of last prediction")


class DetectorConfig(BaseModel):
    artifact_dir: Path = Path("models/ids_iforest_v1")
    threshold_file: str = "threshold.json"
    model_file: str = "model.joblib"
    zeek_log_dir: Path = Path("runtime/zeek")
    predictions_path: Path = Path("runtime/predictions/events.jsonl")
    poll_interval_seconds: float = Field(default=0.25, gt=0)
    metrics_port: int = 9102
    window_seconds: float = 2.0


def load_config(path: Path, root: Path) -> DetectorConfig:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if value := os.getenv("ZEEK_LOG_DIR"):
        payload["zeek_log_dir"] = value
    if value := os.getenv("PREDICTIONS_PATH"):
        payload["predictions_path"] = value
    config = DetectorConfig.model_validate(payload)
    if not config.artifact_dir.is_absolute():
        config.artifact_dir = root / config.artifact_dir
    if not config.zeek_log_dir.is_absolute():
        config.zeek_log_dir = root / config.zeek_log_dir
    if not config.predictions_path.is_absolute():
        config.predictions_path = root / config.predictions_path
    return config


def validate_artifact_features(artifact_dir: Path, pipeline: object) -> list[str]:
    payload = json.loads((artifact_dir / "features.json").read_text(encoding="utf-8"))
    artifact_features = payload.get("features")
    if artifact_features != FEATURES:
        raise ValueError("Model artifact feature schema does not match the online feature schema")
    fitted_features = list(getattr(pipeline, "feature_names_in_", []))
    if fitted_features and fitted_features != artifact_features:
        raise ValueError("Model pipeline feature schema does not match features.json")
    return artifact_features


class Detector:
    def __init__(self, config: DetectorConfig) -> None:
        self.config = config
        self.pipeline = joblib.load(config.artifact_dir / config.model_file)
        validate_artifact_features(config.artifact_dir, self.pipeline)
        threshold_payload = json.loads(
            (config.artifact_dir / config.threshold_file).read_text(encoding="utf-8")
        )
        self.threshold = float(threshold_payload["threshold"])
        if not math.isfinite(self.threshold):
            raise ValueError("Model threshold must be finite")
        self.extractor = LiveFeatureExtractor(window_seconds=config.window_seconds)
        self.tailer = JsonlTailer(
            [config.zeek_log_dir / "dns.log", config.zeek_log_dir / "http.log"]
        )

    def process(self, source: str, record: dict[str, object]) -> dict[str, object] | None:
        event_id = extract_event_id(record)
        if event_id is None:
            SKIPPED.labels(source).inc()
            return None
        features = self.extractor.transform(record, source)
        frame = pd.DataFrame([features], columns=FEATURES)
        score = float(anomaly_scores(self.pipeline, frame)[0])
        prediction = int(score >= self.threshold)
        output = {
            "event_id": event_id,
            "ts": time.time(),
            "zeek_ts": float(record.get("ts", 0.0)),
            "source": source,
            "score": score,
            "threshold": self.threshold,
            "prediction": prediction,
            "features": features,
        }
        append_jsonl(self.config.predictions_path, output)
        PREDICTIONS.labels("attack" if prediction else "normal", source).inc()
        SCORE.observe(score)
        LAST_EVENT.set(output["ts"])
        return output

    def run(self) -> None:
        LOG.info("Detector watching %s", self.config.zeek_log_dir)
        while True:
            for path, record in self.tailer.poll():
                self.process(path.stem, record)
            time.sleep(self.config.poll_interval_seconds)


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    root = Path.cwd()
    config_path = Path(os.getenv("MODEL_CONFIG", root / "config/model.yaml"))
    config = load_config(config_path, root)
    start_http_server(config.metrics_port)
    Detector(config).run()


if __name__ == "__main__":
    main()
