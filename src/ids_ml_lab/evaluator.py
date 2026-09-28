from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from prometheus_client import Counter, Gauge, start_http_server

from ids_ml_lab.io import JsonlTailer

LOG = logging.getLogger(__name__)
MATCHED = Counter("ids_evaluator_matched_events_total", "Matched truth/prediction events")
CONFUSION = Gauge("ids_evaluator_confusion_total", "Cumulative live confusion matrix", ["outcome"])
PRECISION = Gauge("ids_evaluator_precision", "Cumulative live precision")
RECALL = Gauge("ids_evaluator_recall", "Cumulative live recall")
F1 = Gauge("ids_evaluator_f1", "Cumulative live F1")
FPR = Gauge("ids_evaluator_false_positive_rate", "Cumulative live false-positive rate")


@dataclass
class LiveEvaluator:
    truth: dict[str, dict[str, Any]] = field(default_factory=dict)
    predictions: dict[str, dict[str, Any]] = field(default_factory=dict)
    evaluated: set[str] = field(default_factory=set)
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, kind: str, record: dict[str, Any]) -> None:
        if kind == "truth" and record.get("delivered", True) is False:
            return
        event_id = str(record.get("event_id", ""))
        if not event_id:
            return
        target = self.truth if kind == "truth" else self.predictions
        target[event_id] = record
        self._evaluate(event_id)

    def _evaluate(self, event_id: str) -> None:
        if event_id in self.evaluated:
            return
        if event_id not in self.truth or event_id not in self.predictions:
            return
        actual = int(self.truth[event_id]["label"])
        predicted = int(self.predictions[event_id]["prediction"])
        if actual == 1 and predicted == 1:
            self.tp += 1
        elif actual == 0 and predicted == 1:
            self.fp += 1
        elif actual == 1 and predicted == 0:
            self.fn += 1
        else:
            self.tn += 1
        self.evaluated.add(event_id)
        MATCHED.inc()
        self._publish()

    def _publish(self) -> None:
        CONFUSION.labels("tp").set(self.tp)
        CONFUSION.labels("fp").set(self.fp)
        CONFUSION.labels("fn").set(self.fn)
        CONFUSION.labels("tn").set(self.tn)
        precision = self.tp / max(self.tp + self.fp, 1)
        recall = self.tp / max(self.tp + self.fn, 1)
        PRECISION.set(precision)
        RECALL.set(recall)
        F1.set(2 * precision * recall / max(precision + recall, 1e-12))
        FPR.set(self.fp / max(self.fp + self.tn, 1))


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    root = Path.cwd()
    truth_path = Path(os.getenv("TRUTH_PATH", root / "runtime/truth/events.jsonl"))
    predictions_path = Path(
        os.getenv("PREDICTIONS_PATH", root / "runtime/predictions/events.jsonl")
    )
    start_http_server(9103)
    evaluator = LiveEvaluator()
    tailer = JsonlTailer([truth_path, predictions_path])
    LOG.info("Evaluator waiting for ground truth and predictions")
    while True:
        for path, record in tailer.poll():
            evaluator.add("truth" if path == truth_path else "prediction", record)
        time.sleep(0.25)


if __name__ == "__main__":
    main()
