"""Inference on input observations using an exported KDD notebook model."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd

from ids_ml_lab.demo import model_scores


def predict(bundle: dict, frame: pd.DataFrame) -> pd.DataFrame:
    missing = set(bundle["raw_features"]) - set(frame.columns)
    if missing:
        raise ValueError(f"Missing input features: {', '.join(sorted(missing))}")
    result = frame[[c for c in ("row_id", "label", "attack_type") if c in frame]].copy()
    result["score"] = model_scores(bundle["pipeline"], frame[bundle["raw_features"]], bundle["kind"])
    result["prediction"] = (result.score >= bundle["threshold"]).astype(int)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True, help="CSV with headers or Parquet with model raw features")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    frame = pd.read_parquet(args.input) if args.input.suffix == ".parquet" else pd.read_csv(args.input)
    bundle = joblib.load(args.model)
    result = predict(bundle, frame)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.output, index=False)
    print(json.dumps({"kind": bundle["kind"], "rows": len(result),
                      "alerts": int(result.prediction.sum()), "output": str(args.output)}))


if __name__ == "__main__":
    main()
