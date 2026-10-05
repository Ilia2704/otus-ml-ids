"""CLI inference for the full-KDD demo bundles (not the live Zeek detector)."""

import argparse
import json
import sys
from pathlib import Path

import joblib

from ids_ml_lab.demo import load_full_data, model_scores

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--model", type=Path, required=True)
parser.add_argument("--split", choices=["train", "validation", "test"], default="test")
parser.add_argument("--output", type=Path)
args = parser.parse_args()
if Path(sys.prefix).resolve() != (root / ".venv").resolve():
    raise SystemExit("Use uv run --all-groups python scripts/predict_demo.py ...")
bundle = joblib.load(args.model)
_, splits, _, _, _ = load_full_data(root, seed=bundle["metadata"]["seed"])
frame = splits[args.split]
score = model_scores(bundle["pipeline"], frame[bundle["raw_features"]], bundle["kind"])
result = frame[["row_id", "label", "attack_type"]].copy()
result["score"] = score
result["prediction"] = (score >= bundle["threshold"]).astype(int)
if args.output:
    result.to_csv(args.output, index=False)
print(
    json.dumps(
        {
            "python": sys.executable,
            "kind": bundle["kind"],
            "rows": len(result),
            "alerts": int(result.prediction.sum()),
            "threshold": bundle["threshold"],
        }
    )
)
