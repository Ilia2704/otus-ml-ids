from __future__ import annotations

import argparse
import json
import platform
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from scipy.stats import ks_2samp
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline

from ids_ml_lab.features import FEATURES
from ids_ml_lab.modeling import (
    anomaly_scores,
    classification_metrics,
    make_pipeline,
    select_threshold,
)


def validate_split(frame: pd.DataFrame, name: str) -> None:
    required = set(FEATURES + ["label", "attack_type"])
    missing = sorted(required.difference(frame.columns))
    if missing:
        raise ValueError(f"{name} split is missing required columns: {missing}")


def fit_pipeline(train_frame: pd.DataFrame, seed: int = 42) -> Pipeline:
    validate_split(train_frame, "train")
    normal_train = train_frame.loc[train_frame["label"] == 0, FEATURES]
    if normal_train.empty:
        raise ValueError("Training split contains no normal rows")
    pipeline = make_pipeline(seed)
    pipeline.fit(normal_train)
    return pipeline


def compute_shap_importance(
    pipeline: Pipeline,
    frame: pd.DataFrame,
    seed: int = 42,
    sample_size: int = 200,
) -> pd.DataFrame:
    import shap

    explain_rows = frame[FEATURES].sample(n=min(sample_size, len(frame)), random_state=seed)
    preprocessor = pipeline.named_steps["preprocessor"]
    forest = pipeline.named_steps["model"]
    transformed = preprocessor.transform(explain_rows)
    transformed_names = preprocessor.get_feature_names_out()
    values = shap.TreeExplainer(forest)(transformed, check_additivity=False).values
    return pd.DataFrame(
        {
            "feature": transformed_names,
            "mean_abs_shap": np.abs(values).mean(axis=0),
        }
    ).sort_values("mean_abs_shap", ascending=False)


def bootstrap_ci(
    y_true: np.ndarray,
    scores: np.ndarray,
    metric,
    iterations: int = 500,
    seed: int = 42,
) -> dict[str, float]:
    rng = np.random.default_rng(seed)
    values: list[float] = []
    for _ in range(iterations):
        indices = rng.integers(0, len(y_true), len(y_true))
        if np.unique(y_true[indices]).size < 2:
            continue
        values.append(float(metric(y_true[indices], scores[indices])))
    low, high = np.quantile(values, [0.025, 0.975])
    return {"estimate": float(metric(y_true, scores)), "low": float(low), "high": float(high)}


def cross_validate(frame: pd.DataFrame, folds: int = 5, seed: int = 42) -> dict[str, object]:
    X = frame[FEATURES]
    y = frame["label"].to_numpy()
    splitter = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
    rows: list[dict[str, float | int]] = []
    for fold, (train_idx, valid_idx) in enumerate(splitter.split(X, y), start=1):
        pipeline = make_pipeline(seed + fold)
        normal_train = X.iloc[train_idx][y[train_idx] == 0]
        pipeline.fit(normal_train)
        scores = anomaly_scores(pipeline, X.iloc[valid_idx])
        rows.append(
            {
                "fold": fold,
                "roc_auc": float(roc_auc_score(y[valid_idx], scores)),
                "pr_auc": float(average_precision_score(y[valid_idx], scores)),
            }
        )
    return {
        "folds": rows,
        "roc_auc_mean": float(np.mean([row["roc_auc"] for row in rows])),
        "roc_auc_std": float(np.std([row["roc_auc"] for row in rows], ddof=1)),
        "pr_auc_mean": float(np.mean([row["pr_auc"] for row in rows])),
        "pr_auc_std": float(np.std([row["pr_auc"] for row in rows], ddof=1)),
    }


def train(data_dir: Path, artifact_dir: Path, seed: int = 42) -> dict[str, object]:
    train_frame = pd.read_parquet(data_dir / "train.parquet")
    validation_frame = pd.read_parquet(data_dir / "validation.parquet")
    test_frame = pd.read_parquet(data_dir / "test.parquet")
    validate_split(validation_frame, "validation")
    validate_split(test_frame, "test")

    pipeline = fit_pipeline(train_frame, seed)

    validation_y = validation_frame["label"].to_numpy()
    validation_scores = anomaly_scores(pipeline, validation_frame[FEATURES])
    threshold = select_threshold(validation_y, validation_scores, max_fpr=0.05)
    test_y = test_frame["label"].to_numpy()
    test_scores = anomaly_scores(pipeline, test_frame[FEATURES])

    ks = ks_2samp(test_scores[test_y == 0], test_scores[test_y == 1])
    report: dict[str, object] = {
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "validation": classification_metrics(validation_y, validation_scores, threshold),
        "test": classification_metrics(test_y, test_scores, threshold),
        "bootstrap_95_ci": {
            "roc_auc": bootstrap_ci(test_y, test_scores, roc_auc_score, seed=seed),
            "pr_auc": bootstrap_ci(test_y, test_scores, average_precision_score, seed=seed + 1),
        },
        "ks": {"statistic": float(ks.statistic), "pvalue": float(ks.pvalue)},
        "cross_validation": cross_validate(train_frame, seed=seed),
    }
    shap_importance = compute_shap_importance(pipeline, validation_frame, seed=seed)

    artifact_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, artifact_dir / "model.joblib", compress=3)
    (artifact_dir / "features.json").write_text(
        json.dumps({"features": FEATURES}, indent=2) + "\n", encoding="utf-8"
    )
    (artifact_dir / "threshold.json").write_text(
        json.dumps(
            {"threshold": threshold, "selection": "maximum validation F1 with FPR <= 0.05"},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (artifact_dir / "validation_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    shap_importance.to_csv(artifact_dir / "shap_importance.csv", index=False)
    metadata = {
        "model": "IsolationForest",
        "trained_on": "normal rows only",
        "random_seed": seed,
        "python": platform.python_version(),
        "scikit_learn": sklearn.__version__,
        "created_at_utc": datetime.now(UTC).isoformat(),
        "dataset_info": "../../data/prepared/dataset_info.json",
    }
    (artifact_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description="Train and export the IDS Isolation Forest")
    parser.add_argument("--data-dir", type=Path, default=root / "data/prepared")
    parser.add_argument("--artifact-dir", type=Path, default=root / "models/ids_iforest_v1")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    report = train(args.data_dir, args.artifact_dir, seed=args.seed)
    print(json.dumps(report["test"], indent=2))


if __name__ == "__main__":
    main()
