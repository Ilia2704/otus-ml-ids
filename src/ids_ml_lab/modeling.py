from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, RobustScaler

from ids_ml_lab.features import CATEGORICAL_FEATURES, NUMERIC_FEATURES


def make_pipeline(seed: int = 42) -> Pipeline:
    preprocessor = ColumnTransformer(
        [
            (
                "categorical",
                OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                CATEGORICAL_FEATURES,
            ),
            ("numeric", RobustScaler(), NUMERIC_FEATURES),
        ],
        verbose_feature_names_out=False,
    )
    model = IsolationForest(
        n_estimators=300,
        max_samples="auto",
        contamination="auto",
        random_state=seed,
        n_jobs=-1,
    )
    return Pipeline([("preprocessor", preprocessor), ("model", model)])


def anomaly_scores(pipeline: Pipeline, frame: pd.DataFrame) -> np.ndarray:
    return -pipeline.decision_function(frame)


def select_threshold(y_true: np.ndarray, scores: np.ndarray, max_fpr: float = 0.05) -> float:
    candidates = np.unique(np.quantile(scores, np.linspace(0.01, 0.99, 400)))
    best: tuple[float, float] | None = None
    for threshold in candidates:
        predictions = (scores >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
        fpr = fp / max(tn + fp, 1)
        f1 = f1_score(y_true, predictions, zero_division=0)
        if fpr <= max_fpr and (best is None or f1 > best[0]):
            best = (f1, float(threshold))
    if best is not None:
        return best[1]
    return float(np.quantile(scores[y_true == 0], 1.0 - max_fpr))


def classification_metrics(
    y_true: np.ndarray, scores: np.ndarray, threshold: float
) -> dict[str, Any]:
    predictions = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    return {
        "roc_auc": float(roc_auc_score(y_true, scores)),
        "pr_auc": float(average_precision_score(y_true, scores)),
        "accuracy": float(accuracy_score(y_true, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, predictions)),
        "precision": float(precision_score(y_true, predictions, zero_division=0)),
        "recall": float(recall_score(y_true, predictions, zero_division=0)),
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "specificity": float(tn / max(tn + fp, 1)),
        "false_positive_rate": float(fp / max(tn + fp, 1)),
        "matthews_corrcoef": float(matthews_corrcoef(y_true, predictions)),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "threshold": float(threshold),
    }
