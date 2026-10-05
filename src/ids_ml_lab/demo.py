"""Serializable building blocks shared by the two full-data teaching notebooks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from catboost import CatBoostClassifier
from scipy.stats import ks_2samp
from sklearn.base import BaseEstimator, TransformerMixin, clone
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    log_loss,
    matthews_corrcoef,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from dataset_builder.build_dataset import SOURCE_SHA256
from dataset_builder.schema import CATEGORICAL_FEATURES, KDD_COLUMNS

RAW_FEATURES = KDD_COLUMNS[:-1]
DERIVED = {
    "total_bytes": "src_bytes + dst_bytes",
    "src_byte_share": "src_bytes / (total_bytes + 1)",
    "bytes_per_second": "total_bytes / (duration + 1); сглаженная интенсивность",
    "zero_bytes": "total_bytes == 0",
    "srv_count_share": "srv_count / (count + 1)",
    "host_srv_share": "dst_host_srv_count / (dst_host_count + 1)",
    "log_duration": "log1p(duration)",
    "log_src_bytes": "log1p(src_bytes)",
    "log_dst_bytes": "log1p(dst_bytes)",
    "log_total_bytes": "log1p(total_bytes)",
    "log_bytes_per_second": "log1p(bytes_per_second)",
}


def load_full_data(root: Path, seed: int = 42):
    source = root / "data/source/kddcup.data_10_percent.gz"
    checksum = hashlib.sha256(source.read_bytes()).hexdigest()
    if checksum != SOURCE_SHA256:
        raise ValueError("Source checksum mismatch")
    raw = pd.read_csv(source, names=KDD_COLUMNS, compression="gzip", low_memory=False)
    raw["attack_type"] = raw.attack_type.str.rstrip(".")
    raw["label"] = (raw.attack_type != "normal").astype("int8")
    # Keep one row for each feature vector; contradictory binary labels are excluded explicitly.
    keys = pd.util.hash_pandas_object(raw[RAW_FEATURES], index=False)
    label_counts = raw.label.groupby(keys).nunique()
    conflict_keys = label_counts.index[label_counts > 1]
    conflict_mask = keys.isin(conflict_keys)
    clean = raw.loc[~conflict_mask].drop_duplicates(subset=RAW_FEATURES).copy()
    clean["row_id"] = clean.index
    train, holdout = train_test_split(clean, test_size=0.4, stratify=clean.label, random_state=seed)
    validation, test = train_test_split(
        holdout, test_size=0.5, stratify=holdout.label, random_state=seed
    )
    splits = {
        "train": train.reset_index(drop=True),
        "validation": validation.reset_index(drop=True),
        "test": test.reset_index(drop=True),
    }
    keysets = [
        set(pd.util.hash_pandas_object(f[RAW_FEATURES], index=False)) for f in splits.values()
    ]
    assert all(not keysets[i].intersection(keysets[j]) for i in range(3) for j in range(i))
    assert sum(map(len, splits.values())) == len(clean)
    manifest = json.loads((root / "data/prepared/dataset_info.json").read_text())
    prepared = {}
    for name in splits:
        path = root / f"data/prepared/{name}.parquet"
        assert (
            hashlib.sha256(path.read_bytes()).hexdigest() == manifest["files"][path.name]["sha256"]
        )
        prepared[name] = pd.read_parquet(path)
        assert len(prepared[name]) == manifest["files"][path.name]["rows"]
    audit = {
        "source_rows": len(raw),
        "unique_feature_rows": len(clean),
        "conflicting_label_rows": int(conflict_mask.sum()),
        "redundant_rows_removed": len(raw) - int(conflict_mask.sum()) - len(clean),
        "source_sha256": checksum,
        "seed": seed,
    }
    return raw, splits, prepared, manifest, audit


class NetworkFeatures(TransformerMixin, BaseEstimator):
    """Stateless, target-free engineering; preserves named categorical columns."""

    def fit(self, X, y=None):
        self.feature_names_in_ = np.asarray(X.columns, dtype=object)
        return self

    def transform(self, X):
        out = X[RAW_FEATURES].copy()
        for col in CATEGORICAL_FEATURES:
            out[col] = out[col].astype("string").fillna("__MISSING__").astype(str)
        nums = [c for c in RAW_FEATURES if c not in CATEGORICAL_FEATURES]
        out[nums] = (
            out[nums].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
        )
        out["total_bytes"] = out.src_bytes + out.dst_bytes
        out["src_byte_share"] = out.src_bytes / (out.total_bytes + 1)
        out["bytes_per_second"] = out.total_bytes / (out.duration + 1)
        out["zero_bytes"] = (out.total_bytes == 0).astype(int)
        out["srv_count_share"] = out.srv_count / (out["count"] + 1)
        out["host_srv_share"] = out.dst_host_srv_count / (out.dst_host_count + 1)
        for col in ["duration", "src_bytes", "dst_bytes", "total_bytes", "bytes_per_second"]:
            out[f"log_{col}"] = np.log1p(out[col].clip(lower=0))
        return out.replace([np.inf, -np.inf], np.nan)

    def get_feature_names_out(self, input_features=None):
        return np.asarray(RAW_FEATURES + list(DERIVED), dtype=object)


class CorrelationSelector(TransformerMixin, BaseEstimator):
    """Train-only Spearman pruning with deterministic name-order tie breaking."""

    def __init__(self, threshold=0.90):
        self.threshold = threshold

    def fit(self, X, y=None):
        self.feature_names_in_ = np.asarray(X.columns, dtype=object)
        numeric = X.select_dtypes(include="number")
        self.correlation_ = numeric.corr(method="spearman")
        kept, removed = [], []
        for col in X.columns:
            if X[col].nunique(dropna=False) <= 1:
                removed.append(
                    {"removed": col, "retained": None, "correlation": None, "reason": "constant"}
                )
                continue
            duplicates = [k for k in kept if X[col].equals(X[k])]
            correlated = [
                k
                for k in kept
                if col in numeric
                and k in numeric
                and abs(self.correlation_.loc[col, k]) >= self.threshold
            ]
            if duplicates or correlated:
                other = (duplicates or correlated)[0]
                value = (
                    float(self.correlation_.loc[col, other])
                    if col in numeric and other in numeric
                    else None
                )
                removed.append(
                    {
                        "removed": col,
                        "retained": other,
                        "correlation": value,
                        "reason": "duplicate" if duplicates else "Spearman",
                    }
                )
            else:
                kept.append(col)
        self.selected_features_ = kept
        self.report_ = pd.DataFrame(
            removed, columns=["removed", "retained", "correlation", "reason"]
        )
        self.categorical_ = [c for c in kept if c in CATEGORICAL_FEATURES]
        self.numeric_ = [c for c in kept if c not in CATEGORICAL_FEATURES]
        self.medians_ = X[self.numeric_].median().fillna(0)
        return self

    def transform(self, X):
        out = X[self.selected_features_].copy()
        out[self.numeric_] = out[self.numeric_].fillna(self.medians_)
        return out

    def get_feature_names_out(self, input_features=None):
        return np.asarray(self.selected_features_, dtype=object)


def category_columns(X):
    return [c for c in X if c in CATEGORICAL_FEATURES]


def numeric_columns(X):
    return [c for c in X if c not in CATEGORICAL_FEATURES]


class CloneableCatBoostClassifier(CatBoostClassifier):
    """CatBoost copies cat_features; explicitly create a fresh estimator for sklearn CV."""

    def __sklearn_clone__(self):
        return type(self)(**self.get_params())


def make_demo_pipeline(kind, seed=42, correlation_threshold=0.90):
    steps = [
        ("engineering", NetworkFeatures()),
        ("selection", CorrelationSelector(correlation_threshold)),
    ]
    if kind == "catboost":
        estimator = CloneableCatBoostClassifier(
            iterations=250,
            depth=6,
            learning_rate=0.08,
            loss_function="Logloss",
            random_seed=seed,
            thread_count=4,
            verbose=False,
            allow_writing_files=False,
            cat_features=CATEGORICAL_FEATURES,
        )
    else:
        preprocessing = ColumnTransformer(
            [
                (
                    "numeric",
                    Pipeline(
                        [("impute", SimpleImputer(strategy="median")), ("scale", StandardScaler())]
                    ),
                    numeric_columns,
                ),
                (
                    "categorical",
                    OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                    category_columns,
                ),
            ],
            verbose_feature_names_out=False,
        )
        steps.append(("preprocessing", preprocessing))
        if kind == "logreg":
            estimator = LogisticRegression(C=1, max_iter=3000, solver="lbfgs", random_state=seed)
        elif kind == "iforest":
            estimator = IsolationForest(
                n_estimators=300, max_samples=256, contamination="auto", n_jobs=4, random_state=seed
            )
        else:
            raise ValueError(kind)
    return Pipeline(steps + [("model", estimator)])


def model_scores(pipeline, X, kind):
    if kind == "iforest":
        return -pipeline.decision_function(X)
    return pipeline.predict_proba(X)[:, 1]


def threshold_table(y, scores):
    precision, recall, thresholds = precision_recall_curve(y, scores)
    sorted_normal = np.sort(scores[np.asarray(y) == 0])
    fpr = (len(sorted_normal) - np.searchsorted(sorted_normal, thresholds, side="left")) / len(
        sorted_normal
    )
    f1 = 2 * precision[:-1] * recall[:-1] / np.maximum(precision[:-1] + recall[:-1], 1e-15)
    table = pd.DataFrame(
        {
            "threshold": thresholds,
            "precision": precision[:-1],
            "recall": recall[:-1],
            "f1": f1,
            "fpr": fpr,
        }
    )
    # Include a no-alert candidate; makes the FPR constraint feasible even with tied scores.
    return pd.concat(
        [
            table,
            pd.DataFrame(
                [
                    {
                        "threshold": np.nextafter(scores.max(), np.inf),
                        "precision": 0.0,
                        "recall": 0.0,
                        "f1": 0.0,
                        "fpr": 0.0,
                    }
                ]
            ),
        ],
        ignore_index=True,
    )


def choose_threshold(table, max_fpr=0.05):
    feasible = table.loc[table.fpr <= max_fpr]
    return float(
        feasible.sort_values(["f1", "fpr", "threshold"], ascending=[False, True, True])
        .iloc[0]
        .threshold
    )


def evaluate(y, scores, threshold, probabilities=True):
    pred = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    auc = roc_auc_score(y, scores)
    ks = ks_2samp(scores[np.asarray(y) == 0], scores[np.asarray(y) == 1])
    result = {
        "roc_auc": float(auc),
        "average_precision": float(average_precision_score(y, scores)),
        "gini": float(2 * auc - 1),
        "accuracy": float(accuracy_score(y, pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "specificity": float(tn / (tn + fp)),
        "fpr": float(fp / (tn + fp)),
        "fnr": float(fn / (fn + tp)),
        "mcc": float(matthews_corrcoef(y, pred)),
        "ks": float(ks.statistic),
        "ks_pvalue": float(ks.pvalue),
        "threshold": threshold,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }
    if probabilities:
        result.update(
            log_loss=float(log_loss(y, scores, labels=[0, 1])),
            brier=float(brier_score_loss(y, scores)),
        )
    return result


def bootstrap_metrics(y, scores, threshold, probabilities=True, iterations=300, seed=42):
    rng = np.random.default_rng(seed)
    y = np.asarray(y)
    keys = [
        k
        for k in evaluate(y, scores, threshold, probabilities)
        if k not in {"ks_pvalue", "threshold", "tn", "fp", "fn", "tp"}
    ]
    values = []
    # Ordinary paired bootstrap: prevalence may vary; skip one-class replicates.
    for _ in range(iterations):
        idx = rng.integers(0, len(y), len(y))
        if np.unique(y[idx]).size == 2:
            metrics = evaluate(y[idx], scores[idx], threshold, probabilities)
            values.append([metrics[k] for k in keys])
    values = np.asarray(values)
    estimates = evaluate(y, scores, threshold, probabilities)
    return pd.DataFrame(
        {
            "metric": keys,
            "estimate": [estimates[k] for k in keys],
            "low_95": np.quantile(values, 0.025, axis=0),
            "high_95": np.quantile(values, 0.975, axis=0),
            "replicates": len(values),
        }
    )


def demo_cv(pipeline, X, y, kind, folds=5, seed=42):
    splitter = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
    rows = []
    for fold, (fit_idx, val_idx) in enumerate(splitter.split(X, y), 1):
        fitted = clone(pipeline)
        train_X, train_y = X.iloc[fit_idx], y.iloc[fit_idx]
        if kind == "iforest":
            fitted.fit(train_X.loc[train_y == 0])
        else:
            fitted.fit(train_X, train_y)
        scores = model_scores(fitted, X.iloc[val_idx], kind)
        rows.append(
            {
                "fold": fold,
                "roc_auc": roc_auc_score(y.iloc[val_idx], scores),
                "average_precision": average_precision_score(y.iloc[val_idx], scores),
                "n_features": len(fitted.named_steps["selection"].selected_features_),
            }
        )
        print(f"{kind}: fold {fold}/{folds} completed", flush=True)
    return pd.DataFrame(rows)


def export_bundle(path, pipeline, kind, threshold, report, metadata, importance, probe):
    path.mkdir(parents=True, exist_ok=True)
    bundle = {
        "pipeline": pipeline,
        "kind": kind,
        "threshold": threshold,
        "raw_features": RAW_FEATURES,
        "selected_features": pipeline.named_steps["selection"].selected_features_,
        "metadata": metadata,
    }
    joblib.dump(bundle, path / "model.joblib", compress=3)
    (path / "validation_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    )
    (path / "metadata.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n")
    importance.to_csv(path / "shap_importance.csv", index=False)
    pipeline.named_steps["selection"].report_.to_csv(path / "feature_selection.csv", index=False)
    loaded = joblib.load(path / "model.joblib")
    before = model_scores(pipeline, probe, kind)
    after = model_scores(loaded["pipeline"], probe, kind)
    np.testing.assert_allclose(before, after, rtol=0, atol=1e-12)
    np.testing.assert_array_equal(before >= threshold, after >= loaded["threshold"])
    return path / "model.joblib"
