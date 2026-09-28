import json

import numpy as np
import pandas as pd

import ids_ml_lab.training as training
from ids_ml_lab.features import FEATURES


def _split(normal: int, attack: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = normal + attack
    labels = np.array([0] * normal + [1] * attack)
    frame = pd.DataFrame(
        {
            "protocol_type": ["tcp"] * rows,
            "service": ["http"] * rows,
            "flag": ["SF"] * rows,
            "duration": rng.exponential(1, rows),
            "src_bytes": rng.normal(100 + labels * 500, 5, rows),
            "dst_bytes": rng.normal(200 + labels * 500, 5, rows),
            "count": rng.integers(1, 8, rows),
            "srv_count": rng.integers(1, 8, rows),
            "serror_rate": np.zeros(rows),
            "srv_serror_rate": np.zeros(rows),
            "rerror_rate": np.zeros(rows),
            "same_srv_rate": np.ones(rows),
            "diff_srv_rate": np.zeros(rows),
            "dst_host_count": rng.integers(1, 20, rows),
            "dst_host_srv_count": rng.integers(1, 20, rows),
            "dst_host_same_srv_rate": np.ones(rows),
            "label": labels,
            "attack_type": np.where(labels == 0, "normal", "demo_attack"),
        }
    )
    return frame[FEATURES + ["label", "attack_type"]]


def test_fit_pipeline_uses_only_normal_training_rows(monkeypatch) -> None:
    fitted: list[pd.DataFrame] = []

    class PipelineSpy:
        def fit(self, frame: pd.DataFrame) -> "PipelineSpy":
            fitted.append(frame.copy())
            return self

    monkeypatch.setattr(training, "make_pipeline", lambda _seed: PipelineSpy())
    training.fit_pipeline(_split(normal=12, attack=8, seed=1))

    assert len(fitted) == 1
    assert len(fitted[0]) == 12
    assert fitted[0]["src_bytes"].max() < 200


def test_train_uses_validation_threshold_and_exports_complete_artifact(
    tmp_path, monkeypatch
) -> None:
    data_dir = tmp_path / "data"
    artifact_dir = tmp_path / "artifact"
    data_dir.mkdir()
    train_frame = _split(normal=20, attack=20, seed=2)
    validation_frame = _split(normal=15, attack=5, seed=3)
    test_frame = _split(normal=5, attack=15, seed=4)
    train_frame.to_parquet(data_dir / "train.parquet", index=False)
    validation_frame.to_parquet(data_dir / "validation.parquet", index=False)
    test_frame.to_parquet(data_dir / "test.parquet", index=False)

    threshold_labels: list[int] = []

    def select_threshold(y_true: np.ndarray, _scores: np.ndarray, max_fpr: float) -> float:
        assert max_fpr == 0.05
        threshold_labels.extend(y_true.tolist())
        return 0.0

    monkeypatch.setattr(training, "select_threshold", select_threshold)
    monkeypatch.setattr(training, "cross_validate", lambda *_args, **_kwargs: {"folds": []})
    monkeypatch.setattr(
        training,
        "bootstrap_ci",
        lambda *_args, **_kwargs: {"estimate": 0.5, "low": 0.4, "high": 0.6},
    )
    monkeypatch.setattr(
        training,
        "compute_shap_importance",
        lambda *_args, **_kwargs: pd.DataFrame({"feature": ["src_bytes"], "mean_abs_shap": [1.0]}),
    )

    training.train(data_dir, artifact_dir, seed=42)

    assert threshold_labels == validation_frame["label"].tolist()
    assert {path.name for path in artifact_dir.iterdir()} == {
        "features.json",
        "metadata.json",
        "model.joblib",
        "shap_importance.csv",
        "threshold.json",
        "validation_report.json",
    }
    assert json.loads((artifact_dir / "features.json").read_text())["features"] == FEATURES
