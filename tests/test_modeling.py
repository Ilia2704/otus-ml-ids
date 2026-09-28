import numpy as np
import pandas as pd

from ids_ml_lab.features import FEATURES
from ids_ml_lab.modeling import (
    anomaly_scores,
    classification_metrics,
    make_pipeline,
    select_threshold,
)


def _frame(rows: int, attack: bool, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    shift = 500 if attack else 0
    return pd.DataFrame(
        {
            "protocol_type": ["tcp"] * rows,
            "service": ["http"] * rows,
            "flag": ["SF"] * rows,
            "duration": rng.exponential(1, rows),
            "src_bytes": rng.normal(100 + shift, 8, rows).clip(0),
            "dst_bytes": rng.normal(200 + shift, 12, rows).clip(0),
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
        }
    )[FEATURES]


def test_pipeline_scores_and_metrics() -> None:
    normal = _frame(200, attack=False, seed=1)
    attack = _frame(80, attack=True, seed=2)
    pipeline = make_pipeline(seed=3).fit(normal)
    combined = pd.concat([normal.iloc[:80], attack], ignore_index=True)
    y = np.array([0] * 80 + [1] * 80)
    scores = anomaly_scores(pipeline, combined)
    threshold = select_threshold(y, scores, max_fpr=0.1)
    metrics = classification_metrics(y, scores, threshold)
    assert scores[80:].mean() > scores[:80].mean()
    assert 0.0 <= metrics["roc_auc"] <= 1.0
    assert metrics["confusion_matrix"][0][0] >= 0


def test_pipeline_accepts_unknown_online_categories() -> None:
    pipeline = make_pipeline(seed=3).fit(_frame(100, attack=False, seed=1))
    unseen = _frame(1, attack=False, seed=2)
    unseen.loc[0, ["protocol_type", "service", "flag"]] = ["new", "custom", "UNKNOWN"]
    score = anomaly_scores(pipeline, unseen)
    assert score.shape == (1,)
    assert np.isfinite(score[0])
