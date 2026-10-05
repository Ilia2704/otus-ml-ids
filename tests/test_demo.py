import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.base import clone

from ids_ml_lab.demo import (
    RAW_FEATURES,
    CorrelationSelector,
    NetworkFeatures,
    choose_threshold,
    demo_cv,
    make_demo_pipeline,
    model_scores,
    threshold_table,
)


def network_frame(rows=60):
    rng = np.random.default_rng(7)
    frame = pd.DataFrame({c: rng.integers(0, 10, rows) for c in RAW_FEATURES})
    frame["protocol_type"] = np.resize(["tcp", "udp", "icmp"], rows)
    frame["service"] = np.resize(["http", "dns", "ftp"], rows)
    frame["flag"] = np.resize(["SF", "REJ", "S0"], rows)
    frame.loc[0, ["duration", "src_bytes", "dst_bytes", "count", "dst_host_count"]] = 0
    return frame


def test_engineering_zero_denominators_and_no_target():
    frame = network_frame()
    transformed = NetworkFeatures().fit_transform(frame.assign(label=1, attack_type="attack"))
    assert np.isfinite(transformed.select_dtypes("number").to_numpy()).all()
    assert transformed.loc[0, "zero_bytes"] == 1
    assert transformed.loc[0, "bytes_per_second"] == 0
    assert "label" not in transformed and "attack_type" not in transformed


def test_selection_is_frozen_on_holdout_and_serializable(tmp_path):
    train = pd.DataFrame(
        {
            "a": [0, 1, 2, 3],
            "duplicate": [0, 1, 2, 3],
            "reverse": [3, 2, 1, 0],
            "constant": [0] * 4,
            "other": [0, 1, 0, 1],
        }
    )
    selector = CorrelationSelector(0.9).fit(train)
    assert selector.selected_features_ == ["a", "other"]
    holdout = train.copy()
    holdout["duplicate"] = [9, 8, 2, 3]
    assert list(selector.transform(holdout)) == ["a", "other"]
    joblib.dump(selector, tmp_path / "selector.joblib")
    pd.testing.assert_frame_equal(
        joblib.load(tmp_path / "selector.joblib").transform(holdout), selector.transform(holdout)
    )


def test_threshold_honors_fpr_with_tied_scores():
    y = np.array([0, 0, 0, 1, 1])
    scores = np.array([0.5, 0.5, 0.5, 0.5, 0.5])
    table = threshold_table(y, scores)
    threshold = choose_threshold(table, 0.05)
    assert threshold > 0.5
    assert ((scores[y == 0] >= threshold).mean()) <= 0.05


@pytest.mark.parametrize("kind", ["logreg", "catboost", "iforest"])
def test_full_pipeline_clone_unseen_category_and_roundtrip(kind, tmp_path):
    X = network_frame()
    y = pd.Series(np.resize([0, 1], len(X)))
    pipeline = make_demo_pipeline(kind)
    if kind == "catboost":
        pipeline.set_params(model__iterations=5)
    elif kind == "iforest":
        pipeline.set_params(model__n_estimators=5)
    cloned = clone(pipeline)
    if kind == "iforest":
        cloned.fit(X.loc[y == 0])
    else:
        cloned.fit(X, y)
    holdout = X.head(5).copy()
    holdout["service"] = "previously_unseen"
    before = model_scores(cloned, holdout, kind)
    joblib.dump(cloned, tmp_path / "pipeline.joblib")
    np.testing.assert_allclose(
        model_scores(joblib.load(tmp_path / "pipeline.joblib"), holdout, kind), before
    )


def test_iforest_cv_never_fits_attack_rows(monkeypatch):
    X = network_frame()
    y = pd.Series(np.resize([0, 1], len(X)))
    original = NetworkFeatures.fit
    seen = []

    def fit(self, frame, target=None):
        seen.extend(frame.index)
        return original(self, frame, target)

    monkeypatch.setattr(NetworkFeatures, "fit", fit)
    pipeline = make_demo_pipeline("iforest").set_params(model__n_estimators=3)
    results = demo_cv(pipeline, X, y, "iforest", folds=3)
    assert len(results) == 3
    assert all(y.loc[index] == 0 for index in seen)
