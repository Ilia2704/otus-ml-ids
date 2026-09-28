import json
from types import SimpleNamespace

import pytest

from ids_ml_lab.detector import validate_artifact_features
from ids_ml_lab.features import FEATURES


def test_artifact_features_match_online_and_pipeline_schema(tmp_path) -> None:
    (tmp_path / "features.json").write_text(json.dumps({"features": FEATURES}))
    pipeline = SimpleNamespace(feature_names_in_=FEATURES)
    assert validate_artifact_features(tmp_path, pipeline) == FEATURES


def test_artifact_feature_mismatch_fails_fast(tmp_path) -> None:
    (tmp_path / "features.json").write_text(json.dumps({"features": FEATURES[:-1]}))
    with pytest.raises(ValueError, match="online feature schema"):
        validate_artifact_features(tmp_path, SimpleNamespace(feature_names_in_=FEATURES))
