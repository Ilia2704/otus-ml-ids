import numpy as np
import pandas as pd
import pytest

from ids_ml_lab.inference import predict


class InferenceOnly:
    def fit(self, *args):
        raise AssertionError("Inference must not train")

    def decision_function(self, frame):
        assert list(frame.columns) == ["duration"]
        return -frame.duration.to_numpy()


def test_inference_needs_no_labels_and_uses_saved_threshold():
    bundle = {"raw_features": ["duration"], "pipeline": InferenceOnly(),
              "kind": "iforest", "threshold": .5}
    frame = pd.DataFrame({"duration": [.1, .5, .9]})
    result = predict(bundle, frame)
    np.testing.assert_array_equal(result.prediction, [0, 1, 1])
    with_labels = predict(bundle, frame.assign(label=[1, 0, 0], attack_type="irrelevant"))
    np.testing.assert_array_equal(with_labels.score, result.score)
    np.testing.assert_array_equal(with_labels.prediction, result.prediction)
    with pytest.raises(ValueError, match="Missing input features: duration"):
        predict(bundle, frame.rename(columns={"duration": "other"}))
