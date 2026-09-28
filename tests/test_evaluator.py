from ids_ml_lab.evaluator import LiveEvaluator


def test_evaluator_matches_in_any_order() -> None:
    evaluator = LiveEvaluator()
    evaluator.add("prediction", {"event_id": "a", "prediction": 1})
    evaluator.add("truth", {"event_id": "a", "label": 1})
    evaluator.add("truth", {"event_id": "b", "label": 0})
    evaluator.add("prediction", {"event_id": "b", "prediction": 1})
    assert evaluator.tp == 1
    assert evaluator.fp == 1
    assert len(evaluator.evaluated) == 2


def test_evaluator_counts_each_event_only_once() -> None:
    evaluator = LiveEvaluator()
    evaluator.add("truth", {"event_id": "a", "label": 1})
    evaluator.add("prediction", {"event_id": "a", "prediction": 0})
    evaluator.add("prediction", {"event_id": "a", "prediction": 1})
    evaluator.add("truth", {"event_id": "a", "label": 0})
    assert evaluator.fn == 1
    assert evaluator.tp == evaluator.fp == evaluator.tn == 0


def test_evaluator_ignores_undelivered_truth() -> None:
    evaluator = LiveEvaluator()
    evaluator.add("truth", {"event_id": "a", "label": 1, "delivered": False})
    evaluator.add("prediction", {"event_id": "a", "prediction": 1})
    assert evaluator.evaluated == set()
    assert evaluator.truth == {}
