from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ml" / "stage1"))

from features import build_synthetic_feature_dataset  # noqa: E402
from train import train_eval_detector  # noqa: E402


def test_isolation_forest_prediction_shape() -> None:
    dataset = build_synthetic_feature_dataset(samples_per_class=3, seed=5)
    detector, metrics = train_eval_detector(
        "isolation_forest",
        dataset,
        random_state=5,
        test_size=0.3,
        cv_splits=2,
    )

    predictions = detector.predict(dataset.features)
    assert len(predictions) == len(dataset.features)
    assert set(predictions).issubset({"benign", "attack"})
    assert metrics["label_mode"] == "binary_anomaly"
    assert "binary" in metrics


def test_xgboost_determinism_with_fixed_seed() -> None:
    pytest.importorskip("xgboost")
    dataset = build_synthetic_feature_dataset(samples_per_class=3, seed=13)

    first, first_metrics = train_eval_detector("xgboost", dataset, random_state=13, test_size=0.3, cv_splits=2)
    second, second_metrics = train_eval_detector("xgboost", dataset, random_state=13, test_size=0.3, cv_splits=2)

    assert first.predict(dataset.features).tolist() == second.predict(dataset.features).tolist()
    assert first_metrics["binary"]["f1"] == pytest.approx(second_metrics["binary"]["f1"])
    assert first_metrics["label_mode"] == "multiclass"
