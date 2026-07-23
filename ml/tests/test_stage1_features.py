from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ml" / "stage1"))

from features import (  # noqa: E402
    FEATURE_COLUMNS,
    FEATURE_DESCRIPTIONS,
    build_labeled_feature_dataset,
    build_synthetic_feature_dataset,
    load_labeled_dataset,
)


def test_feature_schema_and_label_join() -> None:
    windows = [
        {
            "window_start": datetime(2026, 5, 31, 10, 0, tzinfo=timezone.utc),
            "src_ip": "198.51.100.10",
            "total_msgs": 20,
            "register_count": 18,
            "invite_count": 0,
            "options_count": 0,
            "auth_4xx_count": 12,
            "success_2xx": 1,
            "error_5xx": 0,
            "distinct_ua": 2,
            "distinct_to_uri": 3,
            "distinct_call_id": 5,
            "sum_body_size": 1000,
            "sample_count": 20,
        },
        {
            "window_start": datetime(2026, 5, 31, 10, 5, tzinfo=timezone.utc),
            "src_ip": "198.51.100.20",
            "total_msgs": 4,
            "register_count": 1,
            "invite_count": 1,
            "options_count": 1,
            "auth_4xx_count": 0,
            "success_2xx": 3,
            "error_5xx": 0,
            "distinct_ua": 1,
            "distinct_to_uri": 1,
            "distinct_call_id": 2,
            "sum_body_size": 120,
            "sample_count": 4,
        },
    ]
    labels = [
        {
            "label_time": datetime(2026, 5, 31, 10, 1, tzinfo=timezone.utc),
            "src_ip": "198.51.100.10",
            "attack_id": "sippts_svcrack",
            "mitre_technique": "T1110.001",
            "phase": "credentials",
            "notes": "",
        }
    ]

    dataset = build_labeled_feature_dataset(windows, labels)

    assert list(dataset.features.columns) == FEATURE_COLUMNS
    assert dataset.labels.tolist() == ["credentials", "benign"]
    assert dataset.metadata.loc[0, "attack_id"] == "sippts_svcrack"
    assert dataset.metadata.loc[1, "phase"] == "benign"
    assert set(FEATURE_COLUMNS).issubset(set(FEATURE_DESCRIPTIONS))
    assert dataset.features.loc[0, "register_ratio"] == pytest.approx(0.9)


def test_synthetic_fallback_is_labeled_and_deterministic() -> None:
    first = build_synthetic_feature_dataset(samples_per_class=2, seed=7)
    second = build_synthetic_feature_dataset(samples_per_class=2, seed=7)

    assert first.synthetic is True
    assert first.source.startswith("synthetic_fallback")
    assert first.labels.tolist() == second.labels.tolist()
    assert first.features.equals(second.features)
    assert "benign" in set(first.labels)
    assert {"recon", "credentials", "injection", "dos", "media", "tollfraud"}.issubset(set(first.labels))


def test_load_labeled_dataset_uses_synthetic_when_clickhouse_is_empty() -> None:
    class EmptyClient:
        def execute(self, query: str):
            return []

    dataset = load_labeled_dataset(client=EmptyClient(), synthetic_fallback=True, seed=11)

    assert dataset.synthetic is True
    assert not dataset.features.empty
