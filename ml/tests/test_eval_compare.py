from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ml" / "src" / "eval"))

from compare import compare_detector_arms, events_to_window_predictions, normalize_labeled_windows  # noqa: E402


def labeled_windows() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "window_start": "2026-05-31T10:00:00Z",
                "window_end": "2026-05-31T10:05:00Z",
                "label_time": "2026-05-31T10:00:05Z",
                "src_ip": "198.51.100.10",
                "label": "credentials",
            },
            {
                "window_start": "2026-05-31T10:05:00Z",
                "window_end": "2026-05-31T10:10:00Z",
                "label_time": "2026-05-31T10:05:05Z",
                "src_ip": "198.51.100.20",
                "label": "dos",
            },
            {
                "window_start": "2026-05-31T10:10:00Z",
                "window_end": "2026-05-31T10:15:00Z",
                "label_time": "2026-05-31T10:10:00Z",
                "src_ip": "198.51.100.30",
                "label": "benign",
            },
        ]
    )


def test_event_window_metric_math() -> None:
    events = pd.DataFrame(
        [
            {
                "event_time": "2026-05-31T10:00:10Z",
                "src_ip": "198.51.100.10",
                "detector": "suricata",
                "detail": "1000009",
            },
            {
                "event_time": "2026-05-31T10:11:00Z",
                "src_ip": "198.51.100.30",
                "detector": "suricata",
                "detail": "1000005",
            },
        ]
    )
    table = compare_detector_arms(normalize_labeled_windows(labeled_windows()), suricata_events=events)
    row = table.iloc[0]

    assert row.detector == "suricata"
    assert row.tp == 1
    assert row.fp == 1
    assert row.fn == 1
    assert row.tn == 0
    assert row.precision == pytest.approx(0.5)
    assert row.recall == pytest.approx(0.5)
    assert row.f1 == pytest.approx(0.5)
    assert row.fp_rate_vs_benign == pytest.approx(1.0)
    assert row.mean_latency_seconds == pytest.approx(5.0)


def test_empty_events_produce_all_misses_for_attacks() -> None:
    predictions, latencies = events_to_window_predictions(labeled_windows(), pd.DataFrame())

    assert predictions.tolist() == [0, 0, 0]
    assert latencies == []
