from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ml" / "mlflow"))

from track_eval import dataframe_fingerprint, deterministic_run_key, resolve_tracking_uri  # noqa: E402


def test_deterministic_run_key_is_stable() -> None:
    params = {"detector": "xgboost", "seed": 42}
    metrics = {"binary": {"f1": 0.75, "precision": 0.8}}
    data_hash = dataframe_fingerprint(pd.DataFrame({"b": [2], "a": [1]}))

    first = deterministic_run_key("xgboost", params, metrics, data_hash)
    second = deterministic_run_key("xgboost", params, metrics, data_hash)

    assert first == second
    assert len(first) == 64


def test_tracking_uri_defaults_to_local_file_store(monkeypatch) -> None:
    monkeypatch.delenv("MLFLOW_TRACKING_URI", raising=False)

    assert resolve_tracking_uri().startswith("file://")
    assert "mlruns" in resolve_tracking_uri()
