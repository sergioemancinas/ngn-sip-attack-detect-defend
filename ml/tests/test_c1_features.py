from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ml" / "stage1"))
sys.path.insert(0, str(ROOT / "observability" / "hep-bridge"))

from bridge import transform_row  # noqa: E402
from features import (  # noqa: E402
    build_labeled_feature_dataset,
    get_feature_columns,
)


def test_feature_set_sizes() -> None:
    assert len(get_feature_columns("request_only")) == 16
    assert len(get_feature_columns("response_enriched")) == 31
    assert len(get_feature_columns("legacy_full")) == 22


def test_response_enriched_derived_ratios() -> None:
    windows = [
        {
            "window_start": datetime(2026, 6, 19, 10, 0, tzinfo=timezone.utc),
            "src_ip": "198.51.100.10",
            "total_msgs": 40,
            "register_count": 10,
            "invite_count": 2,
            "options_count": 3,
            "auth_4xx_count": 15,
            "success_2xx": 5,
            "error_5xx": 0,
            "distinct_ua": 2,
            "distinct_to_uri": 4,
            "distinct_call_id": 6,
            "sum_body_size": 800,
            "sample_count": 40,
            "response_msg_count": 20,
            "request_msg_count": 20,
            "client_4xx_count": 3,
            "notfound_404_count": 2,
            "busy_486_count": 1,
            "cancelled_487_count": 0,
            "timeout_408_count": 0,
            "distinct_response_codes": 4,
        }
    ]
    dataset = build_labeled_feature_dataset(windows, [], feature_set="response_enriched")
    row = dataset.features.iloc[0]
    assert row["response_request_ratio"] == pytest.approx(1.0)
    assert row["auth_failure_ratio"] == pytest.approx(0.75)
    assert row["notfound_404_ratio"] == pytest.approx(0.1)


def test_hep_bridge_maps_401_response_to_client_ip() -> None:
    event = transform_row(
        {
            "id": 1,
            "create_date": datetime(2026, 6, 19, 12, 0, tzinfo=timezone.utc),
            "protocol_header": {"srcIp": "10.0.0.5", "dstIp": "198.51.100.44", "srcPort": 5060, "dstPort": 5062},
            "data_header": {"callid": "abc@lab", "response": "401", "reason": "Unauthorized", "cseq": "1 REGISTER"},
            "raw": "",
            "raw_header": "SIP/2.0 401 Unauthorized\r\n",
        }
    )
    assert event is not None
    assert event["response_code"] == 401
    assert event["response_phrase"] == "Unauthorized"
    assert event["src_ip"] == "198.51.100.44"
    assert event["source"] == "hep"
