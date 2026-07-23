"""Ground-truth label emitter for the synthetic attack dataset.

Every attack script in `attacks/0X_*` calls `emit_label()` after sending traffic, so
the synthetic tier of our three-tier evaluation is auto-labeled and reproducible.

Writes one row per call into `ngn_sip.attack_labels` via the ClickHouse HTTP interface.
Reads ClickHouse coordinates from environment variables; no credentials are hardcoded.

Env vars:
    CLICKHOUSE_HOST     default: 127.0.0.1
    CLICKHOUSE_PORT     default: 8123
    CLICKHOUSE_USER     default: ngn
    CLICKHOUSE_PASSWORD required (no default)
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)

_DEFAULT_TIMEOUT = httpx.Timeout(5.0, connect=2.0)


def emit_label(
    src_ip: str,
    attack_id: str,
    mitre_technique: str,
    phase: str,
    notes: str = "",
    clickhouse_host: Optional[str] = None,
    clickhouse_port: Optional[int] = None,
) -> None:
    """Insert one ground-truth label row into ngn_sip.attack_labels.

    Args:
        src_ip: source IP of the synthetic attacker (string form, IPv4 or IPv6)
        attack_id: short stable identifier (e.g. 'sippts_svcrack')
        mitre_technique: MITRE ATT&CK ID (e.g. 'T1110.001')
        phase: pipeline phase ('recon', 'credentials', 'injection', 'dos', 'media', 'tollfraud')
        notes: optional free-text context
        clickhouse_host: override CLICKHOUSE_HOST env
        clickhouse_port: override CLICKHOUSE_PORT env

    Raises:
        RuntimeError: if CLICKHOUSE_PASSWORD is missing
        httpx.HTTPError: on any HTTP transport / status failure
    """
    host = clickhouse_host or os.environ.get("CLICKHOUSE_HOST", "127.0.0.1")
    port = clickhouse_port or int(os.environ.get("CLICKHOUSE_PORT", "8123"))
    user = os.environ.get("CLICKHOUSE_USER", "ngn")
    password = os.environ.get("CLICKHOUSE_PASSWORD")
    if not password:
        raise RuntimeError("CLICKHOUSE_PASSWORD env var is required for label emission")

    # ClickHouse DateTime64 JSON parsing wants 'YYYY-MM-DD HH:MM:SS.ms', no timezone offset.
    label_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.") + f"{datetime.now(timezone.utc).microsecond // 1000:03d}"
    row = {
        "label_time": label_time,
        "src_ip": src_ip,
        "attack_id": attack_id,
        "mitre_technique": mitre_technique,
        "phase": phase,
        "notes": notes,
    }

    url = f"http://{host}:{port}/?database=ngn_sip&query=INSERT%20INTO%20attack_labels%20FORMAT%20JSONEachRow"
    response = httpx.post(
        url,
        auth=(user, password),
        content=json.dumps(row),
        timeout=_DEFAULT_TIMEOUT,
    )
    response.raise_for_status()
    logger.info(
        "attack_label_emitted",
        attack_id=attack_id,
        mitre=mitre_technique,
        phase=phase,
        src_ip=src_ip,
    )


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 5:
        print("usage: label_emitter.py <src_ip> <attack_id> <mitre> <phase> [notes]", file=sys.stderr)
        sys.exit(2)
    emit_label(
        src_ip=sys.argv[1],
        attack_id=sys.argv[2],
        mitre_technique=sys.argv[3],
        phase=sys.argv[4],
        notes=sys.argv[5] if len(sys.argv) > 5 else "",
    )
