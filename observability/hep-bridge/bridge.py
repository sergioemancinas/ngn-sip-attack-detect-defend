#!/usr/bin/env python3
"""Poll Homer/HEPlify Postgres and emit normalized SIP rows for Vector -> ClickHouse.

Why a dedicated bridge instead of Vector reading Postgres directly:
- Vector 0.41 has no first-class Postgres row poller with incremental cursors.
- HEPlify rotates hep_proto_* tables daily; discovery and state are easier in Python.
- JSON in data_header/protocol_header needs SIP-specific normalization (response codes,
  client IP selection on replies) before landing in ngn_sip.sip_events.

Output: newline-delimited JSON on a shared volume; Vector ingests with source='hep'.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg2
import psycopg2.extras
import psycopg2.sql

LOG = logging.getLogger("hep_bridge")

SIP_RESPONSE_LINE = re.compile(
    r"^SIP/2\.0\s+(?P<code>\d{3})\s*(?P<phrase>.*)$",
    re.MULTILINE,
)
SIP_REQUEST_LINE = re.compile(
    r"^(?P<method>[A-Z][A-Z0-9_-]*)\s+",
    re.MULTILINE,
)

DEFAULT_STATE_PATH = Path("/var/lib/hep-bridge/state.json")
DEFAULT_OUTPUT_PATH = Path("/logs/hep/events.ndjson")
DEFAULT_POLL_SECONDS = 5


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def load_state(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): int(v) for k, v in data.items() if str(v).isdigit()}


def save_state(path: Path, state: dict[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def normalize_ip(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "::"
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return text
    if getattr(parsed, "ipv4_mapped", None):
        return str(parsed.ipv4_mapped)
    return str(parsed)


def header_text(data: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def build_uri(user: str, domain: str) -> str:
    user = user.strip()
    domain = domain.strip()
    if user and domain:
        return f"sip:{user}@{domain}"
    if domain:
        return f"sip:{domain}"
    if user:
        return f"sip:{user}"
    return ""


def parse_response_from_raw(raw: str) -> tuple[int, str, str]:
    match = SIP_RESPONSE_LINE.search(raw or "")
    if not match:
        return 0, "", ""
    code = int(match.group("code"))
    phrase = match.group("phrase").strip()
    return code, phrase, "SIP/2.0"


def parse_request_from_raw(raw: str) -> str:
    match = SIP_REQUEST_LINE.search(raw or "")
    if not match:
        return ""
    return match.group("method")


def client_ip(proto: dict[str, Any], response_code: int) -> str:
    src = normalize_ip(proto.get("srcIp") or proto.get("srcIP") or proto.get("source_ip"))
    dst = normalize_ip(proto.get("dstIp") or proto.get("dstIP") or proto.get("destination_ip"))
    if response_code > 0:
        return dst if dst != "::" else src
    return src if src != "::" else dst


def transform_row(row: dict[str, Any]) -> dict[str, Any] | None:
    data = row.get("data_header") or {}
    proto = row.get("protocol_header") or {}
    if not isinstance(data, dict):
        data = {}
    if not isinstance(proto, dict):
        proto = {}

    raw = str(row.get("raw") or "")
    raw_header = str(row.get("raw_header") or "")
    combined = raw_header or raw

    method = header_text(data, "method", "Method").upper()
    response_code = 0
    response_phrase = ""
    response_text = header_text(data, "response", "status", "Status")
    if response_text.isdigit():
        response_code = int(response_text)
    if response_code == 0:
        response_code, response_phrase, _ = parse_response_from_raw(combined)
    if not response_phrase:
        response_phrase = header_text(data, "reason", "response_reason", "status_text")

    if not method or method == "SIP/2.0":
        method = parse_request_from_raw(combined)
    if response_code > 0 and (not method or method == "SIP/2.0"):
        method = ""

    src_ip = client_ip(proto, response_code)
    src_port = int(proto.get("srcPort") or proto.get("source_port") or 0)
    dst_ip = normalize_ip(proto.get("dstIp") or proto.get("dstIP"))
    dst_port = int(proto.get("dstPort") or proto.get("destination_port") or 0)

    from_uri = build_uri(
        header_text(data, "from_user", "fromUser"),
        header_text(data, "from_domain", "fromDomain"),
    )
    to_uri = build_uri(
        header_text(data, "to_user", "toUser"),
        header_text(data, "to_domain", "toDomain"),
    )
    call_id = header_text(data, "callid", "call_id", "Call-ID")
    user_agent = header_text(data, "user_agent", "userAgent", "User-Agent")
    cseq = header_text(data, "cseq", "CSeq")

    create_date = row.get("create_date")
    if isinstance(create_date, datetime):
        event_time = create_date.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    else:
        event_time = utc_now_iso()

    if not method and response_code == 0 and not call_id:
        return None

    body_size = len(raw.encode("utf-8", errors="ignore")) if raw else 0

    return {
        "event_time": event_time,
        "source": "hep",
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "transport": header_text(data, "protocol", "transport") or "udp",
        "method": method,
        "response_code": response_code,
        "response_phrase": response_phrase,
        "call_id": call_id,
        "from_uri": from_uri,
        "to_uri": to_uri,
        "user_agent": user_agent,
        "cseq": cseq,
        "body_size": body_size,
        "raw_message": combined[:8192],
        "attack_id": "",
        "mitre_technique": "",
        "hep_table": row.get("_table", ""),
        "hep_id": row.get("id"),
    }


def discover_tables(conn: psycopg2.extensions.connection) -> list[str]:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT tablename
            FROM pg_catalog.pg_tables
            WHERE schemaname = 'public'
              AND tablename LIKE 'hep_proto_1_%'
            ORDER BY tablename ASC
            """
        )
        return [row[0] for row in cur.fetchall()]


def fetch_new_rows(
    conn: psycopg2.extensions.connection,
    table: str,
    last_id: int,
    batch_size: int,
) -> list[dict[str, Any]]:
    query = psycopg2.sql.SQL(
        """
        SELECT id, create_date, protocol_header, data_header, raw
        FROM {table}
        WHERE id > %s
        ORDER BY id ASC
        LIMIT %s
        """
    ).format(table=psycopg2.sql.Identifier(table))
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(query, (last_id, batch_size))
        rows = [dict(row) for row in cur.fetchall()]
    for row in rows:
        row["_table"] = table
    return rows


def append_events(output_path: Path, events: list[dict[str, Any]]) -> None:
    if not events:
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("a", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, separators=(",", ":"), default=str) + "\n")


def poll_once(
    conn: psycopg2.extensions.connection,
    state: dict[str, int],
    output_path: Path,
    batch_size: int,
) -> tuple[dict[str, int], int]:
    emitted = 0
    for table in discover_tables(conn):
        last_id = int(state.get(table, 0))
        while True:
            rows = fetch_new_rows(conn, table, last_id, batch_size)
            if not rows:
                break
            events = []
            for row in rows:
                event = transform_row(row)
                if event is not None:
                    events.append(event)
                last_id = max(last_id, int(row["id"]))
            append_events(output_path, events)
            emitted += len(events)
            state[table] = last_id
            if len(rows) < batch_size:
                break
    return state, emitted


def build_connection(args: argparse.Namespace) -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=args.pg_host,
        port=args.pg_port,
        dbname=args.pg_database,
        user=args.pg_user,
        password=args.pg_password,
        connect_timeout=10,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HEPlify Postgres -> ndjson bridge for Vector.")
    parser.add_argument("--pg-host", default=os.getenv("HOMER_PG_HOST", "homer-postgres"))
    parser.add_argument("--pg-port", type=int, default=int(os.getenv("HOMER_PG_PORT", "5432")))
    parser.add_argument("--pg-database", default=os.getenv("HOMER_PG_DATABASE", "homer_data"))
    parser.add_argument("--pg-user", default=os.getenv("HOMER_PG_USER", "homer_user"))
    parser.add_argument("--pg-password", default=os.getenv("HOMER_DB_PASSWORD", "change-me-local-only"))
    parser.add_argument("--output", type=Path, default=Path(os.getenv("HEP_BRIDGE_OUTPUT", str(DEFAULT_OUTPUT_PATH))))
    parser.add_argument("--state", type=Path, default=Path(os.getenv("HEP_BRIDGE_STATE", str(DEFAULT_STATE_PATH))))
    parser.add_argument("--poll-seconds", type=float, default=float(os.getenv("HEP_BRIDGE_POLL_SECONDS", DEFAULT_POLL_SECONDS)))
    parser.add_argument("--batch-size", type=int, default=int(os.getenv("HEP_BRIDGE_BATCH_SIZE", "500")))
    parser.add_argument("--once", action="store_true", help="Run a single poll cycle and exit.")
    parser.add_argument("--log-level", default=os.getenv("HEP_BRIDGE_LOG_LEVEL", "INFO"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    state = load_state(args.state)
    try:
        conn = build_connection(args)
    except psycopg2.Error as exc:
        LOG.error("postgres connect failed: %s", exc)
        return 1

    try:
        while True:
            try:
                state, emitted = poll_once(conn, state, args.output, args.batch_size)
                save_state(args.state, state)
                if emitted:
                    LOG.info("emitted %s hep events to %s", emitted, args.output)
            except psycopg2.Error as exc:
                LOG.error("poll failed: %s", exc)
                try:
                    conn.close()
                except Exception:  # noqa: BLE001 - already errored; closing is best-effort
                    pass
                if args.once:
                    return 1
                # Reconnect with retry: build_connection itself raises when the DB
                # is still down, and an unguarded reconnect here would crash the
                # poller on any extended Postgres outage. Loop until it comes back.
                conn = None
                while conn is None:
                    time.sleep(args.poll_seconds)
                    try:
                        conn = build_connection(args)
                        LOG.info("reconnected to postgres")
                    except psycopg2.Error as reconnect_exc:
                        LOG.error("reconnect failed, retrying: %s", reconnect_exc)
                continue

            if args.once:
                break
            time.sleep(args.poll_seconds)
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
