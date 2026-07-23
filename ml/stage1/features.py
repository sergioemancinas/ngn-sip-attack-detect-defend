from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Sequence

import numpy as np
import pandas as pd

IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

DEFAULT_FEATURES_TABLE = "ngn_sip.sip_features_5min"
DEFAULT_EVENTS_TABLE = "ngn_sip.sip_events"
DEFAULT_LABELS_TABLE = "ngn_sip.attack_labels"
WINDOW_SECONDS = 300
DEFAULT_RANDOM_SEED = 42

ATTACK_CLASSES = ("recon", "credentials", "injection", "dos", "media", "tollfraud")
TARGET_CLASSES = ("benign", *ATTACK_CLASSES)

ATTACK_ID_TO_CLASS = {
    "sippts_options_scan": "recon",
    "sipvicious_svmap": "recon",
    "sippts_svcrack": "credentials",
    "sippts_smap_invite": "injection",
    "sippts_malformed_invite": "injection",
    "sipp_register_flood": "dos",
    "rtp_inject": "media",
    "dialplan_abuse": "tollfraud",
}

WINDOW_COLUMNS = [
    "window_start",
    "src_ip",
    "total_msgs",
    "register_count",
    "invite_count",
    "options_count",
    "auth_4xx_count",
    "success_2xx",
    "error_5xx",
    "distinct_ua",
    "distinct_to_uri",
    "distinct_call_id",
    "sum_body_size",
    "sample_count",
]

COUNT_FEATURES = [
    "total_msgs",
    "register_count",
    "invite_count",
    "options_count",
    "auth_4xx_count",
    "success_2xx",
    "error_5xx",
    "distinct_ua",
    "distinct_to_uri",
    "distinct_call_id",
    "sum_body_size",
    "sample_count",
]

DERIVED_FEATURES = [
    "register_ratio",
    "invite_ratio",
    "options_ratio",
    "auth_4xx_ratio",
    "success_2xx_ratio",
    "error_5xx_ratio",
    "avg_body_size",
    "ua_diversity_ratio",
    "to_uri_diversity_ratio",
    "call_id_diversity_ratio",
]

# C1 experiment feature sets (docs/C1_HEP_RESPONSE_FEATURES.md).
RESPONSE_COUNT_FEATURES = [
    "response_msg_count",
    "request_msg_count",
    "client_4xx_count",
    "notfound_404_count",
    "distinct_response_codes",
]

RESPONSE_DERIVED_FEATURES = [
    "response_request_ratio",
    "auth_failure_ratio",
    "client_4xx_ratio",
    "notfound_404_ratio",
]

REQUEST_ONLY_COUNT_FEATURES = [
    "total_msgs",
    "register_count",
    "invite_count",
    "options_count",
    "distinct_ua",
    "distinct_to_uri",
    "distinct_call_id",
    "sum_body_size",
    "sample_count",
]

REQUEST_ONLY_DERIVED_FEATURES = [
    "register_ratio",
    "invite_ratio",
    "options_ratio",
    "avg_body_size",
    "ua_diversity_ratio",
    "to_uri_diversity_ratio",
    "call_id_diversity_ratio",
]

RESPONSE_ENRICHED_COUNT_FEATURES = REQUEST_ONLY_COUNT_FEATURES + [
    "auth_4xx_count",
    "success_2xx",
    "error_5xx",
    *RESPONSE_COUNT_FEATURES,
]

RESPONSE_ENRICHED_DERIVED_FEATURES = REQUEST_ONLY_DERIVED_FEATURES + [
    "auth_4xx_ratio",
    "success_2xx_ratio",
    "error_5xx_ratio",
    *RESPONSE_DERIVED_FEATURES,
]

FEATURE_SETS: dict[str, list[str]] = {
    "request_only": REQUEST_ONLY_COUNT_FEATURES + REQUEST_ONLY_DERIVED_FEATURES,
    "response_enriched": RESPONSE_ENRICHED_COUNT_FEATURES + RESPONSE_ENRICHED_DERIVED_FEATURES,
    "legacy_full": COUNT_FEATURES + DERIVED_FEATURES,
}

FEATURE_COLUMNS = FEATURE_SETS["legacy_full"]

EXTENDED_WINDOW_COLUMNS = WINDOW_COLUMNS + [
    "response_msg_count",
    "request_msg_count",
    "client_4xx_count",
    "notfound_404_count",
    "busy_486_count",
    "cancelled_487_count",
    "timeout_408_count",
    "distinct_response_codes",
]

FEATURE_DESCRIPTIONS = {
    "total_msgs": "Number of SIP messages from the source IP in the five-minute window.",
    "register_count": "REGISTER request count from sip_features_5min.register_count.",
    "invite_count": "INVITE request count from sip_features_5min.invite_count.",
    "options_count": "OPTIONS request count from sip_features_5min.options_count.",
    "auth_4xx_count": "401, 403, and 407 response count from sip_features_5min.auth_4xx_count.",
    "success_2xx": "2xx response count from sip_features_5min.success_2xx.",
    "error_5xx": "5xx response count from sip_features_5min.error_5xx.",
    "distinct_ua": "Unique SIP User-Agent count merged from the AggregateFunction state.",
    "distinct_to_uri": "Unique To URI count merged from the AggregateFunction state.",
    "distinct_call_id": "Unique Call-ID count merged from the AggregateFunction state.",
    "sum_body_size": "Total SIP body bytes in the window from sip_features_5min.sum_body_size.",
    "sample_count": "Materialized-view sample count for the window.",
    "register_ratio": "REGISTER count divided by total message count.",
    "invite_ratio": "INVITE count divided by total message count.",
    "options_ratio": "OPTIONS count divided by total message count.",
    "auth_4xx_ratio": "Authentication 4xx count divided by total message count.",
    "success_2xx_ratio": "2xx response count divided by total message count.",
    "error_5xx_ratio": "5xx response count divided by total message count.",
    "avg_body_size": "Total SIP body bytes divided by sample count.",
    "ua_diversity_ratio": "Unique User-Agent count divided by total message count.",
    "to_uri_diversity_ratio": "Unique To URI count divided by total message count.",
    "call_id_diversity_ratio": "Unique Call-ID count divided by total message count.",
    "response_msg_count": "SIP responses (response_code > 0) in the window; requires HEP source rows.",
    "request_msg_count": "SIP requests (response_code = 0 with a method) in the window.",
    "client_4xx_count": "Non-auth client errors (400-499 excluding 401, 403, 407).",
    "notfound_404_count": "404 Not Found responses in the window.",
    "distinct_response_codes": "Unique non-zero SIP response codes in the window.",
    "response_request_ratio": "Response count divided by request count (retransmit/timeout proxy).",
    "auth_failure_ratio": "Authentication 4xx count divided by response count.",
    "client_4xx_ratio": "Non-auth 4xx count divided by response count.",
    "notfound_404_ratio": "404 count divided by response count.",
}

METADATA_COLUMNS = [
    "window_start",
    "window_end",
    "src_ip",
    "label_time",
    "attack_id",
    "mitre_technique",
    "phase",
    "label_source",
    "synthetic",
]


@dataclass(frozen=True)
class FeatureDataset:
    features: pd.DataFrame
    labels: pd.Series
    metadata: pd.DataFrame
    synthetic: bool
    source: str


def validate_identifier(identifier: str) -> str:
    parts = identifier.split(".")
    if not parts or any(not IDENTIFIER_PATTERN.fullmatch(part) for part in parts):
        raise ValueError(f"invalid ClickHouse identifier: {identifier!r}")
    return ".".join(parts)


def build_clickhouse_client(
    host: str | None = None,
    port: int | None = None,
    user: str | None = None,
    password: str | None = None,
    database: str | None = None,
) -> Any:
    """Create a ClickHouse client with a lazy dependency import."""
    try:
        from clickhouse_driver import Client
    except ImportError as exc:
        raise RuntimeError("clickhouse-driver is required for ClickHouse access") from exc

    return Client(
        host=host or os.getenv("CLICKHOUSE_HOST", "localhost"),
        port=port or int(os.getenv("CLICKHOUSE_PORT", "9000")),
        user=user or os.getenv("CLICKHOUSE_USER", "ngn"),
        password=password if password is not None else os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=database or os.getenv("CLICKHOUSE_DATABASE", "ngn_sip"),
    )


def coerce_datetime(value: Any) -> datetime:
    if isinstance(value, pd.Timestamp):
        dt = value.to_pydatetime()
    elif isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise TypeError(f"unsupported datetime value: {value!r}")

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _datetime_literal(value: datetime) -> str:
    dt = coerce_datetime(value)
    rendered = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return f"toDateTime64('{rendered}', 3, 'UTC')"


def normalize_ip(value: Any) -> str:
    text = str(value or "").strip()
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return text
    if getattr(parsed, "ipv4_mapped", None):
        return str(parsed.ipv4_mapped)
    return str(parsed)


def _where_time_clause(column: str, since_hours: int, start_time: datetime | None, end_time: datetime | None) -> str:
    clauses: list[str] = []
    if start_time is not None:
        clauses.append(f"{column} >= {_datetime_literal(start_time)}")
    if end_time is not None:
        clauses.append(f"{column} < {_datetime_literal(end_time)}")
    if start_time is None and end_time is None:
        clauses.append(f"{column} >= now() - INTERVAL {int(since_hours)} HOUR")
    return " AND ".join(clauses)


def fetch_feature_windows(
    client: Any,
    features_table: str = DEFAULT_FEATURES_TABLE,
    since_hours: int = 24,
    limit: int = 50_000,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> list[dict[str, Any]]:
    """Read five-minute feature windows from ngn_sip.sip_features_5min."""
    table = validate_identifier(features_table)
    where_clause = _where_time_clause("window_start", since_hours, start_time, end_time)
    limit_clause = f"LIMIT {int(limit)}" if limit > 0 else ""
    query = f"""
    SELECT
        window_start,
        toString(src_ip) AS src_ip,
        toUInt64(sum(total_msgs)) AS total_msgs,
        toUInt64(sum(register_count)) AS register_count,
        toUInt64(sum(invite_count)) AS invite_count,
        toUInt64(sum(options_count)) AS options_count,
        toUInt64(sum(auth_4xx_count)) AS auth_4xx_count,
        toUInt64(sum(success_2xx)) AS success_2xx,
        toUInt64(sum(error_5xx)) AS error_5xx,
        toUInt64(uniqMerge(distinct_ua)) AS distinct_ua,
        toUInt64(uniqMerge(distinct_to_uri)) AS distinct_to_uri,
        toUInt64(uniqMerge(distinct_call_id)) AS distinct_call_id,
        toUInt64(sum(sum_body_size)) AS sum_body_size,
        toUInt64(sum(sample_count)) AS sample_count
    FROM {table}
    WHERE {where_clause}
    GROUP BY window_start, src_ip
    ORDER BY window_start ASC, src_ip ASC
    {limit_clause}
    """
    rows = client.execute(query)
    return [dict(zip(WINDOW_COLUMNS, row, strict=True)) for row in rows]


def fetch_feature_windows_from_events(
    client: Any,
    events_table: str = DEFAULT_EVENTS_TABLE,
    since_hours: int = 24,
    limit: int = 50_000,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    feature_set: str = "legacy_full",
) -> list[dict[str, Any]]:
    """Build the feature contract directly from ngn_sip.sip_events."""
    table = validate_identifier(events_table)
    where_clause = _where_time_clause("event_time", since_hours, start_time, end_time)
    limit_clause = f"LIMIT {int(limit)}" if limit > 0 else ""
    response_extra = ""
    if feature_set == "response_enriched":
        response_extra = """,
        toUInt64(countIf(response_code > 0)) AS response_msg_count,
        toUInt64(countIf(response_code = 0 AND method != '')) AS request_msg_count,
        toUInt64(countIf(response_code BETWEEN 400 AND 499 AND response_code NOT IN (401, 403, 407))) AS client_4xx_count,
        toUInt64(countIf(response_code = 404)) AS notfound_404_count,
        toUInt64(countIf(response_code = 486)) AS busy_486_count,
        toUInt64(countIf(response_code = 487)) AS cancelled_487_count,
        toUInt64(countIf(response_code = 408)) AS timeout_408_count,
        toUInt64(countDistinctIf(response_code, response_code > 0)) AS distinct_response_codes"""
    query = f"""
    SELECT
        toStartOfFiveMinute(event_time) AS window_start,
        toString(src_ip) AS src_ip,
        toUInt64(count()) AS total_msgs,
        toUInt64(countIf(method = 'REGISTER')) AS register_count,
        toUInt64(countIf(method = 'INVITE')) AS invite_count,
        toUInt64(countIf(method = 'OPTIONS')) AS options_count,
        toUInt64(countIf(response_code IN (401, 403, 407))) AS auth_4xx_count,
        toUInt64(countIf(response_code BETWEEN 200 AND 299)) AS success_2xx,
        toUInt64(countIf(response_code >= 500)) AS error_5xx,
        toUInt64(countDistinct(user_agent)) AS distinct_ua,
        toUInt64(countDistinct(to_uri)) AS distinct_to_uri,
        toUInt64(countDistinct(call_id)) AS distinct_call_id,
        toUInt64(sum(body_size)) AS sum_body_size,
        toUInt64(count()) AS sample_count{response_extra}
    FROM {table}
    WHERE {where_clause}
    GROUP BY window_start, src_ip
    ORDER BY window_start ASC, src_ip ASC
    {limit_clause}
    """
    rows = client.execute(query)
    output_columns = EXTENDED_WINDOW_COLUMNS if feature_set == "response_enriched" else WINDOW_COLUMNS
    return [dict(zip(output_columns, row, strict=True)) for row in rows]


def fetch_attack_labels(
    client: Any,
    labels_table: str = DEFAULT_LABELS_TABLE,
    since_hours: int = 24,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> list[dict[str, Any]]:
    """Fetch ground-truth labels emitted by attacks.orchestrator.label_emitter."""
    table = validate_identifier(labels_table)
    where_clause = _where_time_clause("label_time", since_hours, start_time, end_time)
    columns = ["label_time", "src_ip", "attack_id", "mitre_technique", "phase", "notes"]
    query = f"""
    SELECT {", ".join(columns)}
    FROM {table}
    WHERE {where_clause}
    ORDER BY label_time ASC, src_ip ASC
    """
    rows = client.execute(query)
    return [dict(zip(columns, row, strict=True)) for row in rows]


def _safe_divide(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    denominator = denominator.replace(0, np.nan)
    return (numerator / denominator).replace([np.inf, -np.inf], np.nan).fillna(0.0)


def normalize_attack_class(label: dict[str, Any]) -> str:
    phase = str(label.get("phase") or "").strip().lower()
    # Benign is the explicit negative class, not an attack class. It is required
    # for any detection metric (the false-positive denominator), so recognise it
    # before the attack-class lookup rather than raising on it.
    if phase == "benign":
        return "benign"
    if phase in ATTACK_CLASSES:
        return phase

    attack_id = str(label.get("attack_id") or "").strip()
    if attack_id.startswith("benign"):
        return "benign"
    mapped = ATTACK_ID_TO_CLASS.get(attack_id)
    if mapped:
        return mapped

    raise ValueError(f"unknown attack label phase={phase!r} attack_id={attack_id!r}")


def get_feature_columns(feature_set: str = "legacy_full") -> list[str]:
    try:
        return list(FEATURE_SETS[feature_set])
    except KeyError as exc:
        known = ", ".join(sorted(FEATURE_SETS))
        raise ValueError(f"unknown feature_set={feature_set!r}; expected one of: {known}") from exc


def _prepare_windows(
    windows: Sequence[dict[str, Any]],
    feature_set: str = "legacy_full",
) -> pd.DataFrame:
    columns = get_feature_columns(feature_set)
    use_extended = feature_set == "response_enriched"
    base_columns = EXTENDED_WINDOW_COLUMNS if use_extended else WINDOW_COLUMNS

    frame = pd.DataFrame.from_records(windows)
    if frame.empty:
        return pd.DataFrame(columns=columns)

    missing = sorted(set(base_columns) - set(frame.columns))
    if missing:
        raise ValueError(f"feature window rows missing columns: {', '.join(missing)}")

    frame = frame[base_columns].copy()
    frame["window_start"] = pd.to_datetime(frame["window_start"], utc=True)
    frame["window_end"] = frame["window_start"] + pd.to_timedelta(WINDOW_SECONDS, unit="s")
    frame["src_ip"] = frame["src_ip"].map(normalize_ip)

    numeric_cols = set(COUNT_FEATURES) | set(RESPONSE_COUNT_FEATURES)
    for column in numeric_cols:
        if column in frame.columns:
            frame[column] = pd.to_numeric(frame[column], errors="coerce").fillna(0.0)

    total = frame["total_msgs"]
    sample_count = frame["sample_count"].replace(0, np.nan)
    frame["register_ratio"] = _safe_divide(frame["register_count"], total)
    frame["invite_ratio"] = _safe_divide(frame["invite_count"], total)
    frame["options_ratio"] = _safe_divide(frame["options_count"], total)
    frame["auth_4xx_ratio"] = _safe_divide(frame["auth_4xx_count"], total)
    frame["success_2xx_ratio"] = _safe_divide(frame["success_2xx"], total)
    frame["error_5xx_ratio"] = _safe_divide(frame["error_5xx"], total)
    frame["avg_body_size"] = (frame["sum_body_size"] / sample_count).replace([np.inf, -np.inf], np.nan).fillna(0.0)
    frame["ua_diversity_ratio"] = _safe_divide(frame["distinct_ua"], total)
    frame["to_uri_diversity_ratio"] = _safe_divide(frame["distinct_to_uri"], total)
    frame["call_id_diversity_ratio"] = _safe_divide(frame["distinct_call_id"], total)

    if use_extended:
        response_msgs = frame["response_msg_count"].replace(0, np.nan)
        frame["response_request_ratio"] = _safe_divide(frame["response_msg_count"], frame["request_msg_count"])
        frame["auth_failure_ratio"] = (frame["auth_4xx_count"] / response_msgs).replace([np.inf, -np.inf], np.nan).fillna(0.0)
        frame["client_4xx_ratio"] = (frame["client_4xx_count"] / response_msgs).replace([np.inf, -np.inf], np.nan).fillna(0.0)
        frame["notfound_404_ratio"] = (frame["notfound_404_count"] / response_msgs).replace([np.inf, -np.inf], np.nan).fillna(0.0)

    feature_frame = frame[columns].copy()
    feature_frame["window_start"] = frame["window_start"]
    feature_frame["window_end"] = frame["window_end"]
    feature_frame["src_ip"] = frame["src_ip"]
    return feature_frame


def _prepare_labels(labels: Sequence[dict[str, Any]]) -> pd.DataFrame:
    if not labels:
        return pd.DataFrame(columns=["label_time", "src_ip", "attack_id", "mitre_technique", "phase", "attack_class"])

    frame = pd.DataFrame.from_records(labels).copy()
    required = {"label_time", "src_ip", "attack_id", "mitre_technique", "phase"}
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"attack label rows missing columns: {', '.join(missing)}")

    frame["label_time"] = pd.to_datetime(frame["label_time"], utc=True)
    frame["src_ip"] = frame["src_ip"].map(normalize_ip)
    frame["attack_class"] = [normalize_attack_class(row) for row in frame.to_dict("records")]
    return frame.sort_values(["src_ip", "label_time"]).reset_index(drop=True)


def _assign_labels(windows: pd.DataFrame, labels: pd.DataFrame, label_source: str) -> tuple[pd.Series, pd.DataFrame]:
    targets: list[str] = []
    metadata_rows: list[dict[str, Any]] = []

    labels_by_ip = {src_ip: group for src_ip, group in labels.groupby("src_ip")} if not labels.empty else {}
    for row in windows.to_dict("records"):
        candidates = labels_by_ip.get(row["src_ip"])
        selected: dict[str, Any] | None = None
        if candidates is not None:
            mask = (candidates["label_time"] >= row["window_start"]) & (candidates["label_time"] < row["window_end"])
            matches = candidates.loc[mask].sort_values("label_time")
            if not matches.empty:
                selected = matches.iloc[0].to_dict()

        if selected is None:
            targets.append("benign")
            metadata_rows.append(
                {
                    "window_start": row["window_start"],
                    "window_end": row["window_end"],
                    "src_ip": row["src_ip"],
                    "label_time": pd.NaT,
                    "attack_id": "",
                    "mitre_technique": "",
                    "phase": "benign",
                    "label_source": "explicit_benign_window",
                    "synthetic": False,
                }
            )
            continue

        attack_class = str(selected["attack_class"])
        targets.append(attack_class)
        metadata_rows.append(
            {
                "window_start": row["window_start"],
                "window_end": row["window_end"],
                "src_ip": row["src_ip"],
                "label_time": selected["label_time"],
                "attack_id": str(selected.get("attack_id") or ""),
                "mitre_technique": str(selected.get("mitre_technique") or ""),
                "phase": attack_class,
                "label_source": label_source,
                "synthetic": False,
            }
        )

    metadata = pd.DataFrame.from_records(metadata_rows, columns=METADATA_COLUMNS)
    return pd.Series(targets, name="label", dtype="string"), metadata


def build_labeled_feature_dataset(
    windows: Sequence[dict[str, Any]],
    labels: Sequence[dict[str, Any]],
    label_source: str = "attack_labels_time_window",
    feature_set: str = "legacy_full",
) -> FeatureDataset:
    """Build model features and explicit benign or attack-class labels."""
    prepared_windows = _prepare_windows(windows, feature_set=feature_set)
    feature_columns = get_feature_columns(feature_set)
    if prepared_windows.empty:
        empty_features = pd.DataFrame(columns=feature_columns)
        empty_labels = pd.Series(name="label", dtype="string")
        empty_metadata = pd.DataFrame(columns=METADATA_COLUMNS)
        return FeatureDataset(empty_features, empty_labels, empty_metadata, synthetic=False, source="empty")

    prepared_labels = _prepare_labels(labels)
    target, metadata = _assign_labels(prepared_windows, prepared_labels, label_source=label_source)
    features = prepared_windows[feature_columns].astype("float64")
    return FeatureDataset(features=features, labels=target, metadata=metadata, synthetic=False, source=label_source)


def _synthetic_window(
    window_start: datetime,
    src_ip: str,
    attack_class: str,
    offset: int,
    rng: np.random.Generator,
) -> dict[str, Any]:
    base = {
        "benign": (18, 4, 2, 5, 1, 10, 0),
        "recon": (90, 2, 0, 80, 0, 4, 0),
        "credentials": (130, 110, 1, 2, 75, 8, 1),
        "injection": (55, 1, 45, 2, 3, 5, 8),
        "dos": (360, 330, 4, 10, 40, 25, 12),
        "media": (48, 1, 22, 1, 1, 18, 2),
        "tollfraud": (36, 1, 28, 1, 1, 8, 1),
    }[attack_class]
    jitter = int(rng.integers(0, 4))
    total, register, invite, options, auth_4xx, success, error = base
    total += offset + jitter
    return {
        "window_start": window_start,
        "src_ip": src_ip,
        "total_msgs": total,
        "register_count": max(0, register + jitter),
        "invite_count": max(0, invite + (offset % 3)),
        "options_count": max(0, options + (offset % 2)),
        "auth_4xx_count": max(0, auth_4xx + jitter),
        "success_2xx": max(0, success + (offset % 3)),
        "error_5xx": max(0, error + (jitter if attack_class in {"dos", "injection"} else 0)),
        "distinct_ua": 1 if attack_class == "benign" else min(total, 2 + offset % 4),
        "distinct_to_uri": min(total, 3 + offset if attack_class != "benign" else 2),
        "distinct_call_id": min(total, max(1, invite + register // 3)),
        "sum_body_size": int(total * (80 + 10 * (offset % 5))),
        "sample_count": total,
    }


def build_synthetic_feature_dataset(
    samples_per_class: int = 6,
    seed: int = DEFAULT_RANDOM_SEED,
    reason: str = "empty_clickhouse",
) -> FeatureDataset:
    """Create a deterministic, clearly marked fallback dataset for dry pipelines."""
    rng = np.random.default_rng(seed)
    start = datetime(2026, 4, 16, 8, 0, tzinfo=timezone.utc)
    windows: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []

    attack_ids_by_class = {
        "recon": "sippts_options_scan",
        "credentials": "sippts_svcrack",
        "injection": "sippts_malformed_invite",
        "dos": "sipp_register_flood",
        "media": "rtp_inject",
        "tollfraud": "dialplan_abuse",
    }
    mitre_by_class = {
        "recon": "T1595",
        "credentials": "T1110.001",
        "injection": "T1190",
        "dos": "T1499",
        "media": "T1557",
        "tollfraud": "T1496",
    }

    for class_index, attack_class in enumerate(TARGET_CLASSES):
        src_ip = f"198.51.100.{10 + class_index}"
        for sample_index in range(samples_per_class):
            window_start = start + timedelta(minutes=5 * (class_index * samples_per_class + sample_index))
            windows.append(_synthetic_window(window_start, src_ip, attack_class, sample_index, rng))
            if attack_class != "benign":
                labels.append(
                    {
                        "label_time": window_start + timedelta(seconds=45 + sample_index),
                        "src_ip": src_ip,
                        "attack_id": attack_ids_by_class[attack_class],
                        "mitre_technique": mitre_by_class[attack_class],
                        "phase": attack_class,
                        "notes": f"synthetic fallback {reason}",
                    }
                )

    dataset = build_labeled_feature_dataset(windows=windows, labels=labels, label_source="synthetic_fallback")
    metadata = dataset.metadata.copy()
    metadata["synthetic"] = True
    metadata["label_source"] = metadata["label_source"].where(
        metadata["label_source"] != "explicit_benign_window",
        "synthetic_benign_window",
    )
    return FeatureDataset(
        features=dataset.features,
        labels=dataset.labels,
        metadata=metadata,
        synthetic=True,
        source=f"synthetic_fallback:{reason}",
    )


def _time_bounds_for_labels(windows: Sequence[dict[str, Any]]) -> tuple[datetime, datetime]:
    starts = [coerce_datetime(row["window_start"]) for row in windows]
    return min(starts), max(starts) + timedelta(seconds=WINDOW_SECONDS)


def load_labeled_dataset(
    client: Any | None = None,
    features_table: str = DEFAULT_FEATURES_TABLE,
    events_table: str = DEFAULT_EVENTS_TABLE,
    labels_table: str = DEFAULT_LABELS_TABLE,
    since_hours: int = 24,
    limit: int = 50_000,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    synthetic_fallback: bool = True,
    seed: int = DEFAULT_RANDOM_SEED,
    feature_set: str = "legacy_full",
) -> FeatureDataset:
    """Load real ClickHouse windows, or a deterministic synthetic fallback."""
    use_events = feature_set == "response_enriched"
    try:
        ch_client = client or build_clickhouse_client()
        windows: list[dict[str, Any]] = []
        source = features_table
        if use_events:
            windows = fetch_feature_windows_from_events(
                ch_client,
                events_table=events_table,
                since_hours=since_hours,
                limit=limit,
                start_time=start_time,
                end_time=end_time,
                feature_set=feature_set,
            )
            source = events_table
        else:
            windows = fetch_feature_windows(
                ch_client,
                features_table=features_table,
                since_hours=since_hours,
                limit=limit,
                start_time=start_time,
                end_time=end_time,
            )
            if not windows:
                windows = fetch_feature_windows_from_events(
                    ch_client,
                    events_table=events_table,
                    since_hours=since_hours,
                    limit=limit,
                    start_time=start_time,
                    end_time=end_time,
                    feature_set=feature_set,
                )
                source = events_table
    except Exception as exc:
        if not synthetic_fallback:
            raise
        return build_synthetic_feature_dataset(seed=seed, reason=f"clickhouse_unavailable_{type(exc).__name__}")

    if not windows:
        if synthetic_fallback:
            return build_synthetic_feature_dataset(seed=seed, reason="empty_clickhouse")
        return build_labeled_feature_dataset([], [], feature_set=feature_set)

    try:
        label_start, label_end = _time_bounds_for_labels(windows)
        labels = fetch_attack_labels(ch_client, labels_table=labels_table, start_time=label_start, end_time=label_end)
    except Exception as exc:
        if not synthetic_fallback:
            raise
        return build_synthetic_feature_dataset(seed=seed, reason=f"labels_unavailable_{type(exc).__name__}")

    dataset = build_labeled_feature_dataset(windows=windows, labels=labels, feature_set=feature_set)
    return FeatureDataset(dataset.features, dataset.labels, dataset.metadata, synthetic=False, source=source)


def assert_feature_schema(frame: pd.DataFrame, feature_columns: Sequence[str] | None = None) -> None:
    expected = list(feature_columns or FEATURE_COLUMNS)
    missing = sorted(set(expected) - set(frame.columns))
    extra = sorted(set(frame.columns) - set(expected))
    if missing or extra:
        raise ValueError(f"feature schema mismatch missing={missing} extra={extra}")


def feature_documentation_rows(feature_set: str = "legacy_full") -> list[dict[str, str]]:
    columns = get_feature_columns(feature_set)
    return [{"feature": name, "description": FEATURE_DESCRIPTIONS[name]} for name in columns]


def iter_feature_rows(dataset: FeatureDataset) -> Iterable[dict[str, Any]]:
    for feature_row, label, metadata_row in zip(
        dataset.features.to_dict("records"),
        dataset.labels.tolist(),
        dataset.metadata.to_dict("records"),
        strict=True,
    ):
        yield {"features": feature_row, "label": label, "metadata": metadata_row}
