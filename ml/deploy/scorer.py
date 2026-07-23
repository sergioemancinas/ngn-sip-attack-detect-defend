#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import signal
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
import pandas as pd
from clickhouse_driver import Client
from clickhouse_driver.errors import Error as ClickHouseError


FEATURE_COLUMNS = [
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

MODEL_PATH = Path(os.getenv("MODEL_PATH", "/models/stage1_pipeline.joblib"))
ISOFOREST_PATH = Path(os.getenv("ISOFOREST_PATH", "/models/isoforest_pipeline.joblib"))
CLASSES_PATH = Path(os.getenv("CLASSES_PATH", "/models/classes.json"))
DEFAULT_ML_LOG_PATH = Path("/var/ossec/logs/ml/stage1.json")
EPOCH = datetime(1970, 1, 1)
CLASSES: list[str] = []

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_STOP = threading.Event()
_LOGGER = logging.getLogger("stage1-scorer")


class ShutdownRequested(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    clickhouse_host: str
    clickhouse_port: int
    clickhouse_user: str
    clickhouse_password: str
    clickhouse_database: str
    score_interval_seconds: int
    ml_log_path: Path


@dataclass(frozen=True)
class ScoreResult:
    window_start: datetime
    src_ip: str
    predicted_class: str
    proba: float
    anomaly_score: float


_RESERVED_LOG_FIELDS = set(
    vars(logging.LogRecord("reserved", logging.INFO, "", 0, "", (), None))
) | {"message", "asctime"}


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": utc_now_iso(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED_LOG_FIELDS and not key.startswith("_"):
                payload[key] = json_safe(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonLogFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())


def json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return datetime_to_utc_iso(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    return value


def utc_now_iso(*, timespec: str = "seconds") -> str:
    return datetime.now(timezone.utc).isoformat(timespec=timespec).replace("+00:00", "Z")


def datetime_to_utc_iso(value: datetime, *, timespec: str = "seconds") -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat(timespec=timespec).replace("+00:00", "Z")


def parse_positive_int(name: str, default: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be > 0, got {value}")
    return value


def load_settings() -> Settings:
    database = os.getenv("CLICKHOUSE_DATABASE", "ngn_sip")
    quote_identifier(database)
    return Settings(
        clickhouse_host=os.getenv("CLICKHOUSE_HOST", "clickhouse"),
        clickhouse_port=parse_positive_int("CLICKHOUSE_PORT", 9000),
        clickhouse_user=os.getenv("CLICKHOUSE_USER", "ngn"),
        clickhouse_password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        clickhouse_database=database,
        score_interval_seconds=parse_positive_int("SCORE_INTERVAL_SECONDS", 60),
        ml_log_path=Path(os.getenv("ML_LOG_PATH", str(DEFAULT_ML_LOG_PATH))),
    )


def quote_identifier(identifier: str) -> str:
    if not _IDENTIFIER_RE.fullmatch(identifier):
        raise RuntimeError(f"Unsafe ClickHouse identifier: {identifier!r}")
    return f"`{identifier}`"


def install_signal_handlers() -> None:
    def request_shutdown(signum: int, _frame: Any) -> None:
        _LOGGER.info("shutdown_requested", extra={"signal": signum})
        _STOP.set()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)


def sha256_model_version(path: Path) -> str:
    override = os.getenv("MODEL_VERSION")
    if override:
        return override

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()[:12]


def validate_feature_names(model: Any, model_name: str) -> None:
    actual_raw = getattr(model, "feature_names_in_", None)
    if actual_raw is None:
        return

    actual = [str(name) for name in list(actual_raw)]
    expected = list(FEATURE_COLUMNS)
    if actual != expected:
        raise RuntimeError(
            f"{model_name} feature_names_in_ mismatch: expected {expected}, got {actual}"
        )


def load_models() -> tuple[Any, Any | None, str]:
    global CLASSES
    if not MODEL_PATH.exists():
        raise RuntimeError(f"Stage-1 pipeline not found at {MODEL_PATH}")
    if not CLASSES_PATH.exists():
        raise RuntimeError(f"classes.json not found at {CLASSES_PATH}")

    model = joblib.load(MODEL_PATH)
    if not hasattr(model, "predict_proba"):
        raise RuntimeError("Stage-1 pipeline must expose predict_proba()")
    with CLASSES_PATH.open() as fh:
        CLASSES = [str(c) for c in json.load(fh)]

    isoforest = None
    if ISOFOREST_PATH.exists():
        isoforest = joblib.load(ISOFOREST_PATH)
        if not hasattr(isoforest, "score_samples"):
            raise RuntimeError("IsolationForest pipeline must expose score_samples()")

    model_version = sha256_model_version(MODEL_PATH)
    _LOGGER.info(
        "models_loaded",
        extra={
            "model_path": str(MODEL_PATH),
            "classes": CLASSES,
            "isoforest_path": str(ISOFOREST_PATH) if isoforest is not None else None,
            "model_version": model_version,
        },
    )
    return model, isoforest, model_version


def connect_clickhouse(settings: Settings) -> Client:
    delay = 1.0
    while not _STOP.is_set():
        try:
            client = Client(
                host=settings.clickhouse_host,
                port=settings.clickhouse_port,
                user=settings.clickhouse_user,
                password=settings.clickhouse_password,
                database=settings.clickhouse_database,
                connect_timeout=10,
                send_receive_timeout=30,
                sync_request_timeout=10,
            )
            client.execute("SELECT 1")
            _LOGGER.info(
                "clickhouse_connected",
                extra={
                    "host": settings.clickhouse_host,
                    "port": settings.clickhouse_port,
                    "database": settings.clickhouse_database,
                },
            )
            return client
        except Exception:
            _LOGGER.exception(
                "clickhouse_connect_failed",
                extra={"retry_seconds": delay, "host": settings.clickhouse_host},
            )
            if _STOP.wait(delay):
                break
            delay = min(delay * 2, 60.0)
    raise ShutdownRequested()


def disconnect_clickhouse(client: Client | None) -> None:
    if client is None:
        return
    try:
        client.disconnect()
    except Exception:
        _LOGGER.exception("clickhouse_disconnect_failed")


def scores_table(settings: Settings) -> str:
    return f"{quote_identifier(settings.clickhouse_database)}.{quote_identifier('ml_scores')}"


def source_table(settings: Settings) -> str:
    return f"{quote_identifier(settings.clickhouse_database)}.{quote_identifier('sip_features_5min')}"


def feature_query(settings: Settings) -> str:
    return f"""
SELECT
    window_start,
    toString(src_ip) AS src_ip_string,
    sum(total_msgs) AS total_msgs,
    sum(register_count) AS register_count,
    sum(invite_count) AS invite_count,
    sum(options_count) AS options_count,
    sum(auth_4xx_count) AS auth_4xx_count,
    sum(success_2xx) AS success_2xx,
    sum(error_5xx) AS error_5xx,
    uniqMerge(distinct_ua) AS distinct_ua,
    uniqMerge(distinct_to_uri) AS distinct_to_uri,
    uniqMerge(distinct_call_id) AS distinct_call_id,
    sum(sum_body_size) AS sum_body_size,
    sum(sample_count) AS sample_count
FROM {source_table(settings)}
WHERE window_start > %(watermark)s
  AND window_start <= now() - INTERVAL 300 SECOND
GROUP BY window_start, src_ip
ORDER BY window_start ASC, src_ip_string ASC
"""


def initialize_clickhouse(settings: Settings) -> tuple[Client, datetime]:
    delay = 1.0
    while not _STOP.is_set():
        client: Client | None = None
        try:
            client = connect_clickhouse(settings)
            watermark = load_watermark(client, settings)
            return client, watermark
        except ShutdownRequested:
            disconnect_clickhouse(client)
            raise
        except Exception:
            disconnect_clickhouse(client)
            _LOGGER.exception(
                "clickhouse_initialization_failed",
                extra={"retry_seconds": delay},
            )
            if _STOP.wait(delay):
                break
            delay = min(delay * 2, 60.0)
    raise ShutdownRequested()


def load_watermark(client: Client, settings: Settings) -> datetime:
    rows = client.execute(f"SELECT max(bucket) FROM {scores_table(settings)}")
    watermark = rows[0][0] if rows and rows[0] else None
    if watermark is None:
        watermark = EPOCH
    _LOGGER.info("watermark_loaded", extra={"watermark": watermark})
    return watermark


def fetch_rows(client: Client, settings: Settings, watermark: datetime) -> list[tuple[Any, ...]]:
    return client.execute(feature_query(settings), {"watermark": watermark})


def feature_frame(values: Sequence[Any]) -> pd.DataFrame:
    if len(values) != len(FEATURE_COLUMNS):
        raise RuntimeError(
            f"Feature value count mismatch: expected {len(FEATURE_COLUMNS)}, got {len(values)}"
        )
    df = pd.DataFrame([list(values)], columns=FEATURE_COLUMNS)
    # Derived features — MUST match ml/stage1/features.py _prepare_windows()
    total = df["total_msgs"]
    sample_count = df["sample_count"]

    def _sd(col: str) -> pd.Series:
        return (df[col] / total).replace([np.inf, -np.inf], np.nan).fillna(0.0)

    df["register_ratio"] = _sd("register_count")
    df["invite_ratio"] = _sd("invite_count")
    df["options_ratio"] = _sd("options_count")
    df["auth_4xx_ratio"] = _sd("auth_4xx_count")
    df["success_2xx_ratio"] = _sd("success_2xx")
    df["error_5xx_ratio"] = _sd("error_5xx")
    df["avg_body_size"] = (df["sum_body_size"] / sample_count).replace([np.inf, -np.inf], np.nan).fillna(0.0)
    df["ua_diversity_ratio"] = _sd("distinct_ua")
    df["to_uri_diversity_ratio"] = _sd("distinct_to_uri")
    df["call_id_diversity_ratio"] = _sd("distinct_call_id")
    return df


def score_row(row: tuple[Any, ...], model: Any, isoforest: Any | None) -> ScoreResult:
    expected_columns = 2 + len(FEATURE_COLUMNS)
    if len(row) != expected_columns:
        raise RuntimeError(f"Query row width mismatch: expected {expected_columns}, got {len(row)}")

    window_start = row[0]
    if not isinstance(window_start, datetime):
        raise RuntimeError(f"window_start must be datetime, got {type(window_start).__name__}")

    src_ip = str(row[1])
    features = feature_frame(row[2:])

    proba_values = np.asarray(model.predict_proba(features), dtype=float)
    if proba_values.ndim != 2 or proba_values.shape[0] != 1:
        raise RuntimeError(f"predict_proba returned unexpected shape {proba_values.shape}")
    idx = int(np.argmax(proba_values[0]))
    predicted_class = CLASSES[idx] if 0 <= idx < len(CLASSES) else str(idx)
    proba = float(proba_values[0][idx])
    if not np.isfinite(proba):
        raise RuntimeError(f"predict_proba returned non-finite probability {proba!r}")

    anomaly_score = 0.0
    if isoforest is not None:
        sample_scores = np.asarray(isoforest.score_samples(features), dtype=float).reshape(-1)
        if sample_scores.size != 1:
            raise RuntimeError(f"score_samples returned unexpected shape {sample_scores.shape}")
        anomaly_score = -float(sample_scores[0])
        if not np.isfinite(anomaly_score):
            raise RuntimeError(f"score_samples returned non-finite anomaly score {anomaly_score!r}")

    return ScoreResult(
        window_start=window_start,
        src_ip=src_ip,
        predicted_class=predicted_class,
        proba=proba,
        anomaly_score=anomaly_score,
    )


def insert_score(
    client: Client, settings: Settings, result: ScoreResult, model_version: str
) -> None:
    client.execute(
        f"""
INSERT INTO {scores_table(settings)}
    (bucket, src_ip, predicted_class, proba, anomaly_score, model_version)
VALUES
""",
        [
            (
                result.window_start,
                result.src_ip,
                result.predicted_class,
                float(result.proba),
                float(result.anomaly_score),
                model_version,
            )
        ],
    )


def append_ml_event(path: Path, result: ScoreResult, model_version: str) -> None:
    event = {
        "timestamp": utc_now_iso(timespec="milliseconds"),
        "ml": {
            "srcip": result.src_ip,
            "window": datetime_to_utc_iso(result.window_start),
            "predicted_class": result.predicted_class,
            "proba": round(result.proba, 3),
            "anomaly": round(result.anomaly_score, 3),
            "model_version": model_version,
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":"), ensure_ascii=False))
        handle.write("\n")


def row_window(row: tuple[Any, ...]) -> datetime | None:
    return row[0] if row and isinstance(row[0], datetime) else None


def row_src_ip(row: tuple[Any, ...]) -> str | None:
    return str(row[1]) if len(row) > 1 else None


def process_rows(
    client: Client,
    settings: Settings,
    rows: list[tuple[Any, ...]],
    model: Any,
    isoforest: Any | None,
    model_version: str,
    watermark: datetime,
) -> tuple[Client, datetime]:
    successes = 0
    failures = 0
    max_success_watermark = watermark
    # A row is "done" only after it is scored, inserted, AND written to the
    # Wazuh ML log. We advance the watermark only to the highest window that is
    # fully done AND strictly earlier than the first failed window, so a
    # partial failure (or a log-write error after a successful insert) causes
    # that window to be re-fetched next cycle rather than silently dropped from
    # the enforcement path. Direction of safety: re-deliver, never lose.
    succeeded_windows: list[datetime] = []
    earliest_failed: datetime | None = None

    def _mark_failed(win: datetime) -> None:
        nonlocal earliest_failed
        if earliest_failed is None or win < earliest_failed:
            earliest_failed = win

    for row in rows:
        if _STOP.is_set():
            break

        try:
            result = score_row(row, model, isoforest)
        except Exception:
            failures += 1
            _mark_failed(row_window(row))
            _LOGGER.exception(
                "window_score_failed",
                extra={"window": row_window(row), "src_ip": row_src_ip(row)},
            )
            continue

        try:
            insert_score(client, settings, result, model_version)
        except ClickHouseError:
            failures += 1
            _mark_failed(result.window_start)
            _LOGGER.exception(
                "score_insert_failed",
                extra={"window": result.window_start, "src_ip": result.src_ip},
            )
            disconnect_clickhouse(client)
            client = connect_clickhouse(settings)
            continue
        except Exception:
            failures += 1
            _mark_failed(result.window_start)
            _LOGGER.exception(
                "score_insert_failed",
                extra={"window": result.window_start, "src_ip": result.src_ip},
            )
            continue

        try:
            append_ml_event(settings.ml_log_path, result, model_version)
        except Exception:
            failures += 1
            _mark_failed(result.window_start)
            _LOGGER.exception(
                "ml_event_append_failed",
                extra={
                    "window": result.window_start,
                    "src_ip": result.src_ip,
                    "ml_log_path": settings.ml_log_path,
                },
            )
            continue

        # Fully done: scored + inserted + logged.
        succeeded_windows.append(result.window_start)
        successes += 1

    eligible = [
        w for w in succeeded_windows
        if earliest_failed is None or w < earliest_failed
    ]
    if eligible:
        max_success_watermark = max([watermark, *eligible])

    _LOGGER.info(
        "batch_complete",
        extra={
            "rows": len(rows),
            "successes": successes,
            "failures": failures,
            "watermark": max_success_watermark,
        },
    )
    return client, max_success_watermark


def run() -> int:
    setup_logging()
    install_signal_handlers()

    settings = load_settings()
    model, isoforest, model_version = load_models()
    client, watermark = initialize_clickhouse(settings)

    try:
        while not _STOP.is_set():
            try:
                rows = fetch_rows(client, settings, watermark)
            except Exception:
                _LOGGER.exception("feature_query_failed", extra={"watermark": watermark})
                disconnect_clickhouse(client)
                client, watermark = initialize_clickhouse(settings)
                if _STOP.wait(settings.score_interval_seconds):
                    break
                continue

            if rows:
                _LOGGER.info(
                    "windows_fetched",
                    extra={"rows": len(rows), "watermark": watermark},
                )
                client, watermark = process_rows(
                    client,
                    settings,
                    rows,
                    model,
                    isoforest,
                    model_version,
                    watermark,
                )

            if _STOP.wait(settings.score_interval_seconds):
                break
    finally:
        disconnect_clickhouse(client)
        _LOGGER.info("shutdown_complete")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except ShutdownRequested:
        _LOGGER.info("shutdown_complete")
        raise SystemExit(0)
    except Exception:
        if not logging.getLogger().handlers:
            setup_logging()
        _LOGGER.exception("service_failed")
        raise SystemExit(1)
