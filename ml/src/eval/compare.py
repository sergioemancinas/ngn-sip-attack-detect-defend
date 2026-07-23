from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd

BENIGN_LABEL = "benign"


@dataclass(frozen=True)
class DetectorResult:
    detector: str
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1: float
    fp_rate_vs_benign: float
    mean_latency_seconds: float | None
    median_latency_seconds: float | None
    p95_latency_seconds: float | None
    samples: int


def _to_utc(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, utc=True)


def normalize_labeled_windows(windows: pd.DataFrame) -> pd.DataFrame:
    required = {"window_start", "window_end", "src_ip", "label"}
    missing = sorted(required - set(windows.columns))
    if missing:
        raise ValueError(f"labeled windows missing columns: {', '.join(missing)}")

    frame = windows.copy()
    frame["window_start"] = _to_utc(frame["window_start"])
    frame["window_end"] = _to_utc(frame["window_end"])
    frame["src_ip"] = frame["src_ip"].astype(str)
    frame["label"] = frame["label"].fillna(BENIGN_LABEL).astype(str)
    if "label_time" in frame.columns:
        frame["label_time"] = _to_utc(frame["label_time"])
    else:
        frame["label_time"] = frame["window_start"]
    return frame.sort_values(["window_start", "src_ip"]).reset_index(drop=True)


def _empty_detection_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=["event_time", "src_ip", "detector", "detail"])


def read_json_lines(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                rows.append(json.loads(stripped))
    return rows


def suricata_events_from_eve(rows: Iterable[dict[str, Any]]) -> pd.DataFrame:
    records: list[dict[str, Any]] = []
    for row in rows:
        if row.get("event_type") != "alert" and "alert" not in row:
            continue
        alert = row.get("alert") if isinstance(row.get("alert"), dict) else {}
        records.append(
            {
                "event_time": row.get("timestamp") or row.get("event_time"),
                "src_ip": row.get("src_ip"),
                "detector": "suricata",
                "detail": str(alert.get("signature_id") or row.get("sig_id") or ""),
            }
        )
    if not records:
        return _empty_detection_frame()
    frame = pd.DataFrame.from_records(records)
    frame["event_time"] = _to_utc(frame["event_time"])
    frame["src_ip"] = frame["src_ip"].astype(str)
    return frame


def wazuh_events_from_alerts(rows: Iterable[dict[str, Any]]) -> pd.DataFrame:
    records: list[dict[str, Any]] = []
    for row in rows:
        rule = row.get("rule") if isinstance(row.get("rule"), dict) else {}
        data = row.get("data") if isinstance(row.get("data"), dict) else {}
        src_ip = data.get("srcip") or data.get("src_ip") or row.get("srcip") or row.get("src_ip")
        rule_id = rule.get("id") or row.get("rule_id")
        if not rule_id or not src_ip:
            continue
        records.append(
            {
                "event_time": row.get("timestamp") or row.get("alert_time") or row.get("event_time"),
                "src_ip": src_ip,
                "detector": "wazuh",
                "detail": str(rule_id),
            }
        )
    if not records:
        return _empty_detection_frame()
    frame = pd.DataFrame.from_records(records)
    frame["event_time"] = _to_utc(frame["event_time"])
    frame["src_ip"] = frame["src_ip"].astype(str)
    return frame


def ml_events_from_predictions(rows: pd.DataFrame) -> pd.DataFrame:
    required = {"window_start", "src_ip", "predicted_label"}
    missing = sorted(required - set(rows.columns))
    if missing:
        raise ValueError(f"ML predictions missing columns: {', '.join(missing)}")
    frame = rows.copy()
    detection_mask = frame["predicted_label"].astype(str) != BENIGN_LABEL
    if "stage1_detection" in frame.columns:
        stage1_mask = frame["stage1_detection"].astype(str).str.lower().isin({"true", "1", "yes"})
        detection_mask = detection_mask | stage1_mask
    frame = frame.loc[detection_mask].copy()
    if frame.empty:
        return _empty_detection_frame()
    frame["event_time"] = _to_utc(frame.get("window_end", frame["window_start"]))
    frame["detector"] = "ml"
    frame["detail"] = frame["predicted_label"].astype(str)
    return frame[["event_time", "src_ip", "detector", "detail"]]


def events_to_window_predictions(labeled_windows: pd.DataFrame, events: pd.DataFrame) -> tuple[np.ndarray, list[float]]:
    windows = normalize_labeled_windows(labeled_windows)
    predictions = np.zeros(len(windows), dtype=np.int64)
    latencies: list[float] = []
    if events.empty:
        return predictions, latencies

    event_frame = events.copy()
    event_frame["event_time"] = _to_utc(event_frame["event_time"])
    event_frame["src_ip"] = event_frame["src_ip"].astype(str)

    for index, window in windows.iterrows():
        matches = event_frame[
            (event_frame["src_ip"] == window["src_ip"])
            & (event_frame["event_time"] >= window["window_start"])
            & (event_frame["event_time"] < window["window_end"])
        ]
        if matches.empty:
            continue
        predictions[index] = 1
        if str(window["label"]) != BENIGN_LABEL:
            first_event_time = matches["event_time"].min()
            latency = (first_event_time - window["label_time"]).total_seconds()
            latencies.append(max(0.0, float(latency)))
    return predictions, latencies


def compute_detector_result(detector: str, labeled_windows: pd.DataFrame, predictions: np.ndarray, latencies: list[float]) -> DetectorResult:
    windows = normalize_labeled_windows(labeled_windows)
    truth = (windows["label"].astype(str) != BENIGN_LABEL).astype(int).to_numpy()
    if len(truth) != len(predictions):
        raise ValueError("prediction length does not match labeled windows")

    tp = int(np.sum((truth == 1) & (predictions == 1)))
    fp = int(np.sum((truth == 0) & (predictions == 1)))
    fn = int(np.sum((truth == 1) & (predictions == 0)))
    tn = int(np.sum((truth == 0) & (predictions == 0)))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    benign_total = int(np.sum(truth == 0))
    fp_rate = fp / benign_total if benign_total else 0.0

    latency_values = np.array(latencies, dtype=float)
    return DetectorResult(
        detector=detector,
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        precision=float(precision),
        recall=float(recall),
        f1=float(f1),
        fp_rate_vs_benign=float(fp_rate),
        mean_latency_seconds=float(np.mean(latency_values)) if len(latency_values) else None,
        median_latency_seconds=float(np.median(latency_values)) if len(latency_values) else None,
        p95_latency_seconds=float(np.percentile(latency_values, 95)) if len(latency_values) else None,
        samples=int(len(truth)),
    )


def compare_detector_arms(
    labeled_windows: pd.DataFrame,
    suricata_events: pd.DataFrame | None = None,
    wazuh_events: pd.DataFrame | None = None,
    ml_predictions: pd.DataFrame | None = None,
) -> pd.DataFrame:
    arms: list[tuple[str, pd.DataFrame]] = []
    if suricata_events is not None:
        arms.append(("suricata", suricata_events))
    if wazuh_events is not None:
        arms.append(("wazuh", wazuh_events))
    if ml_predictions is not None:
        arms.append(("ml", ml_events_from_predictions(ml_predictions)))

    results: list[DetectorResult] = []
    for detector, events in arms:
        predictions, latencies = events_to_window_predictions(labeled_windows, events)
        results.append(compute_detector_result(detector, labeled_windows, predictions, latencies))

    return pd.DataFrame([result.__dict__ for result in results]).sort_values("detector").reset_index(drop=True)


def write_results(table: pd.DataFrame, csv_path: Path, markdown_path: Path) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(csv_path, index=False)
    headers = list(table.columns)
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for row in table.to_dict("records"):
        lines.append("| " + " | ".join("" if pd.isna(row[column]) else str(row[column]) for column in headers) + " |")
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare Suricata, Wazuh, and Stage 1 ML detection results.")
    parser.add_argument("--labeled-windows", type=Path, required=True)
    parser.add_argument("--suricata-eve", type=Path)
    parser.add_argument("--wazuh-alerts", type=Path)
    parser.add_argument("--ml-predictions", type=Path)
    parser.add_argument("--csv-out", type=Path, required=True)
    parser.add_argument("--md-out", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    labeled_windows = pd.read_csv(args.labeled_windows)
    suricata = suricata_events_from_eve(read_json_lines(args.suricata_eve)) if args.suricata_eve else None
    wazuh = wazuh_events_from_alerts(read_json_lines(args.wazuh_alerts)) if args.wazuh_alerts else None
    ml_predictions = pd.read_csv(args.ml_predictions) if args.ml_predictions else None
    table = compare_detector_arms(
        labeled_windows=labeled_windows,
        suricata_events=suricata,
        wazuh_events=wazuh,
        ml_predictions=ml_predictions,
    )
    write_results(table=table, csv_path=args.csv_out, markdown_path=args.md_out)
    print(f"csv={args.csv_out}")
    print(f"markdown={args.md_out}")


if __name__ == "__main__":
    main()
