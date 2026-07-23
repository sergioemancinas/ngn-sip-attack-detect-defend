#!/usr/bin/env python3
"""C1 before/after experiment: request-only vs response-enriched Stage 1 features.

Runs the same leakage-free protocol as train.py (StratifiedGroupKFold grouped by
src_ip, bootstrap 95% CI on pooled out-of-fold predictions) under two feature arms:

  A) request_only     - 16 request-side features (Suricata-equivalent baseline)
  B) response_enriched - A + response-level HEP features (401/404/486/487/408, ratios)

Requires ClickHouse rows with source='hep' and response_code > 0 for arm B to differ
from arm A on real traffic. Use --no-synthetic-fallback on the campus VM.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_recall_fscore_support
from sklearn.model_selection import GroupKFold, StratifiedGroupKFold

STAGE1_DIR = Path(__file__).resolve().parent / "stage1"
sys.path.insert(0, str(STAGE1_DIR))

from features import (  # noqa: E402
    DEFAULT_EVENTS_TABLE,
    DEFAULT_LABELS_TABLE,
    DEFAULT_RANDOM_SEED,
    TARGET_CLASSES,
    _time_bounds_for_labels,
    build_clickhouse_client,
    build_labeled_feature_dataset,
    fetch_attack_labels,
    fetch_feature_windows_from_events,
    get_feature_columns,
)
from train import (  # noqa: E402
    _bootstrap_binary_f1_ci,
    build_detector,
    compute_metrics,
)

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "results"


def _bootstrap_macro_f1_ci(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    labels: list[str],
    iterations: int = 2000,
    random_state: int = DEFAULT_RANDOM_SEED,
) -> dict[str, float]:
    rng = np.random.default_rng(random_state)
    n = len(y_true)
    if n == 0:
        return {"point": 0.0, "lo95": 0.0, "hi95": 0.0, "iterations": 0}
    point = float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0))
    scores: list[float] = []
    for _ in range(iterations):
        idx = rng.integers(0, n, n)
        if len(np.unique(y_true[idx])) < 2:
            continue
        scores.append(float(f1_score(y_true[idx], y_pred[idx], labels=labels, average="macro", zero_division=0)))
    if not scores:
        return {"point": point, "lo95": point, "hi95": point, "iterations": 0}
    return {
        "point": point,
        "lo95": float(np.percentile(scores, 2.5)),
        "hi95": float(np.percentile(scores, 97.5)),
        "iterations": len(scores),
    }


def grouped_oof_evaluate(
    dataset,
    detector_name: str,
    feature_columns: list[str],
    random_state: int,
    cv_splits: int,
) -> dict[str, Any]:
    groups = dataset.metadata["src_ip"].astype(str).to_numpy()
    labels_str = dataset.labels.astype(str).to_numpy()
    n_groups = len(np.unique(groups))
    counts = pd.Series(labels_str).value_counts()
    if counts.empty or counts.min() < 2 or n_groups < 2:
        return {"splits": 0, "reason": "not_enough_groups_or_samples", "n_groups": int(n_groups)}

    splits = int(min(cv_splits, n_groups, counts.min()))
    if splits < 2:
        return {"splits": 0, "reason": "not_enough_groups_or_samples", "n_groups": int(n_groups)}

    try:
        splitter = StratifiedGroupKFold(n_splits=splits, shuffle=True, random_state=random_state)
        split_iter = list(splitter.split(dataset.features, labels_str, groups=groups))
        splitter_name = "StratifiedGroupKFold"
    except ValueError:
        splitter = GroupKFold(n_splits=splits)
        split_iter = list(splitter.split(dataset.features, labels_str, groups=groups))
        splitter_name = "GroupKFold"

    oof_true_labels: list[str] = []
    oof_pred_labels: list[str] = []
    fold_metrics: list[dict[str, Any]] = []

    for fold_index, (train_idx, eval_idx) in enumerate(split_iter, start=1):
        if len(np.unique(labels_str[train_idx])) < 2:
            continue
        detector = build_detector(detector_name, random_state=random_state, feature_columns=feature_columns)
        detector.fit(dataset.features.iloc[train_idx], dataset.labels.iloc[train_idx])
        eval_features = dataset.features.iloc[eval_idx]
        eval_labels = dataset.labels.iloc[eval_idx]
        eval_metadata = dataset.metadata.iloc[eval_idx]
        metrics = compute_metrics(
            detector=detector,
            features=eval_features,
            true_labels=eval_labels,
            metadata=eval_metadata,
        )
        predictions = detector.predict(eval_features)
        oof_true_labels.extend(eval_labels.astype(str).tolist())
        oof_pred_labels.extend(predictions.astype(str).tolist())
        fold_metrics.append(
            {
                "fold": fold_index,
                "binary_f1": metrics["binary"]["f1"],
                "roc_auc": metrics["roc_auc"],
            }
        )

    y_true = np.array(oof_true_labels, dtype=object)
    y_pred = np.array(oof_pred_labels, dtype=object)
    y_binary_true = np.array([0 if label == "benign" else 1 for label in y_true], dtype=np.int64)
    y_binary_pred = np.array([0 if label == "benign" else 1 for label in y_pred], dtype=np.int64)

    present_labels = [label for label in TARGET_CLASSES if label in set(y_true)]
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=present_labels,
        zero_division=0,
    )
    per_class = {
        label: {
            "precision": float(precision[i]),
            "recall": float(recall[i]),
            "f1": float(f1[i]),
            "support": int(support[i]),
        }
        for i, label in enumerate(present_labels)
    }

    return {
        "splitter": splitter_name,
        "splits": len(fold_metrics),
        "n_groups": int(n_groups),
        "feature_count": len(feature_columns),
        "samples_scored": int(len(y_true)),
        "folds": fold_metrics,
        "per_class": per_class,
        "macro_f1": float(f1_score(y_true, y_pred, labels=present_labels, average="macro", zero_division=0)),
        "macro_f1_ci95": _bootstrap_macro_f1_ci(y_true, y_pred, present_labels, random_state=random_state),
        "binary_f1_ci95": _bootstrap_binary_f1_ci(y_binary_true, y_binary_pred, random_state=random_state),
    }


def hep_coverage(client, events_table: str, since_hours: int) -> dict[str, Any]:
    query = f"""
    SELECT
        count() AS total,
        countIf(source = 'hep') AS hep_rows,
        countIf(source = 'hep' AND response_code > 0) AS hep_responses,
        countIf(source = 'suricata') AS suricata_rows,
        countIf(response_code > 0) AS all_responses
    FROM {events_table}
    WHERE event_time >= now() - INTERVAL {int(since_hours)} HOUR
    """
    row = client.execute(query)[0]
    keys = ["total", "hep_rows", "hep_responses", "suricata_rows", "all_responses"]
    stats = dict(zip(keys, row, strict=True))
    stats["hep_response_pct"] = (
        float(stats["hep_responses"]) / float(stats["hep_rows"]) if stats["hep_rows"] else 0.0
    )
    return stats


def build_comparison_table(arm_a: dict[str, Any], arm_b: dict[str, Any]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    labels = sorted(set(arm_a.get("per_class", {})) | set(arm_b.get("per_class", {})))
    for label in labels:
        a = arm_a.get("per_class", {}).get(label, {})
        b = arm_b.get("per_class", {}).get(label, {})
        rows.append(
            {
                "label": label,
                "support": int(a.get("support") or b.get("support") or 0),
                "f1_request_only": a.get("f1"),
                "f1_response_enriched": b.get("f1"),
                "delta_f1": (b.get("f1") or 0.0) - (a.get("f1") or 0.0),
            }
        )
    rows.append(
        {
            "label": "macro",
            "support": arm_a.get("samples_scored"),
            "f1_request_only": arm_a.get("macro_f1"),
            "f1_response_enriched": arm_b.get("macro_f1"),
            "delta_f1": (arm_b.get("macro_f1") or 0.0) - (arm_a.get("macro_f1") or 0.0),
        }
    )
    rows.append(
        {
            "label": "binary_oof",
            "support": arm_a.get("samples_scored"),
            "f1_request_only": arm_a.get("binary_f1_ci95", {}).get("point"),
            "f1_response_enriched": arm_b.get("binary_f1_ci95", {}).get("point"),
            "delta_f1": (arm_b.get("binary_f1_ci95", {}).get("point") or 0.0)
            - (arm_a.get("binary_f1_ci95", {}).get("point") or 0.0),
        }
    )
    return pd.DataFrame(rows)


def write_markdown_report(
    path: Path,
    table: pd.DataFrame,
    arm_a: dict[str, Any],
    arm_b: dict[str, Any],
    coverage: dict[str, Any],
    meta: dict[str, Any],
) -> None:
    a_ci = arm_a.get("macro_f1_ci95", {})
    b_ci = arm_b.get("macro_f1_ci95", {})
    lines = [
        "# C1 HEP response-level feature experiment",
        "",
        f"Generated: {meta['created_at']}",
        "",
        "## Protocol",
        "- Same labeled windows and StratifiedGroupKFold grouped by `src_ip`.",
        "- Arm A: `request_only` (16 features, no response-code dependence).",
        "- Arm B: `response_enriched` (31 features, requires HEP rows in `sip_events`).",
        f"- Detector: {meta['detector']}, CV splits requested: {meta['cv_splits']}.",
        "",
        "## HEP coverage (sanity check)",
        f"- Total sip_events rows (window): {coverage.get('total')}",
        f"- HEP rows: {coverage.get('hep_rows')} | HEP responses (code>0): {coverage.get('hep_responses')}",
        f"- Suricata rows: {coverage.get('suricata_rows')}",
        "",
        "## Headline metrics",
        f"- Macro F1 request-only: {arm_a.get('macro_f1'):.4f} [{a_ci.get('lo95', 0):.4f}, {a_ci.get('hi95', 0):.4f}]",
        f"- Macro F1 response-enriched: {arm_b.get('macro_f1'):.4f} [{b_ci.get('lo95', 0):.4f}, {b_ci.get('hi95', 0):.4f}]",
        f"- Delta (B - A) macro F1: {(arm_b.get('macro_f1') or 0) - (arm_a.get('macro_f1') or 0):+.4f}",
        "",
        "## Per-class F1 comparison",
        "",
        "| label | support | F1 request-only | F1 response-enriched | delta |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for row in table.to_dict("records"):
        lines.append(
            f"| {row['label']} | {row['support']} | "
            f"{'' if row['f1_request_only'] is None else format(row['f1_request_only'], '.4f')} | "
            f"{'' if row['f1_response_enriched'] is None else format(row['f1_response_enriched'], '.4f')} | "
            f"{row['delta_f1']:+.4f} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="C1 request-only vs response-enriched Stage 1 experiment.")
    parser.add_argument("--ch-host", default=os.getenv("CLICKHOUSE_HOST", "localhost"))
    parser.add_argument("--ch-port", type=int, default=int(os.getenv("CLICKHOUSE_PORT", "9000")))
    parser.add_argument("--ch-user", default=os.getenv("CLICKHOUSE_USER", "ngn"))
    parser.add_argument("--ch-password", default=os.getenv("CLICKHOUSE_PASSWORD", ""))
    parser.add_argument("--ch-database", default=os.getenv("CLICKHOUSE_DATABASE", "ngn_sip"))
    parser.add_argument("--events-table", default=DEFAULT_EVENTS_TABLE)
    parser.add_argument("--labels-table", default=DEFAULT_LABELS_TABLE)
    parser.add_argument("--since-hours", type=int, default=336)
    parser.add_argument("--limit", type=int, default=50_000)
    parser.add_argument("--detector", choices=["xgboost", "isolation_forest"], default="xgboost")
    parser.add_argument("--cv-splits", type=int, default=5)
    parser.add_argument("--random-state", type=int, default=DEFAULT_RANDOM_SEED)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--no-synthetic-fallback", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    created_at = datetime.now(timezone.utc).isoformat()
    client = build_clickhouse_client(
        host=args.ch_host,
        port=args.ch_port,
        user=args.ch_user,
        password=args.ch_password,
        database=args.ch_database,
    )

    coverage = hep_coverage(client, args.events_table, args.since_hours)

    windows = fetch_feature_windows_from_events(
        client,
        events_table=args.events_table,
        since_hours=args.since_hours,
        limit=args.limit,
        feature_set="response_enriched",
    )
    if not windows:
        raise SystemExit("No sip_events windows available. Run labeled attacks with HEP capture enabled.")

    label_start, label_end = _time_bounds_for_labels(windows)
    labels = fetch_attack_labels(
        client,
        labels_table=args.labels_table,
        start_time=label_start,
        end_time=label_end,
    )
    dataset_a = build_labeled_feature_dataset(windows, labels, feature_set="request_only")
    dataset_b = build_labeled_feature_dataset(windows, labels, feature_set="response_enriched")

    if dataset_a.features.empty or dataset_b.features.empty:
        raise SystemExit("Feature preparation failed for one or both arms.")

    cols_a = get_feature_columns("request_only")
    cols_b = get_feature_columns("response_enriched")

    arm_a = grouped_oof_evaluate(
        dataset_a,
        detector_name=args.detector,
        feature_columns=cols_a,
        random_state=args.random_state,
        cv_splits=args.cv_splits,
    )
    arm_b = grouped_oof_evaluate(
        dataset_b,
        detector_name=args.detector,
        feature_columns=cols_b,
        random_state=args.random_state,
        cv_splits=args.cv_splits,
    )

    comparison = build_comparison_table(arm_a, arm_b)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    json_path = args.output_dir / f"c1_comparison_{stamp}.json"
    csv_path = args.output_dir / f"c1_comparison_{stamp}.csv"
    md_path = args.output_dir / f"RESULTS_c1_hep_{stamp}.md"

    payload = {
        "created_at": created_at,
        "protocol": "StratifiedGroupKFold by src_ip, bootstrap 95% CI",
        "detector": args.detector,
        "since_hours": args.since_hours,
        "hep_coverage": coverage,
        "synthetic_training_data": False,
        "arm_a_request_only": arm_a,
        "arm_b_response_enriched": arm_b,
        "comparison_table": comparison.to_dict("records"),
    }
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    comparison.to_csv(csv_path, index=False)
    write_markdown_report(
        md_path,
        comparison,
        arm_a,
        arm_b,
        coverage,
        meta={"created_at": created_at, "detector": args.detector, "cv_splits": args.cv_splits},
    )

    print(f"json={json_path}")
    print(f"csv={csv_path}")
    print(f"markdown={md_path}")
    print(
        f"macro_f1 A={arm_a.get('macro_f1'):.4f} B={arm_b.get('macro_f1'):.4f} "
        f"delta={(arm_b.get('macro_f1') or 0) - (arm_a.get('macro_f1') or 0):+.4f}"
    )


if __name__ == "__main__":
    main()
