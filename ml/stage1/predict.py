from __future__ import annotations

import argparse
import json
import os
import pickle
from pathlib import Path
from typing import Any

from features import (
    DEFAULT_EVENTS_TABLE,
    DEFAULT_FEATURES_TABLE,
    DEFAULT_LABELS_TABLE,
    DEFAULT_RANDOM_SEED,
    FeatureDataset,
    build_clickhouse_client,
    load_labeled_dataset,
)

STAGE_DIR = Path(__file__).resolve().parent
DEFAULT_MODEL_PATH = STAGE_DIR / "models" / "stage1_xgboost.pkl"


def load_detector_artifact(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        artifact = pickle.load(handle)
    required = {"detector", "detector_name", "feature_columns", "target_classes"}
    missing = sorted(required - set(artifact))
    if missing:
        raise ValueError(f"invalid Stage 1 artifact missing: {', '.join(missing)}")
    return artifact


def prediction_rows(artifact: dict[str, Any], dataset: FeatureDataset) -> list[dict[str, Any]]:
    detector = artifact["detector"]
    predictions = detector.predict(dataset.features)
    scores = detector.attack_scores(dataset.features)
    rows: list[dict[str, Any]] = []
    for prediction, score, metadata in zip(predictions, scores, dataset.metadata.to_dict("records"), strict=True):
        predicted_label = str(prediction)
        stage1_detection = predicted_label != "benign"
        rows.append(
            {
                "alert_id": f"stage1:{artifact['detector_name']}:{metadata['src_ip']}:{metadata['window_start']}",
                "detector": artifact["detector_name"],
                "stage": "stage1",
                "window_start": str(metadata["window_start"]),
                "window_end": str(metadata["window_end"]),
                "src_ip": metadata["src_ip"],
                "predicted_label": predicted_label,
                "stage1_detection": stage1_detection,
                "attack_score": float(score),
                "advisory_source": "classical_ml",
                "synthetic": bool(metadata.get("synthetic", False)),
            }
        )
    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Stage 1 detector predictions on five-minute SIP windows.")
    parser.add_argument("--ch-host", default=os.getenv("CLICKHOUSE_HOST", "localhost"))
    parser.add_argument("--ch-port", type=int, default=int(os.getenv("CLICKHOUSE_PORT", "9000")))
    parser.add_argument("--ch-user", default=os.getenv("CLICKHOUSE_USER", "ngn"))
    parser.add_argument("--ch-password", default=os.getenv("CLICKHOUSE_PASSWORD", ""))
    parser.add_argument("--ch-database", default=os.getenv("CLICKHOUSE_DATABASE", "ngn_sip"))
    parser.add_argument("--features-table", default=DEFAULT_FEATURES_TABLE)
    parser.add_argument("--events-table", default=DEFAULT_EVENTS_TABLE)
    parser.add_argument("--labels-table", default=DEFAULT_LABELS_TABLE)
    parser.add_argument("--since-hours", type=int, default=1)
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--random-state", type=int, default=DEFAULT_RANDOM_SEED)
    parser.add_argument("--no-synthetic-fallback", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    artifact = load_detector_artifact(args.model_path)
    try:
        client = build_clickhouse_client(
            host=args.ch_host,
            port=args.ch_port,
            user=args.ch_user,
            password=args.ch_password,
            database=args.ch_database,
        )
        dataset = load_labeled_dataset(
            client=client,
            features_table=args.features_table,
            events_table=args.events_table,
            labels_table=args.labels_table,
            since_hours=args.since_hours,
            limit=args.limit,
            synthetic_fallback=not args.no_synthetic_fallback,
            seed=args.random_state,
        )
    except Exception:
        if args.no_synthetic_fallback:
            raise
        from features import build_synthetic_feature_dataset

        dataset = build_synthetic_feature_dataset(seed=args.random_state, reason="prediction_clickhouse_unavailable")

    for row in prediction_rows(artifact, dataset):
        print(json.dumps(row, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
