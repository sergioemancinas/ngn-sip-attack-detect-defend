from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    confusion_matrix,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import (
    GroupKFold,
    StratifiedGroupKFold,
    StratifiedKFold,
    train_test_split,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from features import (
    DEFAULT_EVENTS_TABLE,
    DEFAULT_FEATURES_TABLE,
    DEFAULT_LABELS_TABLE,
    DEFAULT_RANDOM_SEED,
    FEATURE_COLUMNS,
    TARGET_CLASSES,
    FeatureDataset,
    assert_feature_schema,
    get_feature_columns,
    load_labeled_dataset,
)

STAGE_DIR = Path(__file__).resolve().parent
MLFLOW_HELPER_DIR = STAGE_DIR.parent / "mlflow"
DEFAULT_MODEL_DIR = STAGE_DIR / "models"
DEFAULT_METRICS_PATH = STAGE_DIR / "metrics" / "stage1_metrics.json"
DEFAULT_EXPERIMENT_NAME = "ngn-sip-stage1"


class Stage1Detector(Protocol):
    name: str
    label_mode: str

    def fit(self, features: pd.DataFrame, labels: pd.Series) -> "Stage1Detector":
        ...

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        ...

    def attack_scores(self, features: pd.DataFrame) -> np.ndarray:
        ...


def build_preprocessor(feature_columns: list[str] | None = None) -> ColumnTransformer:
    columns = list(feature_columns or FEATURE_COLUMNS)
    return ColumnTransformer(
        transformers=[
            (
                "numeric",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="median")),
                        ("scaler", StandardScaler()),
                    ]
                ),
                columns,
            )
        ],
        remainder="drop",
    )


@dataclass
class XGBoostDetector:
    random_state: int = DEFAULT_RANDOM_SEED
    name: str = "xgboost"
    label_mode: str = "multiclass"
    feature_columns: list[str] | None = None

    def __post_init__(self) -> None:
        # Class encoding is built in fit() from the labels actually present, so
        # indices are contiguous 0..k-1. XGBoost rejects non-contiguous label
        # sets, which occurs when a predefined class is absent from the data
        # (e.g. no media samples leaves a gap in a fixed TARGET_CLASSES encoding).
        self.classes_: list[str] = []
        self.class_to_int_: dict[str, int] = {}
        self.pipeline: Pipeline | None = None

    def fit(self, features: pd.DataFrame, labels: pd.Series) -> "XGBoostDetector":
        from xgboost import XGBClassifier

        present = list(dict.fromkeys(str(v) for v in labels))
        # Keep benign + canonical attack order first for a stable attack_scores().
        self.classes_ = [c for c in TARGET_CLASSES if c in present] + [c for c in present if c not in TARGET_CLASSES]
        self.class_to_int_ = {label: index for index, label in enumerate(self.classes_)}
        encoded = np.array([self.class_to_int_[str(label)] for label in labels], dtype=np.int64)
        classifier = XGBClassifier(
            objective="multi:softprob",
            num_class=len(self.classes_),
            n_estimators=80,
            max_depth=3,
            learning_rate=0.08,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="mlogloss",
            tree_method="hist",
            random_state=self.random_state,
            seed=self.random_state,
            n_jobs=1,
        )
        self.pipeline = Pipeline(steps=[("features", build_preprocessor(self.feature_columns)), ("classifier", classifier)])
        self.pipeline.fit(features, encoded)
        return self

    def _require_pipeline(self) -> Pipeline:
        if self.pipeline is None:
            raise RuntimeError("detector has not been fitted")
        return self.pipeline

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        encoded = self._require_pipeline().predict(features)
        return np.array([self.classes_[int(value)] for value in encoded], dtype=object)

    def predict_proba(self, features: pd.DataFrame) -> np.ndarray:
        return self._require_pipeline().predict_proba(features)

    def attack_scores(self, features: pd.DataFrame) -> np.ndarray:
        probabilities = self.predict_proba(features)
        # If benign is absent from this fit (e.g. an all-attack training fold),
        # every sample is attack, so the attack score is 1.0.
        benign_index = self.class_to_int_.get("benign")
        if benign_index is None:
            return np.ones(probabilities.shape[0], dtype=float)
        return 1.0 - probabilities[:, benign_index]


@dataclass
class IsolationForestDetector:
    random_state: int = DEFAULT_RANDOM_SEED
    contamination: float = 0.15
    name: str = "isolation_forest"
    label_mode: str = "binary_anomaly"
    feature_columns: list[str] | None = None

    def __post_init__(self) -> None:
        self.pipeline: Pipeline | None = None

    def fit(self, features: pd.DataFrame, labels: pd.Series) -> "IsolationForestDetector":
        benign_mask = labels.astype(str) == "benign"
        fit_features = features.loc[benign_mask] if benign_mask.any() else features
        estimator = IsolationForest(
            n_estimators=120,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=1,
        )
        self.pipeline = Pipeline(steps=[("features", build_preprocessor(self.feature_columns)), ("classifier", estimator)])
        self.pipeline.fit(fit_features)
        return self

    def _require_pipeline(self) -> Pipeline:
        if self.pipeline is None:
            raise RuntimeError("detector has not been fitted")
        return self.pipeline

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        raw = self._require_pipeline().predict(features)
        return np.where(raw == -1, "attack", "benign")

    def attack_scores(self, features: pd.DataFrame) -> np.ndarray:
        return -1.0 * self._require_pipeline().decision_function(features)


def build_detector(name: str, random_state: int, feature_columns: list[str] | None = None) -> Stage1Detector:
    if name == "xgboost":
        return XGBoostDetector(random_state=random_state, feature_columns=feature_columns)
    if name == "isolation_forest":
        return IsolationForestDetector(random_state=random_state, feature_columns=feature_columns)
    raise ValueError(f"unsupported detector: {name}")


def split_indices(labels: pd.Series, test_size: float, random_state: int) -> tuple[np.ndarray, np.ndarray, str]:
    indices = np.arange(len(labels))
    counts = labels.astype(str).value_counts()
    if len(labels) >= 14 and counts.min() >= 2:
        train_idx, eval_idx = train_test_split(
            indices,
            test_size=test_size,
            random_state=random_state,
            stratify=labels.astype(str),
        )
        return np.asarray(train_idx), np.asarray(eval_idx), "stratified_holdout"
    return indices, indices, "train_eval_small_sample"


def _binary_labels(labels: pd.Series | np.ndarray | list[str]) -> np.ndarray:
    return np.array([0 if str(label) == "benign" else 1 for label in labels], dtype=np.int64)


def _latency_summary(metadata: pd.DataFrame, true_labels: pd.Series, predictions: np.ndarray) -> dict[str, float | None]:
    if metadata.empty:
        return {"mean_seconds": None, "median_seconds": None, "p95_seconds": None}

    latencies: list[float] = []
    for meta, true_label, predicted_label in zip(
        metadata.to_dict("records"),
        true_labels.astype(str).tolist(),
        predictions.tolist(),
        strict=True,
    ):
        if true_label == "benign" or str(predicted_label) == "benign":
            continue
        label_time = meta.get("label_time")
        if pd.isna(label_time):
            continue
        detection_time = meta.get("window_end") or meta.get("window_start")
        latency = (pd.Timestamp(detection_time) - pd.Timestamp(label_time)).total_seconds()
        latencies.append(max(0.0, float(latency)))

    if not latencies:
        return {"mean_seconds": None, "median_seconds": None, "p95_seconds": None}
    values = np.array(latencies, dtype=float)
    return {
        "mean_seconds": float(np.mean(values)),
        "median_seconds": float(np.median(values)),
        "p95_seconds": float(np.percentile(values, 95)),
    }


def _per_class_metrics(labels: list[str], true_labels: pd.Series, predictions: np.ndarray) -> dict[str, dict[str, float | int]]:
    precision, recall, f1, support = precision_recall_fscore_support(
        true_labels.astype(str),
        predictions.astype(str),
        labels=labels,
        zero_division=0,
    )
    return {
        label: {
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(f1[index]),
            "support": int(support[index]),
        }
        for index, label in enumerate(labels)
    }


def _roc_auc(detector: Stage1Detector, features: pd.DataFrame, true_labels: pd.Series) -> float | None:
    y_binary = _binary_labels(true_labels)
    if len(set(y_binary.tolist())) < 2:
        return None

    try:
        if isinstance(detector, XGBoostDetector):
            # A leakage-free (grouped) fold can put a class in eval that the model never
            # saw in training; that class has no encoding, so ROC-AUC is undefined here.
            if any(str(label) not in detector.class_to_int_ for label in true_labels):
                return None
            encoded_true = np.array([detector.class_to_int_[str(label)] for label in true_labels], dtype=np.int64)
            present = sorted(set(encoded_true.tolist()))
            if len(present) >= 2:
                probabilities = detector.predict_proba(features)
                return float(
                    roc_auc_score(
                        encoded_true,
                        probabilities,
                        labels=list(range(len(detector.classes_))),
                        multi_class="ovr",
                    )
                )
        return float(roc_auc_score(y_binary, detector.attack_scores(features)))
    except ValueError:
        return None


def compute_metrics(
    detector: Stage1Detector,
    features: pd.DataFrame,
    true_labels: pd.Series,
    metadata: pd.DataFrame,
) -> dict[str, Any]:
    predictions = detector.predict(features)
    if detector.label_mode == "multiclass":
        labels = list(TARGET_CLASSES)
        metric_true_labels = true_labels.astype(str)
    else:
        labels = ["benign", "attack"]
        metric_true_labels = pd.Series(
            np.where(true_labels.astype(str) == "benign", "benign", "attack"),
            index=true_labels.index,
            dtype="string",
        )

    y_binary = _binary_labels(true_labels)
    pred_binary = _binary_labels(predictions.tolist())
    binary_precision = precision_score(y_binary, pred_binary, zero_division=0)
    binary_recall = recall_score(y_binary, pred_binary, zero_division=0)
    binary_f1 = precision_recall_fscore_support(y_binary, pred_binary, average="binary", zero_division=0)[2]

    matrix = confusion_matrix(metric_true_labels.astype(str), predictions.astype(str), labels=labels)
    metrics = {
        "detector": detector.name,
        "label_mode": detector.label_mode,
        "samples": int(len(true_labels)),
        "per_class": _per_class_metrics(labels, metric_true_labels, predictions),
        "binary": {
            "precision": float(binary_precision),
            "recall": float(binary_recall),
            "f1": float(binary_f1),
        },
        "roc_auc": _roc_auc(detector, features, true_labels),
        "confusion_matrix": {
            "labels": labels,
            "matrix": matrix.astype(int).tolist(),
        },
        "alert_latency": _latency_summary(metadata, true_labels, predictions),
    }
    return metrics


def cross_validate_detector(
    detector_name: str,
    dataset: FeatureDataset,
    random_state: int,
    requested_splits: int,
) -> dict[str, Any]:
    counts = dataset.labels.astype(str).value_counts()
    if counts.empty or counts.min() < 2:
        return {"splits": 0, "reason": "not_enough_samples_per_class"}

    splits = int(min(requested_splits, counts.min()))
    if splits < 2:
        return {"splits": 0, "reason": "not_enough_samples_per_class"}

    fold_metrics: list[dict[str, Any]] = []
    splitter = StratifiedKFold(n_splits=splits, shuffle=True, random_state=random_state)
    for fold_index, (train_idx, eval_idx) in enumerate(splitter.split(dataset.features, dataset.labels.astype(str)), start=1):
        detector = build_detector(detector_name, random_state=random_state)
        detector.fit(dataset.features.iloc[train_idx], dataset.labels.iloc[train_idx])
        metrics = compute_metrics(
            detector=detector,
            features=dataset.features.iloc[eval_idx],
            true_labels=dataset.labels.iloc[eval_idx],
            metadata=dataset.metadata.iloc[eval_idx],
        )
        fold_metrics.append(
            {
                "fold": fold_index,
                "binary_precision": metrics["binary"]["precision"],
                "binary_recall": metrics["binary"]["recall"],
                "binary_f1": metrics["binary"]["f1"],
                "roc_auc": metrics["roc_auc"],
            }
        )

    return {
        "splits": splits,
        "folds": fold_metrics,
        "mean_binary_f1": float(np.mean([fold["binary_f1"] for fold in fold_metrics])),
    }


def _bootstrap_binary_f1_ci(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    iterations: int = 2000,
    random_state: int = DEFAULT_RANDOM_SEED,
) -> dict[str, float]:
    """Bootstrap 95% CI for binary F1 over pooled out-of-fold predictions.

    Reports an interval rather than a single point so the small-N result is not
    presented as more precise than it is (evaluation-audit finding: ML gap on CIs).
    """
    rng = np.random.default_rng(random_state)
    n = len(y_true)
    if n == 0:
        return {"point": 0.0, "lo95": 0.0, "hi95": 0.0, "iterations": 0}
    point = float(precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)[2])
    scores: list[float] = []
    for _ in range(iterations):
        idx = rng.integers(0, n, n)
        # Skip degenerate resamples with a single class in truth (F1 undefined direction).
        if len(np.unique(y_true[idx])) < 2:
            continue
        scores.append(
            float(precision_recall_fscore_support(y_true[idx], y_pred[idx], average="binary", zero_division=0)[2])
        )
    if not scores:
        return {"point": point, "lo95": point, "hi95": point, "iterations": 0}
    return {
        "point": point,
        "lo95": float(np.percentile(scores, 2.5)),
        "hi95": float(np.percentile(scores, 97.5)),
        "iterations": len(scores),
    }


def grouped_cross_validate_detector(
    detector_name: str,
    dataset: FeatureDataset,
    random_state: int,
    requested_splits: int,
    feature_columns: list[str] | None = None,
) -> dict[str, Any]:
    """Leakage-free CV: group by source IP so no campaign straddles train and eval.

    Each attack run in attack_matrix uses a distinct static source IP, so grouping by
    src_ip isolates campaigns. Reports per-fold F1 and a bootstrap 95% CI on the pooled
    out-of-fold predictions. This is the apples-to-apples protocol the C3 comparison
    needs (evaluation-audit findings: ML HIGH gaps 1 and 2).
    """
    if "src_ip" not in dataset.metadata.columns:
        return {"splits": 0, "reason": "no_src_ip_in_metadata"}
    groups = dataset.metadata["src_ip"].astype(str).to_numpy()
    labels_str = dataset.labels.astype(str).to_numpy()
    n_groups = len(np.unique(groups))
    counts = pd.Series(labels_str).value_counts()
    if counts.empty or counts.min() < 2 or n_groups < 2:
        return {"splits": 0, "reason": "not_enough_groups_or_samples", "n_groups": int(n_groups)}

    splits = int(min(requested_splits, n_groups, counts.min()))
    if splits < 2:
        return {"splits": 0, "reason": "not_enough_groups_or_samples", "n_groups": int(n_groups)}

    # StratifiedGroupKFold keeps groups intact and balances classes; fall back to plain
    # GroupKFold when stratification is infeasible for the group/class layout.
    try:
        splitter = StratifiedGroupKFold(n_splits=splits, shuffle=True, random_state=random_state)
        split_iter = list(splitter.split(dataset.features, labels_str, groups=groups))
        splitter_name = "StratifiedGroupKFold"
    except ValueError:
        splitter = GroupKFold(n_splits=splits)
        split_iter = list(splitter.split(dataset.features, labels_str, groups=groups))
        splitter_name = "GroupKFold"

    fold_metrics: list[dict[str, Any]] = []
    oof_true = np.full(len(dataset.labels), -1, dtype=np.int64)
    oof_pred = np.full(len(dataset.labels), -1, dtype=np.int64)
    for fold_index, (train_idx, eval_idx) in enumerate(split_iter, start=1):
        # Guard against a fold whose training split lost a whole class.
        if len(np.unique(labels_str[train_idx])) < 2:
            continue
        detector = build_detector(detector_name, random_state=random_state, feature_columns=feature_columns)
        detector.fit(dataset.features.iloc[train_idx], dataset.labels.iloc[train_idx])
        metrics = compute_metrics(
            detector=detector,
            features=dataset.features.iloc[eval_idx],
            true_labels=dataset.labels.iloc[eval_idx],
            metadata=dataset.metadata.iloc[eval_idx],
        )
        eval_true = _binary_labels(dataset.labels.iloc[eval_idx])
        eval_pred = _binary_labels(detector.predict(dataset.features.iloc[eval_idx]).tolist())
        oof_true[eval_idx] = eval_true
        oof_pred[eval_idx] = eval_pred
        fold_metrics.append(
            {
                "fold": fold_index,
                "binary_precision": metrics["binary"]["precision"],
                "binary_recall": metrics["binary"]["recall"],
                "binary_f1": metrics["binary"]["f1"],
                "roc_auc": metrics["roc_auc"],
            }
        )

    scored = oof_true >= 0
    ci = _bootstrap_binary_f1_ci(oof_true[scored], oof_pred[scored], random_state=random_state)
    return {
        "splitter": splitter_name,
        "splits": len(fold_metrics),
        "n_groups": int(n_groups),
        "folds": fold_metrics,
        "mean_binary_f1": float(np.mean([fold["binary_f1"] for fold in fold_metrics])) if fold_metrics else 0.0,
        "oof_binary_f1_ci95": ci,
    }


def train_eval_detector(
    detector_name: str,
    dataset: FeatureDataset,
    random_state: int = DEFAULT_RANDOM_SEED,
    test_size: float = 0.25,
    cv_splits: int = 5,
    feature_columns: list[str] | None = None,
) -> tuple[Stage1Detector, dict[str, Any]]:
    columns = list(feature_columns or FEATURE_COLUMNS)
    assert_feature_schema(dataset.features, columns)
    train_idx, eval_idx, split_name = split_indices(dataset.labels, test_size=test_size, random_state=random_state)
    detector = build_detector(detector_name, random_state=random_state, feature_columns=columns)
    detector.fit(dataset.features.iloc[train_idx], dataset.labels.iloc[train_idx])
    eval_metrics = compute_metrics(
        detector=detector,
        features=dataset.features.iloc[eval_idx],
        true_labels=dataset.labels.iloc[eval_idx],
        metadata=dataset.metadata.iloc[eval_idx],
    )
    eval_metrics["split"] = split_name
    # `cv_naive_leaky` is a plain StratifiedKFold on windows: the SAME source IP
    # can land in both train and eval, so its F1 is optimistically inflated by
    # campaign leakage. It is retained ONLY as the deliberate contrast to
    # `grouped_cv` below (the honest, leakage-free number the paper reports).
    # Do NOT cite `cv_naive_leaky` as a performance figure. Renamed from the
    # ambiguous "cv" key so it cannot be mistaken for the headline metric.
    eval_metrics["cv_naive_leaky"] = cross_validate_detector(detector_name, dataset, random_state=random_state, requested_splits=cv_splits)
    eval_metrics["grouped_cv"] = grouped_cross_validate_detector(
        detector_name,
        dataset,
        random_state=random_state,
        requested_splits=cv_splits,
        feature_columns=columns,
    )
    eval_metrics["synthetic_training_data"] = bool(dataset.synthetic)
    eval_metrics["dataset_source"] = dataset.source
    return detector, eval_metrics


def save_detector_artifact(
    detector: Stage1Detector,
    path: Path,
    metrics: dict[str, Any],
    params: dict[str, Any],
    feature_columns: list[str] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "detector_name": detector.name,
        "label_mode": detector.label_mode,
        "feature_columns": list(feature_columns or FEATURE_COLUMNS),
        "target_classes": list(TARGET_CLASSES),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "params": params,
        "metrics": metrics,
        "detector": detector,
    }
    with path.open("wb") as handle:
        pickle.dump(artifact, handle)


def write_metrics(path: Path, metrics: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(metrics, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _load_track_eval() -> Any | None:
    if str(MLFLOW_HELPER_DIR) not in sys.path:
        sys.path.insert(0, str(MLFLOW_HELPER_DIR))
    try:
        import track_eval
    except ImportError:
        return None
    return track_eval


def maybe_log_mlflow(
    detector: Stage1Detector,
    dataset: FeatureDataset,
    metrics: dict[str, Any],
    params: dict[str, Any],
    artifact_paths: list[Path],
    tracking_uri: str | None,
    experiment_name: str,
) -> str | None:
    helper = _load_track_eval()
    if helper is None:
        return None
    return helper.log_training_run(
        detector_name=detector.name,
        params=params,
        metrics=metrics,
        artifact_paths=artifact_paths,
        model=detector,
        input_example=dataset.features.head(5),
        predictions=detector.predict(dataset.features.head(5)),
        tracking_uri=tracking_uri,
        experiment_name=experiment_name,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train reproducible Stage 1 SIP detectors.")
    parser.add_argument("--ch-host", default=os.getenv("CLICKHOUSE_HOST", "localhost"))
    parser.add_argument("--ch-port", type=int, default=int(os.getenv("CLICKHOUSE_PORT", "9000")))
    parser.add_argument("--ch-user", default=os.getenv("CLICKHOUSE_USER", "ngn"))
    parser.add_argument("--ch-password", default=os.getenv("CLICKHOUSE_PASSWORD", ""))
    parser.add_argument("--ch-database", default=os.getenv("CLICKHOUSE_DATABASE", "ngn_sip"))
    parser.add_argument("--features-table", default=DEFAULT_FEATURES_TABLE)
    parser.add_argument("--events-table", default=DEFAULT_EVENTS_TABLE)
    parser.add_argument("--labels-table", default=DEFAULT_LABELS_TABLE)
    parser.add_argument("--since-hours", type=int, default=24)
    parser.add_argument("--limit", type=int, default=50_000)
    parser.add_argument("--detector", choices=["xgboost", "isolation_forest", "both"], default="both")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--cv-splits", type=int, default=5)
    parser.add_argument("--random-state", type=int, default=DEFAULT_RANDOM_SEED)
    parser.add_argument("--model-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--metrics-path", type=Path, default=DEFAULT_METRICS_PATH)
    parser.add_argument("--tracking-uri", default=os.getenv("MLFLOW_TRACKING_URI"))
    parser.add_argument("--experiment-name", default=DEFAULT_EXPERIMENT_NAME)
    parser.add_argument("--feature-set", choices=["legacy_full", "request_only", "response_enriched"], default="legacy_full")
    parser.add_argument("--no-synthetic-fallback", action="store_true")
    parser.add_argument("--no-mlflow", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    from features import build_clickhouse_client

    try:
        client = build_clickhouse_client(
            host=args.ch_host,
            port=args.ch_port,
            user=args.ch_user,
            password=args.ch_password,
            database=args.ch_database,
        )
    except Exception:
        if args.no_synthetic_fallback:
            raise
        from features import build_synthetic_feature_dataset

        dataset = build_synthetic_feature_dataset(seed=args.random_state, reason="clickhouse_client_unavailable")
    else:
        dataset = load_labeled_dataset(
            client=client,
            features_table=args.features_table,
            events_table=args.events_table,
            labels_table=args.labels_table,
            since_hours=args.since_hours,
            limit=args.limit,
            synthetic_fallback=not args.no_synthetic_fallback,
            seed=args.random_state,
            feature_set=args.feature_set,
        )
    if dataset.features.empty:
        raise SystemExit("No feature windows available and synthetic fallback is disabled.")

    detector_names = ["xgboost", "isolation_forest"] if args.detector == "both" else [args.detector]
    feature_columns = get_feature_columns(args.feature_set)
    all_metrics: dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset_source": dataset.source,
        "synthetic_training_data": dataset.synthetic,
        "feature_set": args.feature_set,
        "feature_columns": feature_columns,
        "detectors": {},
    }

    for detector_name in detector_names:
        params = {
            "detector": detector_name,
            "random_state": args.random_state,
            "test_size": args.test_size,
            "cv_splits": args.cv_splits,
            "feature_set": args.feature_set,
            "features_table": args.features_table,
            "events_table": args.events_table,
            "labels_table": args.labels_table,
            "since_hours": args.since_hours,
            "synthetic_training_data": dataset.synthetic,
        }
        detector, metrics = train_eval_detector(
            detector_name=detector_name,
            dataset=dataset,
            random_state=args.random_state,
            test_size=args.test_size,
            cv_splits=args.cv_splits,
            feature_columns=feature_columns,
        )
        model_path = args.model_dir / f"stage1_{detector_name}_{args.feature_set}.pkl"
        save_detector_artifact(detector=detector, path=model_path, metrics=metrics, params=params, feature_columns=feature_columns)
        all_metrics["detectors"][detector_name] = {**metrics, "model_path": str(model_path)}

        if not args.no_mlflow:
            run_id = maybe_log_mlflow(
                detector=detector,
                dataset=dataset,
                metrics=metrics,
                params=params,
                artifact_paths=[model_path],
                tracking_uri=args.tracking_uri,
                experiment_name=args.experiment_name,
            )
            all_metrics["detectors"][detector_name]["mlflow_run_id"] = run_id

    write_metrics(args.metrics_path, all_metrics)
    print(f"metrics_path={args.metrics_path}")
    for detector_name, metrics in all_metrics["detectors"].items():
        gcv = metrics.get("grouped_cv", {})
        ci = gcv.get("oof_binary_f1_ci95", {}) if isinstance(gcv, dict) else {}
        gcv_str = (
            f" grouped_cv_f1={gcv.get('mean_binary_f1', 0):.4f}"
            f" oof_f1={ci.get('point', 0):.4f}[{ci.get('lo95', 0):.4f},{ci.get('hi95', 0):.4f}]"
            f" groups={gcv.get('n_groups', 0)}"
            if ci
            else f" grouped_cv={gcv.get('reason', 'n/a')}"
        )
        print(
            f"{detector_name}: model_path={metrics['model_path']} "
            f"holdout_binary_f1={metrics['binary']['f1']:.4f} roc_auc={metrics['roc_auc']}"
            f"{gcv_str}"
        )


if __name__ == "__main__":
    main()
