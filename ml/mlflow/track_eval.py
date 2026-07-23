from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable

import pandas as pd

EXPERIMENT_NAME = "ngn-sip-detection-eval"
MLFLOW_DIR = Path(__file__).resolve().parent
DEFAULT_TRACKING_URI = f"file://{MLFLOW_DIR / 'mlruns'}"


def resolve_tracking_uri(explicit: str | None = None) -> str:
    return explicit or os.getenv("MLFLOW_TRACKING_URI") or DEFAULT_TRACKING_URI


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def dataframe_fingerprint(frame: pd.DataFrame | None) -> str:
    if frame is None:
        return "no-frame"
    payload = frame.sort_index(axis=1).to_csv(index=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def deterministic_run_key(detector_name: str, params: dict[str, Any], metrics: dict[str, Any], data_hash: str) -> str:
    payload = {
        "detector_name": detector_name,
        "params": params,
        "metric_names": sorted(_flatten_numeric(metrics).keys()),
        "data_hash": data_hash,
    }
    return hashlib.sha256(stable_json(payload).encode("utf-8")).hexdigest()


def _flatten_numeric(value: Any, prefix: str = "") -> dict[str, float]:
    flattened: dict[str, float] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            child_prefix = f"{prefix}_{key}" if prefix else str(key)
            flattened.update(_flatten_numeric(item, child_prefix))
    elif isinstance(value, list):
        return flattened
    elif isinstance(value, bool):
        flattened[prefix] = float(int(value))
    elif isinstance(value, int | float) and value is not None:
        flattened[prefix] = float(value)
    return flattened


def _log_artifacts(paths: Iterable[Path]) -> None:
    import mlflow

    for path in paths:
        if path.exists():
            mlflow.log_artifact(str(path), artifact_path="artifacts")


def _existing_run_id(mlflow_module: Any, experiment_id: str, run_key: str) -> str | None:
    try:
        runs = mlflow_module.search_runs(
            experiment_ids=[experiment_id],
            filter_string=f"tags.ngn_run_key = '{run_key}'",
            output_format="list",
        )
    except Exception:
        return None
    if not runs:
        return None
    return runs[0].info.run_id


def _signature_dict(input_example: pd.DataFrame | None, predictions: Any) -> dict[str, Any] | None:
    if input_example is None:
        return None
    try:
        from mlflow.models import infer_signature

        signature = infer_signature(input_example, predictions)
    except Exception:
        return None
    return signature.to_dict()


def log_training_run(
    detector_name: str,
    params: dict[str, Any],
    metrics: dict[str, Any],
    artifact_paths: list[Path],
    model: Any,
    input_example: pd.DataFrame | None,
    predictions: Any,
    tracking_uri: str | None = None,
    experiment_name: str = EXPERIMENT_NAME,
) -> str:
    """Log a train or eval run to MLflow using a local file store by default."""
    import mlflow

    resolved_uri = resolve_tracking_uri(tracking_uri)
    mlflow.set_tracking_uri(resolved_uri)
    experiment = mlflow.set_experiment(experiment_name)

    data_hash = dataframe_fingerprint(input_example)
    run_key = deterministic_run_key(detector_name, params, metrics, data_hash)
    existing_run_id = _existing_run_id(mlflow, experiment.experiment_id, run_key)
    start_kwargs = {"run_id": existing_run_id} if existing_run_id else {"run_name": f"{detector_name}-{run_key[:12]}"}

    with mlflow.start_run(**start_kwargs) as run:
        mlflow.set_tag("ngn_run_key", run_key)
        mlflow.set_tag("detector", detector_name)
        mlflow.log_params({key: str(value) for key, value in params.items()})
        mlflow.log_metrics(_flatten_numeric(metrics))
        mlflow.log_dict(metrics, "metrics/metrics.json")

        signature = _signature_dict(input_example, predictions)
        if signature is not None:
            mlflow.log_dict(signature, "model/signature.json")

        pipeline = getattr(model, "pipeline", None)
        if pipeline is not None and input_example is not None:
            try:
                import mlflow.sklearn

                mlflow.sklearn.log_model(
                    sk_model=pipeline,
                    artifact_path="sklearn_pipeline",
                    signature=None,
                    input_example=input_example,
                )
            except Exception:
                mlflow.set_tag("sklearn_model_log_failed", "true")

        _log_artifacts(artifact_paths)
        return run.info.run_id


def log_results_table(
    table: pd.DataFrame,
    params: dict[str, Any],
    artifact_paths: list[Path],
    tracking_uri: str | None = None,
    experiment_name: str = EXPERIMENT_NAME,
) -> str:
    import mlflow

    resolved_uri = resolve_tracking_uri(tracking_uri)
    mlflow.set_tracking_uri(resolved_uri)
    experiment = mlflow.set_experiment(experiment_name)
    metrics = {f"{row.detector}_f1": float(row.f1) for row in table.itertuples() if hasattr(row, "f1")}
    run_key = deterministic_run_key("comparative_eval", params, metrics, dataframe_fingerprint(table))
    existing_run_id = _existing_run_id(mlflow, experiment.experiment_id, run_key)
    start_kwargs = {"run_id": existing_run_id} if existing_run_id else {"run_name": f"comparative-{run_key[:12]}"}

    with mlflow.start_run(**start_kwargs) as run:
        mlflow.set_tag("ngn_run_key", run_key)
        mlflow.set_tag("detector", "comparative_eval")
        mlflow.log_params({key: str(value) for key, value in params.items()})
        mlflow.log_metrics(metrics)
        mlflow.log_table(table, "metrics/comparative_results.json")
        _log_artifacts(artifact_paths)
        return run.info.run_id


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Log an existing metrics JSON file to MLflow.")
    parser.add_argument("--metrics-json", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, action="append", default=[])
    parser.add_argument("--detector-name", default="stage1")
    parser.add_argument("--tracking-uri", default=os.getenv("MLFLOW_TRACKING_URI"))
    parser.add_argument("--experiment-name", default=EXPERIMENT_NAME)
    parser.add_argument("--param", action="append", default=[], help="key=value parameter to log")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    metrics = json.loads(args.metrics_json.read_text(encoding="utf-8"))
    params = {}
    for item in args.param:
        key, _, value = item.partition("=")
        if not key or not value:
            raise SystemExit(f"invalid --param value: {item!r}")
        params[key] = value
    run_id = log_training_run(
        detector_name=args.detector_name,
        params=params,
        metrics=metrics,
        artifact_paths=[args.metrics_json, *args.artifact],
        model=None,
        input_example=None,
        predictions=None,
        tracking_uri=args.tracking_uri,
        experiment_name=args.experiment_name,
    )
    print(f"mlflow_run_id={run_id}")


if __name__ == "__main__":
    main()
