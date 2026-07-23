# MLflow

Experiment tracking for the ML runs. MLflow is the ledger that ties a run's data,
features, prompts, and rules to its metrics, so regressions like "better recall
but worse latency" are explainable and comparable across changes.

It tracks:

- Stage-1 feature-engineering and model runs (windowing, SIP features, CV scores).
- Stage-2 prompt-template versions and their precision/recall/latency against `attack_labels`.
- RAG corpus versions and eval-as-judge scoring runs.

## Tracking URI

`MLFLOW_TRACKING_URI` decides where runs are stored. The default is a local
file store:

```bash
export MLFLOW_TRACKING_URI="file:///mlruns"
export MLFLOW_PROJECT_NAME="ngn-sip-detect-defend"
```

Point it at a remote MLflow server (with the matching `MLFLOW_TRACKING_USERNAME`
/ token env vars) if you want a shared tracking backend. The tracking dir
(`models/mlruns/`) is not committed.
