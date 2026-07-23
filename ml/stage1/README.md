# Stage 1 Detectors

Stage 1 builds behavioural SIP detectors over 5-minute source-IP feature windows and
evaluates them against ground-truth attack labels. It trains two arms in sklearn
Pipelines (median impute + StandardScaler):

- `xgboost`: supervised multiclass detector (benign + attack classes), the primary arm.
- `isolation_forest`: unsupervised anomaly baseline, trained on benign-only windows.

## Inputs

- ClickHouse `ngn_sip.sip_features_5min` or `ngn_sip.sip_events` (feature sets in
  `features.py`: `legacy_full` 22 cols, `request_only` 16, `response_enriched` 31).
- ClickHouse `ngn_sip.attack_labels` (ground truth from
  `attacks.orchestrator.label_emitter`).

A window is labeled by its source IP and time: an attack label whose `label_time` falls in
the window labels that window with the attack class; windows with no matching label are the
explicit benign negative class (the false-positive denominator).

## Train

```bash
cd ml/stage1
python3 -m venv .venv && . .venv/bin/activate
pip install -e .

export CLICKHOUSE_HOST=localhost CLICKHOUSE_USER=ngn CLICKHOUSE_PASSWORD=...
python train.py --since-hours 336 --detector both --cv-splits 5 --feature-set legacy_full
```

C1 before/after experiment (request-only vs response-enriched on the same windows):

```bash
python ../c1_experiment.py --since-hours 336 --no-synthetic-fallback --output-dir ../results
```

See `docs/C1_HEP_RESPONSE_FEATURES.md`.

On the campus VM, ClickHouse's native port is not host-published, so training runs in a
one-off container on the `ngn-sip_sip_lab` network (see `~/run_ml_train.sh`).

### Evaluation protocol

Each run reports three views so the result is not over-stated:

- a random `--test-size` holdout (per-class P/R/F1, confusion matrix, ROC-AUC, latency);
- standard `StratifiedKFold` CV (`cv`); and
- **leakage-free `StratifiedGroupKFold` grouped by source IP** (`grouped_cv`), so no attack
  campaign's windows straddle train and eval, with a bootstrap 95% CI on the pooled
  out-of-fold binary F1. This is the headline number to cite. See
  `docs/results/RESULTS_stage1_grouped.md`.

A deterministic synthetic fallback exists and is tagged `synthetic_training_data` so
fallback numbers can never be passed off as real.

## Artifacts

Trained detectors are pickled per arm:

```text
ml/stage1/models/stage1_xgboost.pkl
ml/stage1/models/stage1_isolation_forest.pkl
```

Metrics (including `grouped_cv` and the CI) are written to
`ml/stage1/metrics/stage1_metrics.json`. Each run logs params, metrics, and a data
fingerprint to MLflow (local `mlruns` unless `MLFLOW_TRACKING_URI` is set); use `--no-mlflow`
to skip.

## Predict

```bash
python predict.py --since-hours 1 --limit 100
```

Predictions are emitted as JSON lines for downstream scoring / SOAR glue. The deployed
online scorer (`~/ml-deploy/scorer.py`) polls `sip_features_5min` on an interval and writes
verdicts to `ngn_sip.ml_scores`.
