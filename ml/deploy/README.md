# Stage 1 online scorer - deployment bundle

This is the runtime bundle for the Stage 1 behavioural scorer as deployed on the
campus VM. It was previously VM-only (`~/ml-deploy`); it lives here now so the
live scoring path is reproducible from the repository, not just from the host.

## Contents

| File | Role |
|------|------|
| `scorer.py` | Online scorer: reads `sip_features_5min` windows from ClickHouse, runs the XGBoost multiclass model + IsolationForest baseline, writes `ngn_sip.ml_scores`. |
| `models/stage1_xgboost.pkl`, `stage1_pipeline.joblib` | Trained XGBoost multiclass arm + preprocessing pipeline. |
| `models/stage1_isolation_forest.pkl`, `isoforest_pipeline.joblib` | Benign-only IsolationForest baseline + pipeline. |
| `models/classes.json` | Class label order for the multiclass head. |
| `models/metrics.json` | Metrics captured at train time for this model version. |
| `models/reexport.py` | Bridges train -> serve: converts the trainer's custom-wrapper `stage1_*.pkl` into the portable `*.joblib` + `classes.json` the scorer loads. |
| `ml_scores.sql` | DDL for `ngn_sip.ml_scores` (also mirrored by the live table). |
| `ml_rules.xml` | Wazuh rules 100150/100151 that turn `ml_scores` verdicts into SIEM alerts (the ML verdict rule referenced by the dashboard). |
| `Dockerfile`, `requirements.txt` | Container + Python deps for the scorer. |

The training/eval code that produces these models is under `ml/stage1/`; this
directory is the deployable result of that pipeline. The MLflow tracking dir
(`models/mlruns/`, ~3 MB) is intentionally not committed.

### Re-exporting after a retrain (train -> serve)

The trainer and the scorer use different artifact formats on purpose:

```
ml/stage1/train.py  ->  stage1_*.pkl            (custom detector dataclasses)
models/reexport.py  ->  *.joblib + classes.json (portable sklearn pipelines)
ml/deploy/scorer.py ->  loads the *.joblib      (no custom code at serve time)
```

After retraining you must run the re-export step or the scorer will not see the
new model:

```bash
make ml-export        # runs models/reexport.py locally
```

`reexport.py` defaults its paths to this directory and `ml/stage1`; override
`MODELS_DIR` / `STAGE1_DIR` to run it inside a container.

## Model class list: `classes.json` (6) vs `metrics.json` (7)

`classes.json` lists 6 labels (`benign, recon, credentials, injection, dos,
tollfraud`) and is the one `scorer.py` loads to map the XGBoost model's
predicted class index back to a string (`CLASSES[idx]`). This is correct and
must not be "completed" to 7: verified directly against the shipped
`stage1_pipeline.joblib`: `pipeline.classes_` is `[0, 1, 2, 3, 4, 5]` (6
values), so the trained model structurally cannot predict a 7th class.

`metrics.json`'s `detectors.xgboost.per_class` and `confusion_matrix` list 7
labels, adding `media`. That is not a mismatch to fix. `media` is a category
in the paper's attack taxonomy that had **zero** training/eval samples in this
dataset (`per_class.media.support == 0`, and its confusion-matrix row/column is
all zeros). scikit-learn/XGBoost only learn classes present in the training
data, so a class with zero support never enters `classes_` and the model can
never emit it. `metrics.json` intentionally keeps `media` in the table to
report that gap honestly (per the paper's per-class results); do not add a
7th entry to `classes.json` to "match" it, and do not drop `media` from
`metrics.json` to match `classes.json`: the numbers stay as-is. Fix means
retraining on a dataset that actually contains `media`-labeled windows, not
editing either file.

## Live `ml_scores` schema (campus VM)

```sql
CREATE TABLE ngn_sip.ml_scores (
    scored_at DateTime64(3) DEFAULT now64(3),
    bucket DateTime,
    src_ip String,
    predicted_class LowCardinality(String),
    proba Float32,
    anomaly_score Float32,
    model_version String
) ENGINE = MergeTree
PARTITION BY toYYYYMMDD(bucket)
ORDER BY (bucket, src_ip)
TTL toDateTime(bucket) + toIntervalDay(30);
```
