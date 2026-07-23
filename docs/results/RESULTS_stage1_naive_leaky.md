# Stage-1 Detection Results (naive, leaky baseline)

> **Superseded — do not cite this number.** Kept only to document the leakage
> that motivated the honest protocol. The reportable result is in
> [`RESULTS_stage1_grouped.md`](RESULTS_stage1_grouped.md).

The first Stage-1 run used **5-fold `StratifiedKFold` on 5-minute windows** and
reported an XGBoost binary F1 of **0.988 ± 0.015** (ROC-AUC 0.985) on the
114-row `sip-dataset-2026-06-02.csv`. Isolation Forest sat at 0.898.

That number is inflated. Each attack campaign uses a distinct static source IP
and produces many adjacent 5-minute windows; splitting on windows puts windows
from the **same campaign** in both train and test folds, so the model recognizes
the campaign rather than the attack class. Re-evaluating with
`StratifiedGroupKFold` grouped by source IP (no IP in both folds) drops binary
F1 to **0.75 [0.68, 0.81]** — the honest, leakage-free figure this project
reports. See [`RESULTS_stage1_grouped.md`](RESULTS_stage1_grouped.md) and
[`../06_evaluation_methodology.md`](../06_evaluation_methodology.md).
