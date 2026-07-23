# Stage 1 Detection Results, Leakage-Free Protocol

This supersedes an earlier headline binary number (also cited in
`RESULTS_c3_comparison.md`): XGBoost binary F1 = 0.988 from
**5-fold StratifiedKFold on windows**, which lets windows from the same attack run (same
source IP) fall in both train and eval. Because each attack run uses one static source IP
and produces several 5-minute windows, that is per-campaign leakage. This run re-evaluates
under a grouped protocol that removes it (internal audit, ML HIGH gaps 1 and 2).

## Protocol

- Data: `ngn_sip.sip_features_5min` joined to `ngn_sip.attack_labels` by source IP and
  5-minute window, live campus VM (`synthetic_training_data = false`), 14-day window.
- Leakage-free CV: `StratifiedGroupKFold`, **groups = source IP**, so no campaign's windows
  straddle train and eval. 138 groups, 5 folds.
- Confidence interval: bootstrap (2000 resamples) 95% CI on the pooled out-of-fold binary
  predictions, not just fold standard deviation.
- Also reported: a random 30% holdout for comparison.
- Reproduce: `train.py --since-hours 336 --detector both --cv-splits 5` (grouped CV and the
  CI are computed automatically in `grouped_cross_validate_detector`).

## Headline, binary attack vs benign

| Detector | Grouped-CV F1 | OOF F1 (95% CI) | ROC-AUC | Random-holdout F1 |
|---|---|---|---|---|
| XGBoost (supervised) | 0.746 | **0.750 [0.684, 0.812]** | 0.947 | 0.725 |
| Isolation Forest (unsupervised) | 0.385 | 0.378 [0.297, 0.454] | 0.584 | 0.329 |

The previously reported leaky number was 0.988. The honest, leakage-free figure is
**0.75 with a 95% CI of [0.68, 0.81]**. The grouped-CV mean (0.746), the bootstrap OOF
point (0.750) and the independent random holdout (0.725) agree, which is the evidence that
0.75, not 0.99, is the real operating point.

ROC-AUC stays high (0.947) while F1 sits at 0.75: the model ranks attack above benign well,
but the default decision threshold is not the F1-optimal one. Threshold calibration is a
cheap, honest follow-up that should lift F1 without retraining.

## Per-class (holdout eval, n=115)

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| benign | 0.81 | 0.97 | 0.88 | 73 |
| credentials | 0.77 | 0.63 | 0.69 | 16 |
| recon | 1.00 | 0.44 | 0.61 | 16 |
| injection | 0.50 | 0.75 | 0.60 | 4 |
| dos | 1.00 | 0.50 | 0.67 | 2 |
| tollfraud | n/a | n/a | n/a | 0 |
| media | n/a | n/a | n/a | 0 |

## DoS now joins (the "0 joinable" was the Suricata outage)

The earlier naive-CV run recorded DoS as 0 joinable rows. That was not a structural
bug: Suricata, the source of `sip_events` (and therefore of every feature window), had been
blind from 2026-06-02 17:38 until it was fixed on 2026-06-10, so the June 3 DoS floods
(`172.18.200.20-23`) ran during the blind window and were never captured. After the fix,
13 of the 32 DoS source IPs already appear in `sip_features_5min` and DoS windows join
(n=2 in this eval). New DoS campaigns will join normally.

## Honest remaining limitations (not yet closed)

- **Small and imbalanced.** injection (4), dos (2), tollfraud/media (0) in this eval split
  are below a reportable per-class threshold. Per-class claims need >=30 samples per class,
  which requires more attack campaigns; this is data collection, not a code change, and is
  not faked here.
- **Threshold not calibrated.** ROC-AUC 0.95 vs F1 0.75 indicates headroom from picking an
  F1-optimal threshold; do this on a held-out split, never on the test fold.
- **Tool-shaped benign.** The benign negative class is still low-rate `sippts` probing; a
  non-tool benign class (authenticated REGISTER, full calls) remains the right next step and
  ties to the HEP/response-level feature work.

## Files

- `stage1_metrics_grouped_2026-06-10.json`: full metrics (per-class, confusion, grouped_cv
  with the bootstrap CI), produced by this run.
