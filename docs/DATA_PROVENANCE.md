# Data Provenance and Released Artifacts

This note records exactly what the shipped model was trained on and what this
repository releases. It exists so the repo and the paper are consistent and so a
reviewer can see the data lineage at a glance.

## The model is trained on real traffic

The Stage-1 detector shipped in `ml/deploy/models/` (`metrics.json` →
`synthetic_training_data: false`, trained 2026-06-03) is fit on **per-source-IP,
5-minute behavioural feature vectors** - message-type counts, response-code
statistics, and diversity ratios - produced by this repository's own aggregation
pipeline (`ngn_sip.sip_features_5min` over `ngn_sip.sip_events`).

Those features come from **real SIP traffic on the TH Köln campus VM**: the
labeled attack campaigns plus a 6-day live-internet exposure (2026-06-23 – 06-29)
that drew tens of millions of Suricata alerts and millions of SIP events from
real internet sources. The model learns from the aggregated per-window features,
grouped by source IP (138 groups) under leakage-free cross-validation.

## What I release, and why

I release the **trained model**, its **provenance-pinned metrics**
(`ml/deploy/models/metrics.json`, `docs/results/*.json`), the **full training and
evaluation code** (`ml/stage1/train.py`, grouped CV), a **labeled sample**
(`ml/stage1/datasets/sip-dataset-2026-06-02.csv`) that runs the training path
end to end, and the **entire pipeline** that generates and scores this data
(`make up-all` → `make e2e`).

I do **not** ship the raw live-exposure corpus as a bulk downloadable dataset:
that is not what the artifact is for, and the aggregate capture is large and
VM-bound. Individual **observed attacker source addresses do appear** in the
dashboard and in the demo recording as the honeypot evidence they are, which is
standard practice for security research on a publicly-exposed edge. Two honesty
caveats travel with those addresses: they are third-party internet sources, and
independent threat intelligence confirmed only 7.6% of the automatically banned
ones, so a shown IP is "observed attacking the exposed SIP edge," not a verified
malicious actor. They are presented as observed telemetry, never as a
confirmed-attacker blocklist.

## Reproducibility posture

| Layer | Status |
|---|---|
| Attack → detect → score → respond **pipeline** | Fully reproducible: `make up-all` + post-steps + `make e2e`. |
| Evaluation **methodology** (source-IP-grouped CV, the C3 arms, the graded SOAR policy) | Fully reproducible: the code is the method (`ml/stage1/train.py`). |
| The published **metrics** (Table I: binary F1 0.75, ROC-AUC 0.947, 138 groups; live-exposure counts) | Provenance-pinned to the committed training-run JSON. Regenerating the identical numbers requires the full campus-VM corpus, which is not shipped as a bulk dataset. |

Re-training on freshly generated local traffic validates the training code and
produces a smaller model against local data - a working demonstration of the
same method, reported as such rather than as the campus-VM result.

This mirrors standard practice for security ML on real-world captures: ship the
model, the code, the pinned metrics, and a runnable sample; surface observed
attacker telemetry (with its confirmation caveat) rather than a bulk raw
dataset.

## A note on the leakage-free claim

The grouped cross-validation in `ml/stage1/train.py` groups by **source IP**
(`StratifiedGroupKFold`, `groups = src_ip`), which guarantees that no single
source IP appears in both the train and evaluation folds. The stronger phrasing
"no attack campaign spans train and test" holds only under the data assumption
that **each labeled campaign uses a distinct static source IP** (true for the
self-generated lab campaigns by construction). The training code does not
enforce that 1:1 campaign-to-IP mapping, so if a future campaign were labeled
across multiple source IPs, grouping by IP alone could split it across folds.
For reproductions on new data, group by `attack_id` (present in the metadata)
or assert the 1:1 mapping at load time. This does not affect the pinned results,
which were produced on data where the assumption holds; it is stated so the
protocol's guarantee is not overread.
