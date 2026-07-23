# Evaluation Methodology

This project measures comparative detection efficacy across three detector
arms:

1. Suricata signature alerts from EVE JSON.
2. Wazuh correlation alerts from `alerts.json`.
3. Stage 1 classical ML predictions from the five-minute SIP feature windows.

Stage 2 LLM triage is excluded from primary detection scoring. It is measured
only as advisory post-processing for Stage 1 alerts, mainly for false-positive
review and analyst rationale quality.

## Dataset Contract

The ground truth source is `ngn_sip.attack_labels`, emitted by the attack
orchestrator with `attack_id`, `mitre_technique`, `phase`, `src_ip`, and
`label_time`. Feature windows come from `ngn_sip.sip_features_5min`, with a
fallback aggregation from `ngn_sip.sip_events` when the materialized feature
table is empty. Windows without a matching attack label for the same source IP
inside the five-minute interval are explicitly labeled `benign`.

The measured attack classes are:

| Class | Ground-truth phase | Example attack IDs |
|---|---|---|
| `recon` | `recon` | `sippts_options_scan`, `sipvicious_svmap` |
| `credentials` | `credentials` | `sippts_svcrack` |
| `injection` | `injection` | `sippts_smap_invite`, `sippts_malformed_invite` |
| `dos` | `dos` | `sipp_register_flood` |
| `media` | `media` | `rtp_inject` |
| `tollfraud` | `tollfraud` | `dialplan_abuse` |
| `benign` | no matching label | normal lab SIP traffic |

## Train And Test Protocol

Stage 1 is evaluated under a leakage-free protocol. A single attacker source IP
produces many correlated five-minute windows, so an ordinary window-level split
leaks whole attack campaigns across the train/test boundary and inflates scores.
Cross-validation is therefore `StratifiedGroupKFold` grouped by source IP: every
window from a given source stays entirely within one fold, and no source is ever
seen in both training and evaluation. A fixed random seed keeps each run
reproducible.

The supervised arm is XGBoost over the explicit class set above; the
unsupervised baseline is IsolationForest, trained primarily on benign windows
and scored as `benign` versus `attack`. Aggregate performance is reported with a
bootstrap 95% confidence interval rather than a single point estimate. Under the
grouped protocol, XGBoost reaches a binary F1 of **0.75 [0.68, 0.81]** and
ROC-AUC 0.947; IsolationForest sits well below at binary F1 0.38.

This grouped result supersedes an earlier 0.988 F1 produced by plain
window-level `StratifiedKFold`. That figure is retained only as a documented
example of source leakage, not as a performance claim: the
generalization-representative number is 0.75. Per-class precision, recall, F1,
and confusion matrices are always reported alongside the aggregate, because the
injection and toll-fraud classes still have too few labeled source groups for a
stable per-class estimate.

The synthetic fallback exists only so the code path runs before live lab data is
available. Any metrics produced from fallback data are marked synthetic and are
never presented as experimental evidence.

## Metrics

For each detector arm, `ml/src/eval/compare.py` computes:

| Metric | Definition |
|---|---|
| TP | Attack window with at least one detector event in the same source-IP window. |
| FP | Benign window with at least one detector event in the same source-IP window. |
| FN | Attack window with no detector event in the same source-IP window. |
| TN | Benign window with no detector event in the same source-IP window. |
| Precision | `TP / (TP + FP)`, zero when the denominator is zero. |
| Recall | `TP / (TP + FN)`, zero when the denominator is zero. |
| F1 | Harmonic mean of precision and recall, zero when both are zero. |
| FP rate vs benign | `FP / benign_windows`. |
| Latency | Earliest detector event time minus `label_time`, clamped at zero. |

Stage 1 training also records per-class precision, recall, F1, ROC-AUC where
defined, confusion matrices, and latency summaries. Latency for Stage 1 uses the
window close time as the detection time because the model scores completed
five-minute windows.

## Reproducibility

Every run records:

- Git commit and detector parameters when available.
- Fixed random seed.
- Feature column list and class list.
- Train/test split type.
- Cross-validation split count.
- Model artifact path.
- Metrics JSON.
- MLflow run key derived from parameters, metric names, and data fingerprint.

The default MLflow backend is a local file store under `ml/mlflow/mlruns`. No
external tracking server is required for local experiments.

## Stage 2 Triage Measurement

Stage 2 consumes Stage 1 alerts only. Its verdict is advisory and cannot
override a Stage 1 detection. The worker records guardrail outcomes, latency,
RAG context IDs, confidence, and rationale in `ngn_sip.llm_verdicts`.

Guardrails are mandatory for every triage call:

| Guardrail | Implementation |
|---|---|
| Input sanitization | Control characters are removed, long strings are truncated, and SIP log text is wrapped under `untrusted_alert_data`. |
| Prompt-injection mitigation | Instruction-like SIP text is flagged and the prompt states that SIP headers, bodies, URIs, and RAG excerpts are data only. |
| Output schema validation | The model response must be JSON with `verdict`, `confidence`, `reasoning`, and `rag_context_ids`. |
| Refusal path | Refusals, invalid JSON, schema errors, and call failures become `needs_review` with confidence `0.0`. |
| Advisory-only rule | The returned `advisory_only` and `stage1_detection_preserved` fields make clear that Stage 2 cannot suppress Stage 1. |

The metric hook compares triage verdicts with Stage 1 ground truth when the
ground-truth label is present in the alert envelope:

- Stage 1 false positive candidate: Stage 1 fired on a `benign` window.
- Triage marks benign: LLM verdict is `benign`.
- Advisory false-positive reduction candidate: both conditions are true.

This hook measures possible review value. It is not counted as detector
performance.

## Threats To Validity

Internal validity is strong: labels, traffic generation, and detector logs are all controlled. External validity is limited, since the traffic is less diverse than a carrier or enterprise SIP network. Two biases follow from a self-generated dataset: cooperative-attacker bias (attacks come from known lab scripts, which can inflate any detector that mirrors those tools) and single-host bias (early runs are on one host, so timing, packet visibility, and NAT behaviour differ from multi-host deployments). Class imbalance is expected, so reports include per-class metrics and confusion matrices, not just aggregate scores.
