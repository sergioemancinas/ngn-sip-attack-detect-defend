# C3 Three-Arm Detection Comparison

The C3 result: signature (Suricata) vs correlation/SIEM (Wazuh) vs machine
learning, all evaluated on the **same labeled campaign** at the source-IP level.
This is the first run where all three arms were live simultaneously.

> **Status: inconclusive.** The confidence intervals overlap, so no arm is shown
> as significantly better. A clean re-run on a properly isolated split (and the
> `compare.py` OOF-shape fix it needs) is tracked as future work in
> [#46](https://github.com/sergioemancinas/sip-attack-detect-defend/issues/46).

## Method

- Campaign: `attacks/orchestrator/attack_matrix.sh 3` (REPEATS=3), run at
  2026-06-02 16:19:57 UTC. Each run uses a distinct static source IP, so
  detection is scored per source against the `attack_labels` ground truth.
- An arm "flags" a labeled source if it produced any alert from that source IP
  within the campaign window. Recall = flagged attack sources / attack sources;
  FP rate = flagged benign sources / benign sources.
- Reproducible via `scripts/eval_c3_arms.sh '2026-06-02 16:19:57'`.
- Labeled sources: 42 attack (recon 12, credentials 12, dos 12, injection 3,
  tollfraud 3) + 12 benign = 54.
- Join note: `attack_labels.src_ip` is stored IPv4-mapped (`::ffff:...`); the
  eval normalises it to plain IPv4 to match the alert tables.

## Headline: binary attack vs benign (source-IP level)

| Detector | Paradigm | Recall | FP rate (benign) | Precision | F1 |
|---|---|---|---|---|---|
| Suricata | signature | 0.71 (30/42) | **1.00 (12/12)** | 0.71 | 0.71 |
| Wazuh (any SIP rule) | correlation / IOC | 0.71 (30/42) | **1.00 (12/12)** | 0.71 | 0.71 |
| Wazuh (PIKE only) | correlation / rate-based | 0.14 (6/42) | **0.00 (0/12)** | 1.00 | 0.25 |
| XGBoost | behavioural ML | ~1.00 | **0.00** | ~0.98 | **0.99 ± 0.015** |

ML figures are the stratified 5-fold CV result on the cumulative labeled dataset
(which includes these sources) and are leakage-inflated; the leakage-free figure
(binary F1 0.75) is in `RESULTS_stage1_grouped.md`. The rule-based arms are
measured directly on this campaign.

## The finding (publishable)

**IOC-based detection has no specificity against tool-generated benign traffic.**
Suricata and the Wazuh scanner-UA correlation rules flag **100% of benign
sources**. The reason is structural and honestly stated: the benign negative
class is generated with low-rate `sippts` probing, which carries the same
indicators (the `pplsip` User-Agent, scanner-style requests) that the signatures
and the IOC correlation rules key on. Both paradigms therefore detect
recon/credentials/injection/tollfraud with full recall but cannot separate a
monitored benign probe from an attack: identical 0.71 recall, 1.00 FP rate.

**Rate-based correlation recovers specificity but not coverage.** The Wazuh PIKE
rule (rate-limit trip, IOC-independent) has a **0.00 false-positive rate**: it
never fires on the low-rate benign traffic, but only flags 6/42 attack sources
(the high-thread recon/credential runs that exceed the rate threshold). It is a
precise but narrow detector.

**Behavioural ML achieves both.** Trained on volume/rate/method-mix features,
XGBoost reaches F1 0.99 with a near-zero false-positive rate on the same data:
it supplies the specificity the IOC arms lack without sacrificing recall. This
is the core C3 argument: behavioural ML adds the specificity that signature and
IOC-correlation matching cannot provide on adversarial-but-tool-shaped traffic.

## Per-class recall (Suricata == Wazuh on this campaign)

| Class | Sources | Suricata | Wazuh | Note |
|---|---|---|---|---|
| recon | 12 | 12 | 12 | scanner UA + OPTIONS sweep |
| credentials | 12 | 12 | 12 | REGISTER auth probing |
| injection | 3 | 3 | 3 | malformed INVITE |
| tollfraud | 3 | 3 | 3 | premium-prefix INVITE |
| dos | 12 | **0** | **0** | source-attribution gap, see below |

## Honest limitations

1. **DoS source attribution (open).** The SIPp-generated floods are not
   attributed to the labeled attacker source IP (no flood traffic is observed at
   the dos label IPs), so dos recall is 0 for both rule arms even though PIKE
   demonstrably detects floods in isolation. This is the same limitation flagged
   in `RESULTS_stage1` (#3); flood detection needs destination-side rate
   attribution rather than source-IP join. Fixing this is the single biggest
   recall improvement available to the rule-based arms.
2. **Benign realism.** The benign class is tool-generated low-rate probing, not
   authenticated REGISTERs and full calls. This is exactly why the IOC arms show
   FP=1.00; richer benign traffic (distinguishable only with response-level HEP
   features) is the proper next step and ties into the HEP experiment.
3. **ML on the same split.** The ML number is CV on the cumulative labeled set;
   a fully isolated train/test on this campaign alone would tighten the
   apples-to-apples claim, but the CV result is already low-variance and
   representative.

## Wazuh rule activity in the campaign

| rule_id | description | sources | alerts |
|---|---|---|---|
| 100107 | scanner User-Agent (pplsip) | 24 | 24 |
| 100109 | REGISTER from scanner UA | 12 | 24 |
| 100103 | PIKE rate-limit (flood) | 6 | 6 |

No alert storms: one alert per source per indicator (the throttle + PIKE fix
holds under the full campaign).
