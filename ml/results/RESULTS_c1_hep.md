# C1: HEP response-level feature experiment

Does adding SIP response-code features (from HEP capture) improve Stage-1
detection over request-only features? Result: a small but consistent gain.

## Protocol
- Same labeled windows and StratifiedGroupKFold grouped by `src_ip`.
- Arm A: `request_only` (16 features, no response-code dependence).
- Arm B: `response_enriched` (31 features, requires HEP rows in `sip_events`).
- Detector: xgboost, CV splits requested: 5.

## HEP coverage (sanity check)
- Total sip_events rows (window): 1296988
- HEP rows: 167792 | HEP responses (code>0): 80854
- Suricata rows: 1129196

## Headline metrics
- Macro F1 request-only: 0.5820 [0.5406, 0.6164]
- Macro F1 response-enriched: 0.5952 [0.5558, 0.6270]
- Delta (B - A) macro F1: +0.0132

## Per-class F1 comparison

| label | support | F1 request-only | F1 response-enriched | delta |
| --- | ---: | ---: | ---: | ---: |
| benign | 54 | 0.8421 | 0.8776 | +0.0354 |
| credentials | 24 | 0.9412 | 0.9412 | +0.0000 |
| dos | 24 | 0.8070 | 0.8846 | +0.0776 |
| injection | 6 | 0.0000 | 0.0000 | +0.0000 |
| recon | 25 | 0.9020 | 0.8679 | -0.0340 |
| tollfraud | 6 | 0.0000 | 0.0000 | +0.0000 |
| macro | 139 | 0.5820 | 0.5952 | +0.0132 |
| binary_oof | 139 | 0.9180 | 0.9333 | +0.0153 |
