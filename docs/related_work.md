# Related Work

The SIP/VoIP intrusion-detection literature this project builds on, and the
standards that ground its protocol. The pattern across prior work: a single
detector tuned on a single attack type, high in-sample accuracy, and little
false-positive analysis on realistic benign traffic. This project's contribution
is the honest, leakage-free evaluation (grouped by source IP, bootstrap CIs,
negative results reported) across three arms on identical windows.

## SIP/VoIP detection literature

- **Asgharian, Akbari & Raahemi (2015)** — windowed SIP-header features (REGISTER/INVITE/RINGING statistics) with SVM for SIP DoS. [DOI: 10.1002/sec.1106](https://doi.org/10.1002/sec.1106). Motivates the 5-minute per-`src_ip` feature contract and the classical ML arm, but without grouped campaign isolation or bootstrap CIs.
- **Hybrid CNN-BLSTM SIP DDoS (Computer Networks, 2024)** — CNN spatial + stacked BLSTM temporal features for REGISTER/INVITE/ACK flooding. [ScienceDirect: S1389128623005911](https://www.sciencedirect.com/science/article/pii/S1389128623005911). The deep-learning flooding line this project contrasts against by reporting an honest grouped-CV F1 (0.75) rather than near-perfect in-sample accuracy on small datasets.
- **Nazih et al. (2019)** — n-gram SIP message features with a sparse l1-SVM for malformed / INVITE-flood / SPIT. [IJCCC](https://univagora.ro/jour/index.php/ijccc/article/view/3563). A fast linear baseline; this project uses tree-based XGBoost on behavioural window aggregates instead of raw n-grams.
- **Nazih et al., DoS/DDoS-on-SIP survey (Electronics, 2020)** — statistical, specification-based, and ML countermeasures for SIP flooding. [MDPI 9/11/1827](https://www.mdpi.com/2079-9292/9/11/1827). Notes high false-positive rates in simulated evaluations, which motivates this project's explicit benign class and FP-rate reporting in C3.
- **Tang, Cheng & Hao (2012)** — per-attribute distributions and Hellinger distance over SIP message types. [IEEE INFOCOM PDF](https://www.ece.iit.edu/~yucheng/YCheng_INFOCOM12_2.pdf). Motivates the 5-minute feature windows and the PIKE/Wazuh burst rules (`100103`, `100108`).
- **VoIPdocs, IRSF / toll-fraud (industry)** — operational use of SIP response codes (high volumes of 487 during premium-route probing). [voipdocs.io](https://voipdocs.io/international-toll-fraudinternational-revenue-share-fraud-irsf). Validates the C1 response-level angle: request-only Suricata EVE cannot compute the failure-response ratios, so HEP capture is required (`docs/C1_HEP_RESPONSE_FEATURES.md`).

## Standards

| Standard | Role | Anchor |
|---|---|---|
| **RFC 3261** (SIP) | Signaling semantics and security considerations (spoofable UDP source, digest/TLS); grounds SBC hardening and the ban allowlist | `infra/kamailio/` |
| **RFC 5390** (overload control) | Graded throttling semantics; grounds the SOAR `rate_limit_notify` policy | [`09_soar_runbook.md`](09_soar_runbook.md) |
| **OWASP LLM Top 10 (2025)** | Stage-2 guardrails: LLM01 injection (43% detector bypass measured), LLM05 output handling, LLM08 embedding consistency | `ml/stage2/` |
| **MITRE ATT&CK** | Technique mapping; toll-fraud standardized to **T1496**, with T1110/T1078 as access vectors | [`03_attack_playbook.md`](03_attack_playbook.md), `siem/sigma/mapping.md` |

## Cross-references

Evaluation protocol: [`06_evaluation_methodology.md`](06_evaluation_methodology.md) ·
threat model: [`02_threat_model.md`](02_threat_model.md) ·
detection cross-walk: [`04_detection_rules.md`](04_detection_rules.md).
