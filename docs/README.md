# Documentation

Design, evaluation, security, and operations documentation for the SIP
attack-detect-defend testbed. Start with the top-level [`README`](../README.md)
for the overview; this folder holds the detail.

## Architecture and design

- [`01_architecture.md`](01_architecture.md) — system architecture and the five functional rings
- [`02_threat_model.md`](02_threat_model.md) — STRIDE threat model and data-flow diagram
- [`architecture/data_flow_and_tests.md`](architecture/data_flow_and_tests.md) — data flow and the test layers
- [`05_kubernetes_migration.md`](05_kubernetes_migration.md) — the Helm/Kubernetes port (design-only)

## Attacks, detection, and response

- [`03_attack_playbook.md`](03_attack_playbook.md) — the attack catalogue across six phases
- [`04_detection_rules.md`](04_detection_rules.md) — attack ↔ Suricata ↔ Wazuh ↔ Sigma cross-walk
- [`09_soar_runbook.md`](09_soar_runbook.md) — SOAR runbook and the graded response policy
- [`soar_pipeline.md`](soar_pipeline.md) — Wazuh → Shuffle → ClickHouse alert flow

## ML, evaluation, and results

- [`06_evaluation_methodology.md`](06_evaluation_methodology.md) — leakage-free evaluation protocol
- [`08_llm_triage_design.md`](08_llm_triage_design.md) — Stage-2 LLM triage design and guardrails
- [`C1_HEP_RESPONSE_FEATURES.md`](C1_HEP_RESPONSE_FEATURES.md) — HEP response-level feature experiment
- [`related_work.md`](related_work.md) — literature grounding and standards
- [`results/`](results/) — pinned result snapshots (Stage-1, C3, Wazuh correlation)
- [`DATA_PROVENANCE.md`](DATA_PROVENANCE.md) — what the model was trained on and what is released

## Security and operations

- [`security/`](security/) — defense-in-depth notes, hardening runbooks, and CI security gates
- [`OPERATIONS_DEEP_DIVE.md`](OPERATIONS_DEEP_DIVE.md) — Wazuh/Vector/ClickHouse/Shuffle operational gotchas
- [`INTERNET_EXPOSURE.md`](INTERNET_EXPOSURE.md) — the checklist before any non-loopback exposure
- [`13_https_reverse_proxy.md`](13_https_reverse_proxy.md) — Caddy HTTPS reverse proxy and OIDC callbacks
- [`sso/`](sso/) — Keycloak SSO architecture and runbook
- [`12_stack_dashboard.md`](12_stack_dashboard.md) — the Next.js dashboard
- [`ethics_authorisation.md`](ethics_authorisation.md) — ethics and authorisation statement
