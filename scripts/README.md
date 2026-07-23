# Scripts

Helper scripts for bringing the stack up, wiring SSO/SOAR, generating data, and
running the demo. Most are called by `make` targets; run them directly only when
you need the finer-grained step.

## Bring-up and host setup
- `bootstrap.sh` — one idempotent post-`up` pass (indexer OIDC, log collectors, SSO clients, SOAR provisioning).
- `bootstrap_local.sh`, `bootstrap_dev_machine.sh`, `bootstrap_vm.sh` — environment-specific first-run setup.
- `setup_host_security.sh` — host hardening for the campus VM.

## Identity and SOAR wiring
- `setup_keycloak_sso_clients.sh` — create/update the Keycloak OIDC clients (grafana, shuffle, homer); `DRY_RUN=1` supported. See [`../docs/sso/sso_runbook.md`](../docs/sso/sso_runbook.md).
- `apply_wazuh_sso.sh` — push the Wazuh indexer OIDC config via `securityadmin.sh`.
- `provision_shuffle.sh` — import the SOAR workflow and wire the Wazuh webhook.
- `deploy_wazuh_agents.sh` — enroll Wazuh agents.

## Verification and evaluation
- `e2e_verify.sh` — drive labeled attack traffic and assert every ring produced evidence (`make e2e`).
- `smoke_sip_call.sh` — a single REGISTER/INVITE round trip.
- `ensure_suricata_capture.sh` — re-attach Suricata to the Kamailio netns after a restart.
- `eval_c3_arms.sh` — run the three-arm (signature vs correlation vs ML) comparison.

## Data and RAG
- `fetch_datasets.sh`, `export_dataset.sh`, `anonymize_dataset.py` — dataset fetch/export/anonymize.
- `ingest_rag_corpus.sh` — embed the RAG corpus into pgvector.
- `capture_traffic.sh` — packet capture for evidence.

## Demo
- `live_demo.sh`, `labeled_attack_demo.sh`, and `demo/` — scripted walkthroughs of the attack-detect-respond loop.

## Security scanning
- `scout_scan.sh`, `scout_triage.sh`, `scout_cron.sh`, `scout_triage_summarizer.py` — the Docker Scout CVE-triage pipeline. See [`../docs/security/scout_triage_README.md`](../docs/security/scout_triage_README.md).

## CI
- `set_required_checks.sh` — configure the required status checks on the default branch.
