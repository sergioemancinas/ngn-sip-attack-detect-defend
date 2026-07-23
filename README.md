# NGN SIP Attack-Detect-Defend

[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
![SIP/VoIP security testbed](https://img.shields.io/badge/domain-SIP%2FVoIP%20security-blue)
![Loopback-only lab](https://img.shields.io/badge/deployment-loopback--only%20lab-orange)

[![CI](https://github.com/sergioemancinas/ngn-sip-attack-detect-defend/actions/workflows/ci.yml/badge.svg)](https://github.com/sergioemancinas/ngn-sip-attack-detect-defend/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sergioemancinas/ngn-sip-attack-detect-defend/badge)](https://securityscorecards.dev/viewer/?uri=github.com/sergioemancinas/ngn-sip-attack-detect-defend)

## Demo



https://github.com/user-attachments/assets/f62fe960-1003-4489-b81f-ba241d3acd41


A 3-minute walkthrough: live ingress traffic through Suricata and Wazuh detection, ML triage, automated response, and observability.

*Note:* The source IPs shown are real honeypot telemetry captured on the exposed edge; see the data-provenance details under [Results](#results).

A reproducible SIP attack-detect-defend testbed and a candid evaluation study. It generates labeled attack traffic against a real SIP core (Kamailio, Asterisk, rtpengine) and compares three detection arms (Suricata signatures, Wazuh correlation, and an XGBoost classifier) under a leakage-free protocol: source-IP-grouped cross-validation with bootstrap confidence intervals, negative results reported plainly.

Detections drive an audited automated response through Kamailio active response and a graded Shuffle SOAR workflow. An advisory LLM triage stage is included and reported as latency-bound. All evidence lands in ClickHouse and is visible in Grafana and a Next.js dashboard. This repository is the artifact for the accompanying IEEE paper.

> [!WARNING]
> This is a **research lab, not a production platform**. It is lab-secure (loopback-bound, placeholder credentials) by design. Before exposing any of it beyond loopback, follow [`docs/INTERNET_EXPOSURE.md`](docs/INTERNET_EXPOSURE.md).

## Contents

- [Demo](#demo)
- [Security posture](#security-posture)
- [Architecture](#architecture)
- [ML triage](#ml-triage)
- [Results](#results)
- [Quick start](#quick-start)
- [Access](#access)
- [Components](#components)
- [Continuous integration](#continuous-integration)
- [Repository layout](#repository-layout)
- [Deployment](#deployment)
- [Known limitations](#known-limitations)
- [Documentation](#documentation)
- [Ethics](#ethics)
- [License](#license)

## Security posture

- No privileged containers. Every service runs with `no-new-privileges` and `cap_drop: ALL`, re-adding only the capabilities it needs.
- Container images are pinned to explicit versions; Dependabot tracks base images, pip, npm, and Actions.
- No secrets in the repository. Configuration comes from `.env`, copied from the `.env.example` placeholders, and CI runs a blocking Gitleaks scan.
- CI workflows run with least-privilege permissions (`contents: read`); an OpenSSF Scorecard workflow and a release SBOM track supply-chain posture.

## Architecture

```mermaid
flowchart LR
  Attacker(["Attacker<br/>sippts · SIPp · scapy"]):::atk

  subgraph CORE["SIP core"]
    direction TB
    Kamailio["Kamailio SBC<br/>PIKE rate-limit · NGN-SEC xlog · ban_table"]
    Asterisk["Asterisk PBX"]
    Rtpengine["rtpengine<br/>media relay"]
    Postgres[("PostgreSQL<br/>+ pgvector")]
  end

  subgraph DETECT["Detect"]
    direction TB
    Suricata["Suricata IDS"]
    Heplify["heplify<br/>HEP agent"]
    Homer["Homer<br/>HEP store + UI"]
    HepBridge["hep-bridge"]
  end

  subgraph EVID["Evidence & observe"]
    direction TB
    Vector["Vector"]
    ClickHouse[("ClickHouse<br/>evidence store")]
    Grafana["Grafana"]
    Prometheus["Prometheus"]
  end

  subgraph TRIAGE["ML triage"]
    direction TB
    Stage1["Stage 1<br/>XGBoost + IsolationForest"]
    Stage2["Stage 2<br/>Ollama LLM<br/>RAG-grounded · advisory"]
  end

  Wazuh["Wazuh SIEM<br/>SIP rules 100100-100134"]

  subgraph RESP["Respond"]
    direction TB
    Autoban["autoban<br/>deterministic"]
    Shuffle["Shuffle SOAR<br/>graded policy"]
    Relay["kamcmd-relay"]
  end

  subgraph IDP["Identity & proxy"]
    direction TB
    Caddy["Caddy<br/>TLS reverse proxy"]
    Keycloak["Keycloak<br/>OIDC SSO"]
    Dashboard["Next.js dashboard"]
  end

  %% SIP / data path (solid)
  Attacker --> Kamailio
  Kamailio --> Asterisk --> Rtpengine
  Kamailio --- Postgres
  Kamailio --> Suricata
  Kamailio -->|siptrace HEP| Heplify --> Homer
  Homer -->|poll| HepBridge
  Suricata & HepBridge --> Vector --> ClickHouse
  ClickHouse -->|SIP rules| Wazuh
  ClickHouse --> Stage1 --> Stage2
  Stage1 -->|verdict rules 100150/100151| Wazuh
  Wazuh --> Autoban & Shuffle
  Shuffle --> Relay
  Shuffle -->|enrich| ClickHouse

  %% Defend loop + observe / auth (dotted)
  Autoban & Relay -.->|ban_table| Kamailio
  Postgres -.->|RAG grounding| Stage2
  ClickHouse -.-> Grafana
  Prometheus -.-> Grafana
  ClickHouse -.-> Dashboard
  Keycloak -.->|OIDC SSO| Caddy
  Caddy -.->|TLS| Grafana & Dashboard

  classDef atk fill:#fde,stroke:#c33,color:#900;
```

The dashed edges are the closed defend loop: both the deterministic `autoban` and the graded Shuffle path enforce bans back at the Kamailio SBC through the shared `ban_table`.

The stack is organized into functional groups sharing one ClickHouse evidence store: the SIP core; detection (Suricata plus Homer/HEP capture); evidence and observability (Vector, ClickHouse, Grafana, Prometheus); ML triage (Stage-1 scorer, Stage-2 Ollama); response (autoban, Shuffle, kamcmd-relay); and identity and proxy (Keycloak, Caddy, the dashboard). Wazuh correlates across the groups and drives active response.

## ML triage

```mermaid
flowchart LR
    CH[("ClickHouse<br/>suricata_alerts · sip_events · attack_labels")]
    S1["Stage 1 — XGBoost<br/>per-source-IP 5-min features"]
    W["Wazuh<br/>verdict rules 100150/151"]
    S2["Stage 2 — Ollama LLM<br/>advisory triage"]
    RAG[("pgvector RAG corpus")]
    LV[("ClickHouse llm_verdicts")]
    CH --> S1 --> W --> S2 --> LV
    RAG --> S2
```

Stage-1 XGBoost scores per-source-IP behaviour; Wazuh turns high-confidence verdicts into alerts; Stage-2 Ollama adds RAG-grounded advisory triage that never overrides Stage-1. Detail in [`ml/README.md`](ml/README.md).

## Results

> [!NOTE]
> **Data provenance.** The shipped model is trained on real campus-VM SIP traffic (labeled campaigns plus a six-day live-internet exposure) aggregated into per-source-IP five-minute behavioural features across 138 source-IP groups. I release the trained model, the provenance-pinned metrics, the training code, a runnable labeled sample, and the full pipeline (`make e2e`); the metrics below are pinned to the committed training-run JSON. Observed attacker source addresses appear in the dashboard and demo as honeypot telemetry: third-party sources, only 7.6% threat-intel-confirmed, so shown as "observed on the exposed edge," not a verified blocklist. See [`docs/DATA_PROVENANCE.md`](docs/DATA_PROVENANCE.md).

![Stage-1 training and leakage-free evaluation: source-IP-grouped cross-validation, F1 0.75, confusion matrix](docs/media/ml_stage1_explainer.png)

- Stage-1 detection, leakage-free protocol. `StratifiedGroupKFold` grouped by source IP with a bootstrap 95% confidence interval gives an XGBoost binary F1 of **0.75 [0.68, 0.81]** and ROC-AUC 0.947. Isolation Forest sits far lower (binary F1 0.38). The earlier 0.988 figure came from `StratifiedKFold` on windows, which leaked whole attack campaigns across folds. Detail in [`docs/results/RESULTS_stage1_grouped.md`](docs/results/RESULTS_stage1_grouped.md).
- C1 HEP response-level features. Adding response-code features (31 versus 16 request-only) raises macro F1 by **+0.013** (0.582 to 0.595) and binary OOF F1 by **+0.015** (0.918 to 0.933). Detail in [`ml/results/RESULTS_c1_hep.md`](ml/results/RESULTS_c1_hep.md).
- Stage-2 LLM triage is advisory only and never overrides a Stage-1 detection. At the benchmarked `qwen2.5:3b` (chosen for CPU-bound latency; the shipped default is `7b-instruct`), it adds no measured false-positive reduction over a simple `attack_score >= 0.6` threshold, and the syntactic prompt-injection guardrail is bypassed by 43% of the adversarial corpus. Both are reported as measured, not tuned away.

<img width="1290" height="1087" alt="defend_evidence" src="docs/media/defend_evidence.png" />

End-to-end defend evidence from the campus VM. Top: the Grafana attack-evidence board joins ground truth to detections, with 19.4 million Suricata alerts from 484 unique attacker addresses, 359 attack_labels rows, the top firing signatures, and a MITRE technique pivot. Bottom: live ban_audit rows recording each enforcement decision with source address, action, and timestamps.

<img width="1290" height="745" alt="live_threats" src="docs/media/live_threats.png" />

Evidence from the exposed SIP edge. Top: the live Kamailio log shows a REGISTER carrying a SQL-injection payload in its SIP URI, and banned sources being dropped at ingress. Middle: sip_events rows show spoofed FreePBX and Polycom user agents and the SIPVicious friendly-scanner, one dialing a premium number. Bottom: Suricata flags the toll-fraud INVITE and ban_audit records the bans, two of them triggered by the Stage-1 ML verdict.

## Quick start

Requires Docker (Engine 26+) with about 18 GiB available to the VM. On macOS, Colima is the tested runtime.

```bash
git clone <this-repository>
cd sip-attack-detect-defend
cp .env.example .env

make up-all                   # base, IDS, Keycloak, Wazuh, Homer, observability
make ml-up && make ml-pull    # ML ring plus the models (about 4.7 GB)
make soar-up                  # Shuffle SOAR and the ban relay
make bootstrap                # one idempotent pass: indexer OIDC, log collectors, SSO clients, SOAR provisioning
make e2e                      # drive labeled attack traffic and assert every ring produced evidence
```

`make bootstrap` and `make e2e` are safe to re-run. Host ports bind to loopback (`127.0.0.1`) via `DEV_BIND_IP`. Use `localhost` in the browser so OIDC state cookies survive the Keycloak redirect.

## Access

`ngn-sip.lab` is a private placeholder TLD resolved through local hosts entries, not a registered domain. Caddy fronts each web UI on its own `*.ngn-sip.lab` hostname with a `tls internal` certificate; reach them through an SSH tunnel to the Caddy port and map the hostnames to `127.0.0.1`. Keycloak is not proxied. Setup and OIDC callback steps are in [`docs/13_https_reverse_proxy.md`](docs/13_https_reverse_proxy.md).

| Service | Direct loopback | Auth | Login |
|---|---|---|---|
| Dashboard | http://127.0.0.1:3002 | Keycloak OIDC (open in loopback dev) | `lab-admin`, set at first login |
| Grafana | http://127.0.0.1:3000 | Local or Keycloak OIDC | `admin` / `${GRAFANA_ADMIN_PASSWORD}`, or Keycloak `lab-admin` |
| Wazuh Dashboard | https://127.0.0.1:5601 | Keycloak OIDC only | `lab-admin`, set at first login |
| Shuffle | http://127.0.0.1:3001 | Local (first-run wizard) | set during setup |
| Prometheus | http://127.0.0.1:9090 | None (loopback only) | n/a |
| ClickHouse HTTP | http://127.0.0.1:8123 | Basic auth | `ngn` / `change-me-local-only` |
| Keycloak admin | http://127.0.0.1:8080 | Local (`master` realm) | `admin` / `${KEYCLOAK_ADMIN_PASSWORD}` |

Passwords shown are local lab defaults. Rotate them and set `KC_HOSTNAME_STRICT` before any non-loopback exposure.

## Components

| Service | Role | How to use it |
|---|---|---|
| Kamailio (5060/udp) | SIP proxy. Routes REGISTER/INVITE/BYE, runs the NGN-SEC xlog filter, owns the `ban_table` htable used by active response. | `docker exec ngn-sip-kamailio-1 kamcmd htable.dump ban_table`. Driven by `make smoke`. |
| Asterisk | PBX. Terminates SIPp UAs and emits `chan_pjsip` auth-failed events the Wazuh decoder reads. | `docker compose logs asterisk`. |
| rtpengine | RTP relay (userspace on Mac, kernel-mode on the VM). | `docker exec ngn-sip-rtpengine-1 rtpengine-ctl list sessions`. |
| PostgreSQL + pgvector | Subscriber database and vector store for Stage-2 RAG context. | PSQL to `127.0.0.1:5432`. |
| ClickHouse (8123) | OLAP store for `sip_events`, `attack_labels`, `suricata_alerts`, `wazuh_alerts`, `ml_scores`, `llm_verdicts`, `ban_audit`, `soar_cases`. | `curl -u ngn:change-me-local-only "http://localhost:8123/?query=SELECT count() FROM ngn_sip.suricata_alerts"`. |
| Vector | Log shipper. Tails Asterisk, Suricata `eve.json`, Wazuh alerts, and HEP rows into ClickHouse with disk-backed buffers and Prometheus-visible drop counters. | Metrics at http://localhost:9598/metrics. |
| Suricata | Signature IDS on the SIP bridge, sharing Kamailio's network namespace. | Generate traffic, then read `suricata_alerts` in ClickHouse. |
| Wazuh manager / indexer / dashboard | SIEM. Loads the project decoders plus the SIP correlation rules (100100-100134) and the ML rules (100150/100151), and drives active response. | `docker exec -i ngn-sip-wazuh-manager-1 /var/ossec/bin/wazuh-logtest`. |
| Keycloak (8080) | Identity provider. `master` realm for admin, `ngn-sip-lab` realm for the OIDC clients (wazuh-dashboard, grafana, shuffle, homer, dashboard). | Admin console at http://localhost:8080/admin. |
| Shuffle (3001) | SOAR. Receives the Wazuh webhook on `rule_level >= 10`, enriches from ClickHouse (`ml_scores`, `llm_verdicts`, `suricata_alerts`), applies a graded policy, bans through the kamcmd-relay only when corroborated, and records `ngn_sip.soar_cases`. | `make soar-up && make shuffle-provision`. |
| Ollama | Stage-2 LLM triage worker. Reads Stage-1 detections, classifies with `qwen2.5:7b-instruct` (the deployed default, pulled by `make ml-pull`), and writes advisory verdicts. The paper's Stage-2 benchmark used the smaller `qwen2.5:3b` for CPU-bound latency. | `make ml-up && make ml-pull`. Worker in `ml/stage2/`. |
| Homer + heplify | HEP capture of full SIP request and response detail for the C1 response-level features. | `make homer-up`. See [`docs/C1_HEP_RESPONSE_FEATURES.md`](docs/C1_HEP_RESPONSE_FEATURES.md). |
| Grafana (3000) | Seven provisioned dashboards (D1-D7) over ClickHouse and Prometheus. | Sign in with Keycloak, then open D1-D7. |
| Prometheus (9090) | Metrics for Kamailio, Asterisk, rtpengine, ClickHouse, Vector, and the Wazuh indexer JVM. | Query `up` at http://localhost:9090. |

### Grafana dashboards

Auto-provisioned from `observability/grafana/provisioning/dashboards/`.

| Dashboard | Shows |
|---|---|
| D1 SIP Overview | REGISTER/INVITE/BYE rates, top source IPs, response-code distribution, failed-auth ratio. |
| D2 Attack Timeline | Suricata alerts, ground-truth labels, and Wazuh alerts on one timeline. |
| D3 Suricata Detection | Alerts per signature, top source IPs, severity distribution. |
| D4 Attack Evidence | 24-hour rollup of ground truth versus Suricata hits and recent `attack_labels`. |
| D5 System Health | Prometheus `up` per target, ClickHouse query rate, table row counts. |
| D6 MITRE Coverage | Suricata signatures versus ground truth by MITRE technique and phase. |
| D7 Wazuh SIP Correlation | SIP rules 100100-100134 and ML rules 100150/100151 alert feed, rule table, ban triggers. |

A panel that reads "No data" means the underlying ClickHouse table is empty. Drive attack traffic, then it populates.

## Continuous integration

CI is a hard gate: a broken commit fails the pipeline, with no `allow_failure` on the quality jobs. GitHub Actions (`.github/workflows/`) runs and blocks on shell/YAML/Dockerfile lint, `docker compose config` for every Compose file, a Kamailio config check, the `ml/tests` suite, and an observability smoke test. Container builds run a Trivy CRITICAL/HIGH gate, and a Gitleaks secret scan blocks separately.

## Repository layout

```text
.
├── attacks/                    # Attack scripts by phase (01_recon ... 06_tollfraud)
├── caddy/                      # Caddy HTTPS reverse-proxy config
├── dashboard/                  # Next.js stack dashboard
├── docs/                       # Architecture, threat model, runbooks, results, provenance
├── identity/keycloak/          # Keycloak realm and OIDC client configuration
├── ids/suricata/               # Suricata rules and config
├── infra/                      # Per-service Dockerfiles and runtime config
│   ├── clickhouse/             #   ClickHouse: DDL and init for the evidence store
│   ├── kamailio/ asterisk/ …   #   SIP core services
│   └── postgres/               #   Subscriber DB + pgvector
├── observability/              # Metrics and log pipeline
│   ├── vector/                 #   Vector: log/alert shipper into ClickHouse
│   ├── grafana/                #   Provisioned dashboards D1-D7
│   └── prometheus/ hep-bridge/ #   Metrics scrape + HEP bridge
├── ml/                         # Stage 1, Stage 2, eval harness, C1 experiment, tests
├── scripts/                    # Bootstrap, provisioning, and E2E verification helpers
├── siem/wazuh/                 # Wazuh decoders, rules, integrations, active response
├── soar/                       # Shuffle workflow and the kamcmd ban relay
├── docker-compose*.yml         # Compose files split by ring and optional service
└── Makefile                    # up-all, bootstrap, e2e, and per-tier targets
```

ClickHouse configuration lives at `infra/clickhouse/` and Vector at
`observability/vector/`; both run as Compose services (see the `Components`
table above for how to query them live).

## Deployment

Docker Compose is the verified path; the other targets are scaffolding at varying
maturity, each labeled with its real status:

| Path | Where | Status |
|---|---|---|
| Docker Compose + Makefile | `docker-compose*.yml`, `Makefile` | **Verified** end-to-end on a fresh machine (`make up-all` / `make e2e`). |
| Kubernetes (Helm) | `helm/ngn-sip/` | **Design-verified**: lint-clean and `kubeconform -strict`-validated, with deployable-now vs design-only tiers annotated. Not stood up end-to-end. See [`docs/05_kubernetes_migration.md`](docs/05_kubernetes_migration.md). |
| VM provisioning (OpenTofu) | `terraform/proxmox/` | **Skeleton**: resource model and roadmap for a Proxmox reference network. Syntax-checked only; not applied to a live cluster. |
| VM configuration (Ansible) | `ansible/` | **Skeleton**: playbook structure and baseline hardening tasks. `--check`/syntax-checked only; no real secrets or complete service config. |

Use Compose to run the stack. The Helm chart and the VM skeletons document how the
same architecture maps to a cluster and to bare VMs; treat them as design intent,
not turnkey deployments.

## Known limitations

Reported honestly, not defects (the Stage-2 caveats are detailed under [Results](#results)):

- The injection and toll-fraud classes have too few labeled groups for a stable per-class F1.
- Wazuh rule 100151 (Stage-1 high-confidence ML verdict) is enabled for SOC-visible level-10 alerting. Destructive active response is intentionally gated on the external-only `kamailio-autoban` path rather than wired natively to this rule; see the rule header in [`siem/wazuh/rules/ml_rules.xml`](siem/wazuh/rules/ml_rules.xml) for the per-class rationale.

## Documentation

- Threat model (STRIDE and DFD): [`docs/02_threat_model.md`](docs/02_threat_model.md)
- Evaluation methodology (leakage-free source-IP-grouped protocol): [`docs/06_evaluation_methodology.md`](docs/06_evaluation_methodology.md)
- Internet-exposure hardening checklist: [`docs/INTERNET_EXPOSURE.md`](docs/INTERNET_EXPOSURE.md)
- Data provenance and released artifacts: [`docs/DATA_PROVENANCE.md`](docs/DATA_PROVENANCE.md)
- SSO architecture and OAuth hardening: [`docs/sso/keycloak_architecture.md`](docs/sso/keycloak_architecture.md), [`docs/security/oauth_hardening_checklist.md`](docs/security/oauth_hardening_checklist.md)
- SOAR runbook: [`docs/09_soar_runbook.md`](docs/09_soar_runbook.md)

## Ethics

This project is restricted to authorized lab infrastructure, synthetic identities, and synthetic attack traffic. No production systems, third-party networks, or unauthorized targets are in scope. See [`docs/ethics_authorisation.md`](docs/ethics_authorisation.md).

## License

MIT License (see [LICENSE](LICENSE)).
