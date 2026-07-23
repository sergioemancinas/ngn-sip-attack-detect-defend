# Services and access

## Access

`ngn-sip.lab` is a private placeholder TLD resolved through local hosts entries, not a registered domain. Caddy fronts each web UI on its own `*.ngn-sip.lab` hostname with a `tls internal` certificate; reach them through an SSH tunnel to the Caddy port and map the hostnames to `127.0.0.1`. Keycloak is not proxied. Setup and OIDC callback steps are in [`13_https_reverse_proxy.md`](13_https_reverse_proxy.md).

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
| Homer + heplify | HEP capture of full SIP request and response detail for the C1 response-level features. | `make homer-up`. See [`C1_HEP_RESPONSE_FEATURES.md`](C1_HEP_RESPONSE_FEATURES.md). |
| Grafana (3000) | Seven provisioned dashboards (D1-D7) over ClickHouse and Prometheus. | Sign in with Keycloak, then open D1-D7. |
| Prometheus (9090) | Metrics for Kamailio, Asterisk, rtpengine, ClickHouse, Vector, and the Wazuh indexer JVM. | Query `up` at http://localhost:9090. |

## Grafana dashboards

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
