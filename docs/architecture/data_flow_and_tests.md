# Data flow + how tests work end-to-end

Walks one attack from script to dashboard, naming every component and the file where the wiring lives. Cross-references public docs/RFCs so each layer can be defended at viva.

## End-to-end picture (one attack)

```
attacks/01_recon/sippts_options_scan.sh
        │  (1) Python label emitter
        ▼
attacks/orchestrator/label_emitter.py  ──INSERT──►  ClickHouse ngn_sip.attack_labels
                                                            ▲
                                                            │  (Vector ch_raw_logs sink)
                                                            │
        │  (2) generates SIP OPTIONS traffic
        ▼
Suricata container on sip_lab bridge
        │  reads packets via AF_PACKET on eth0
        │  evaluates ids/suricata/rules/sip.rules
        │  writes /var/log/suricata/eve.json
        ▼
Vector observability/vector.yaml  ──ch_suricata_alerts sink──►  ClickHouse ngn_sip.suricata_alerts
        │
        │  (3) Kamailio xlog writes NGN-SEC events
        ▼
Wazuh manager
  /var/ossec/etc/decoders/kamailio.xml  → decode the message
  /var/ossec/etc/rules/sip_rules.xml    → match rule (SID 100100-100199)
  writes /var/ossec/logs/alerts/alerts.json
        │
        │  (4) Vector wazuh_alerts file source
        ▼
ClickHouse ngn_sip.wazuh_alerts
        │
        │  (5) Wazuh active-response (kamcmd htable.sets ban_table <ip> 1) + integration block (level >= 10)
        ▼
Kamailio ban  +  Shuffle webhook  http://shuffle-backend:5001/api/v1/hooks/wazuh-sip-orchestration
        │
        │  (6) Shuffle workflow in soar/shuffle/ (normalize, dedupe, enrich, audit)
        ▼
ClickHouse audit_log / compliance_evidence  (Shuffle records; it does not block)
        │
        │  (7) Grafana queries ClickHouse via the grafana-clickhouse-datasource
        ▼
Grafana dashboards D1-D7 (observability/grafana/provisioning/dashboards/)
```

Every arrow above is exercised once by `make smoke` + the recon attack.

## Layer-by-layer with the source file + reference

### Layer 1: SIP core

| File | What it does | Reference |
|---|---|---|
| `docker-compose.yml` | Brings up Kamailio, Asterisk, rtpengine, Postgres+pgvector on `sip_lab` bridge | [Docker Compose v2 spec](https://compose-spec.io/) |
| `infra/kamailio/modules/ban.cfg` | Reads `$sht(ban_table=>$si)` on REGISTER and INVITE to drop banned sources | [Kamailio htable docs](https://kamailio.org/docs/modules/stable/modules/htable.html) |
| `infra/kamailio/modules/htable.cfg` | Defines `ban_table=>size=8;autoexpire=3600` | same |
| `attacks/orchestrator/label_emitter.py` | Inserts ground-truth row into `ngn_sip.attack_labels` via ClickHouse HTTP | [ClickHouse HTTP interface](https://clickhouse.com/docs/en/interfaces/http) |
| `attacks/01_recon/sippts_options_scan.sh` | Emits a label; real `sippts` packet path still stubbed (NGN-T1.5 follow-up) | sippts: https://github.com/Pepelux/sippts |

### Layer 2: Suricata IDS

| File | What it does | Reference |
|---|---|---|
| `docker-compose.ids.yml` | Runs `jasonish/suricata:7.0.10` on `sip_lab` bridge, `eth0` interface | [Suricata user guide](https://docs.suricata.io/en/latest/) |
| `ids/suricata/etc/suricata.yaml` | EVE JSON logging, sip parser enabled | [SIP keyword set](https://docs.suricata.io/en/latest/rules/sip-keywords.html) |
| `ids/suricata/rules/sip.rules` | 14 SIDs (1000001–1000014): scanner UA, OPTIONS burst, malformed Via/CSeq, protocol classifier | MITRE technique IDs in rule `metadata:` |

### Layer 3: Vector pipeline

| File | What it does | Reference |
|---|---|---|
| `observability/vector/vector.yaml` | `suricata_eve` file source → `parse_suricata_alerts` remap → `ch_suricata_alerts` sink. Same triple for `asterisk_full` and `wazuh_alerts`. | [Vector docs](https://vector.dev/docs/) |
| `infra/clickhouse/init/06_suricata_alerts.sql` | DDL for `suricata_alerts` table; `TTL toDateTime(event_time) + INTERVAL 30 DAY` | [ClickHouse TTL](https://clickhouse.com/docs/en/engines/table-engines/mergetree-family/mergetree#table_engine-mergetree-ttl) |
| `infra/clickhouse/init/07_wazuh_alerts.sql` | DDL for `wazuh_alerts` table | same |

### Layer 4: Wazuh SIEM

| File | What it does | Reference |
|---|---|---|
| `siem/wazuh/decoders/kamailio.xml` | `<prematch>NGN-SEC</prematch>` + pcre2 regex extract `srcip,user_agent,reason`. Must live at `/var/ossec/etc/decoders/` (not only `local/`). | [Wazuh decoders](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/index.html) |
| `siem/wazuh/rules/sip_rules.xml` | 25+ SIDs 100100–100199, MITRE-tagged (T1110/T1499/T1595.001 etc.) | [Wazuh rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/index.html) |
| `siem/wazuh/integrations/wazuh_shuffle_integration.xml` | `<integration><name>shuffle</name><hook_url>...</hook_url><level>10</level><rule_id>100102,100103,100105,100108</rule_id></integration>` | [Wazuh integrator](https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html) |
| `siem/wazuh/active-response/kamcmd_block.sh` | Wazuh AR script: `kamcmd htable.sets ban_table <ip> 1` either via local `kamcmd` or `docker exec` | [Wazuh active response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html) |

### Layer 5: SOAR / audit

| File | What it does | Reference |
|---|---|---|
| `soar/shuffle/workflows/sip_response_orchestration.json` | Stage 3 workflow: webhook → normalize → dedupe → enrich from ClickHouse → graded response → write case/audit rows to ClickHouse. Orchestration and audit; `kamailio-autoban` remains the deterministic blocking backstop. | [Shuffle docs](https://shuffler.io/docs/) |

TheHive/Cortex were removed because TheHive is no longer open source; the `soar/thehive/`, `soar/cortex/`, and `docker-compose.thehive.yml` files were deleted.

### Layer 6: Identity (Keycloak SSO)

| File | What it does | Reference |
|---|---|---|
| `docker-compose.keycloak.yml` | Keycloak 26 with `KC_HOSTNAME=http://localhost:8080`, `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true` | [Keycloak hostname guide](https://www.keycloak.org/server/hostname) |
| `identity/keycloak/realm-export.json` | Realm `ngn-sip-lab` + clients (`wazuh-dashboard`, `grafana`, `shuffle`, `homer`) | [Keycloak realm import](https://www.keycloak.org/server/importExport) |
| `siem/wazuh/config/opensearch_dashboards.yml` | OIDC config for the dashboard | [OpenSearch Security OIDC](https://opensearch.org/docs/latest/security/authentication-backends/openid-connect/) |
| `siem/wazuh/indexer-security/{config,roles_mapping}.yml` | Indexer-side OIDC `auth_domain` + role mapping (lab-admin → 14 admin OS roles) | same |
| `docs/sso/keycloak_architecture.md` | Front/back-channel URL split rationale, 6-client matrix | RFC 8414 OIDC discovery |
| `docs/security/oauth_hardening_checklist.md` | 10-table gap list vs RFC 6749 / 7636 / 8705 / 9449 | listed in the doc |

### Layer 7: Observability + dashboards

| File | What it does | Reference |
|---|---|---|
| `observability/grafana/provisioning/datasources/clickhouse.yml` | Provisions the ClickHouse datasource (uid `clickhouse`) | [Grafana provisioning](https://grafana.com/docs/grafana/latest/administration/provisioning/) |
| `observability/grafana/provisioning/datasources/prometheus.yml` | Provisions Prometheus (uid `prometheus`) | same |
| `observability/grafana/provisioning/dashboards/D{1..7}_*.json` | D1 SIP overview, D2 attack timeline, D3 Suricata detection, D4 attack evidence, D5 system health, D6 MITRE coverage, D7 Wazuh SIP correlation. All use `$__timeFilter()` macro. | [Grafana ClickHouse datasource](https://grafana.com/grafana/plugins/grafana-clickhouse-datasource/) |
| `observability/prometheus/prometheus.yml` | Scrape targets: kamailio:8089 (xhttp_prom), asterisk:8088 (res_prometheus), rtpengine:9900 | [Prometheus config](https://prometheus.io/docs/prometheus/latest/configuration/configuration/) |

## How to run the tests

```bash
# 1. Bring up the rings.
make up && make obs-up && make ids-up && make wazuh-up

# 2. SIP baseline (proves Ring 1).
make smoke

# 3. Recon attack (proves Rings 2-4 detection chain).
set -a && . ./.env && set +a
TARGET_HOST=127.0.0.1 TARGET_PORT=5060 ./attacks/01_recon/sippts_options_scan.sh

# 4. Generate real SIP packets in Suricata's namespace (Mac Docker bridge limit workaround).
docker run --rm --network container:ngn-sip-suricata-1 alpine:3.20 sh -c '
  apk add --quiet python3 >/dev/null 2>&1
  python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);[s.sendto((\"OPTIONS sip:kamailio SIP/2.0\\r\\nVia: SIP/2.0/UDP x:5060;branch=b\"+str(i)+\"\\r\\nFrom: <sip:s@x>;tag=\"+str(i)+\"\\r\\nTo: <sip:kamailio>\\r\\nCall-ID: c-\"+str(i)+\"\\r\\nCSeq: 1 OPTIONS\\r\\nUser-Agent: sippts\\r\\nContent-Length: 0\\r\\n\\r\\n\").encode(),(\"kamailio\",5060)) for i in range(25)]"'

# 5. Verify ClickHouse rows landed.
curl -sS -u ngn:change-me-local-only "http://localhost:8123/?database=ngn_sip" \
  -d "SELECT sig_id, signature, count() FROM suricata_alerts GROUP BY sig_id, signature ORDER BY count() DESC"

# 6. Wazuh rule fires on the canonical fixture.
printf 'May 13 10:00:00 lab kamailio[123]: INFO: NGN-SEC REGISTER src=198.51.100.10 ua="sippts" reason="options scan"\n' \
  | docker exec -i ngn-sip-wazuh-manager-1 /var/ossec/bin/wazuh-logtest

# 7. Kamailio htable ban_table round-trip (active-response state object).
docker compose exec kamailio kamcmd htable.sets ban_table 198.51.100.10 1
docker compose exec kamailio kamcmd htable.dump  ban_table
docker compose exec kamailio kamcmd htable.delete ban_table 198.51.100.10
```

## Public references (standards + protocols)

- **SIP**: RFC 3261 (core), RFC 3262 (PRACK), RFC 3264 (offer/answer), RFC 3550 (RTP), RFC 3711 (SRTP), RFC 8224/8225 (STIR/SHAKEN).
- **OAuth 2.0**: RFC 6749 (framework), RFC 7636 (PKCE), RFC 8705 (mTLS-bound), RFC 9449 (DPoP), `draft-ietf-oauth-security-topics`.
- **OIDC**: OpenID Connect Core 1.0, OIDC Discovery 1.0.
- **MITRE ATT&CK**: T1110 brute force, T1499 endpoint denial of service, T1595.001 IP-block scanning, T1565 stored-data manipulation, T1190 exploit public-facing application, T1046 network service discovery.
- **Wazuh**: Wazuh Documentation 4.x, covering decoders, rules, active response, integrations.
- **Keycloak**: Keycloak 26 Server Administration Guide.
- **OpenSearch Security**: OpenSearch 2.x security plugin docs.
- **Suricata**: Suricata 7.0 user guide + SIP keyword set.
- **Vector**: Vector 0.41 transforms + ClickHouse sink docs.
- **ClickHouse**: ClickHouse 24.x, covering MergeTree TTL, materialized views, HTTP interface.

Related design docs: `docs/01_architecture.md`, `docs/02_threat_model.md`, `docs/03_attack_playbook.md`, `docs/04_detection_rules.md`, `docs/sso/keycloak_architecture.md`, `docs/security/oauth_hardening_checklist.md`.
