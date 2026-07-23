# ClickHouse

OLAP evidence store for the NGN SIP detect-defend pipeline. HTTP API on loopback port 8123; native protocol internal to the `sip_lab` Docker network.

## Init scripts

Ordered DDL under `init/` (mounted into the container entrypoint):

| File | Purpose |
|---|---|
| `01_events_schema.sql` | Core `ngn_sip` database: `sip_events`, `attack_labels`, `sip_features_5min` |
| `02_materialized_views.sql` | `mv_sip_features_5min` 5-minute per-`src_ip` aggregation |
| `03_audit_schema.sql` | Audit and compliance tables |
| `03_hep_unified_view.sql` | `sip_events_by_source`, `sip_response_codes` for HEP/Suricata discrimination |
| `04_scoring_aggregations.sql` | ML scoring rollups |
| `05_compliance_audit.sql` | Compliance audit schema |
| `06_suricata_alerts.sql` | `suricata_alerts` + 5-min rollup MV |
| `07_wazuh_alerts.sql` | `wazuh_alerts` for Grafana D7 and C3 correlation arm |

Downstream tables populated by application services: `ml_scores`, `llm_verdicts`, `ban_audit`, `soar_cases`.

## Usage

Query via HTTP (see root `README.md` login table) or from containers on `sip_lab`:

```bash
docker exec ngn-sip-clickhouse-1 clickhouse-client --user ngn -q "SELECT count() FROM ngn_sip.sip_events"
```

Vector tails Suricata EVE, Wazuh alerts, and hep-bridge ndjson into these tables (`observability/vector/vector.yaml`).
