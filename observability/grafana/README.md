# Grafana

Grafana runs from `docker-compose.observability.yml` and binds to `127.0.0.1:3000` by default.

Provisioned assets:

- ClickHouse datasource UID: `clickhouse`
- Prometheus datasource UID: `prometheus`
- Dashboard provisioning: `observability/grafana/provisioning/dashboards/dashboards.yml`
- Dashboard JSON directory: `observability/grafana/provisioning/dashboards/`

The ClickHouse datasource backs the analytics dashboards (SIP events, Suricata/Wazuh alerts, ML and LLM verdicts). The Prometheus datasource backs the Kamailio, Asterisk, rtpengine, and service-health metrics. The dashboards themselves (D1-D7) are listed in [`docs/SERVICES.md`](../../docs/SERVICES.md).
