# Grafana Provisioning

Grafana provisioning files are mounted read-only into `/etc/grafana/provisioning`.

Current scope:

- `datasources/clickhouse.yml`
- `datasources/prometheus.yml`
- `dashboards/dashboards.yml`
- `dashboards/*.json` — the seven provisioned dashboards, D1 through D7 (described in [`docs/SERVICES.md`](../../../docs/SERVICES.md))
