# Observability

Metrics, logs, and the evidence store for the SIP lab. Runs from
[`../docker-compose.observability.yml`](../docker-compose.observability.yml) on
the shared `ngn-sip_sip_lab` bridge; host ports stay loopback-only via
`DEV_BIND_IP`.

```mermaid
flowchart LR
    subgraph SRC["Log sources"]
        SU["Suricata eve.json"]
        AS["Asterisk logs"]
        WZ["Wazuh alerts.json"]
        HP["HEP / hep-bridge"]
    end
    V["Vector<br/>tail · transform · route"]
    CH[("ClickHouse<br/>sip_events · *_alerts · ml_scores · llm_verdicts · ban_audit")]
    subgraph METRICS["Metrics"]
        KM["Kamailio · Asterisk · rtpengine"]
        PR["Prometheus"]
    end
    G["Grafana<br/>dashboards D1-D7"]

    SU --> V
    AS --> V
    WZ --> V
    HP --> V
    V --> CH
    CH --> G
    KM --> PR --> G
```

## Services

- **[`vector/`](vector/)** — tails Suricata `eve.json`, Asterisk logs, Wazuh alerts, and HEP rows, normalizes them, and writes to ClickHouse.
- **`clickhouse`** ([`../infra/clickhouse/`](../infra/clickhouse/)) — the OLAP evidence store for raw logs, SIP events, ML feature windows, and verdicts.
- **[`grafana/`](grafana/)** — provisioned ClickHouse + Prometheus datasources and the D1-D7 dashboards.
- **[`prometheus/`](prometheus/)** — scrapes Kamailio, Asterisk, rtpengine, and itself.

## Run

```sh
make obs-up
make obs-smoke
```

Endpoints (loopback): ClickHouse `http://127.0.0.1:8123`, Grafana
`http://127.0.0.1:3000`, Prometheus `http://127.0.0.1:9090`.
