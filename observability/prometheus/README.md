# Prometheus

Prometheus scrape configuration for the SIP lab lives in `prometheus.yml`.

Active scrape jobs:

- `prometheus` on `localhost:9090`
- `kamailio` on `kamailio:8089/metrics` through `xhttp_prom`
- `asterisk` on `asterisk:8088/metrics` through Asterisk `res_prometheus`
- `rtpengine` on `rtpengine:9900/metrics` through rtpengine's HTTP listener
