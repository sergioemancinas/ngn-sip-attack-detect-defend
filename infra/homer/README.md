# Homer

HEP capture stack for C1 response-level SIP telemetry. Brought up via `docker-compose.homer.yml` on the `sip_lab` network.

## Components

| Path / service | Role |
|---|---|
| `heplify-server.toml` | HEPv3 listener config (UDP 9060) |
| `postgres-init/` | Homer 7 `hep_proto_1_*` schema seed |
| `heplify-server` container | Receives Kamailio `siptrace` duplicates |
| `homer-postgres` | Stores captured SIP request/reply rows |
| `observability/hep-bridge/bridge.py` | Polls Postgres, normalizes reply client IP, emits ndjson for Vector |

Kamailio HEP capture is enabled by default (`#!define HEP_CAPTURE_ENABLE` in `infra/kamailio/kamailio.cfg`; module in `infra/kamailio/modules/siptrace.cfg`).

## Data path

```
Kamailio siptrace -> heplify-server -> homer-postgres -> hep-bridge -> Vector -> ngn_sip.sip_events (source=hep)
```

Full protocol and experiment steps: `docs/C1_HEP_RESPONSE_FEATURES.md`.
