# Infrastructure

Build contexts and runtime configuration for the SIP core and its supporting
services. Each directory is a Compose service, wired together by the top-level
`docker-compose*.yml` files.

## Contents

| Directory | Service | Notes |
|---|---|---|
| [`kamailio/`](kamailio/README.md) | SIP edge proxy | Routing, the NGN-SEC xlog filter, and the `ban_table` used by active response |
| [`asterisk/`](asterisk/README.md) | PBX | PJSIP digest authentication and dial plan behind the edge |
| [`rtpengine/`](rtpengine/README.md) | RTP media relay | Userspace on macOS, kernel mode on the VM |
| [`postgres/`](postgres/README.md) | PostgreSQL 16 + pgvector | Subscribers and Stage-2 RAG context |
| [`clickhouse/`](clickhouse/README.md) | ClickHouse | OLAP evidence store for all detection and response tables |
| [`homer/`](homer/README.md) | Homer / HEP | heplify + web app, for response-level SIP features |
| [`sipp/`](sipp/README.md) | SIPp | Load generator: registration and call scenarios for smoke tests |
| [`keycloak/`](keycloak/README.md) | Keycloak | Build context for SSO |
| `tls/`, `stepca/` | TLS material | CA scaffolding for the VM (the local stack uses Caddy's internal CA) |

The SIP core (Kamailio, Asterisk, rtpengine, Postgres) starts with `make up`; the
rest come up through their per-tier `make` targets. See the top-level
[`README`](../README.md) for the full bring-up.
