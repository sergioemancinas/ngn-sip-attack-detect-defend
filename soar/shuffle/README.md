# Shuffle SOAR

This folder contains the Shuffle SOAR deployment and the Stage 3 response orchestration workflow.

Bring up the stack (from repo root):

```bash
docker compose -f docker-compose.soar.yml up -d
```

Workflow:

- `soar/shuffle/workflows/sip_response_orchestration.json`

Required environment variables (set in your local `.env`):

| Variable | Purpose |
|---|---|
| `DEV_BIND_IP` | Host bind address for published SOAR ports (default `127.0.0.1`). |
| `SHUFFLE_DEFAULT_USERNAME` | Initial Shuffle admin username. |
| `SHUFFLE_DEFAULT_PASSWORD` | Initial Shuffle admin password. |
| `SHUFFLE_DEFAULT_APIKEY` | Initial API key placeholder for bootstrap. |
| `SHUFFLE_ENCRYPTION_MODIFIER` | Encryption salt/key modifier used by Shuffle. |
| `SHUFFLE_OPENSEARCH_USERNAME` | OpenSearch auth username placeholder for Shuffle config. |
| `SHUFFLE_OPENSEARCH_PASSWORD` | OpenSearch auth password placeholder for Shuffle config. |
| `AUTH_FOR_ORBORUS` | Orborus environment auth token/secret. |

Ports:

| Service | Bind | Notes |
|---|---|---|
| `shuffle-frontend` | `${DEV_BIND_IP:-127.0.0.1}:3001` | Shuffle UI |
| `shuffle-backend` | `${DEV_BIND_IP:-127.0.0.1}:5001` | API/webhook endpoint (`/api/v1/hooks/wazuh-sip-orchestration`) |
| `shuffle-opensearch` | internal only | No host bind in this scaffold |
| `shuffle-orborus` | internal only | Worker orchestrator only |

Hardening note: this compose intentionally keeps OpenSearch security disabled for loopback-only lab development. Before any non-loopback exposure, enforce TLS + OIDC, remove insecure defaults, and keep ports private behind controlled ingress.
