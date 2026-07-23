# Keycloak SSO architecture

Single Keycloak instance, two realms by design: `master` for Keycloak administration only, `ngn-sip-lab` for every application in the project. This is the standard Keycloak pattern; splitting users across multiple application realms is an anti-pattern unless you have multi-tenant isolation requirements, which this lab does not.

## Realm responsibilities

| Realm | Audience | Users | Clients | Purpose |
|---|---|---|---|---|
| `master` | Keycloak administrators only | `admin` (env `KEYCLOAK_ADMIN`) | `admin-cli`, `security-admin-console`, `master-realm`, … | Console + admin REST API. **No application uses this realm.** |
| `ngn-sip-lab` | Lab operators, examiner read-only accounts | `lab-admin` (role `wazuh-admin`, `all_access`) | All app clients listed below | OIDC SSO for every UI in the project. |

The `master` admin should never authenticate against an application. A break-glass `lab-admin` exists in `ngn-sip-lab` and is used for routine login.

## OIDC clients in `ngn-sip-lab`

| Client ID | Service | Front-channel redirect | Back-channel reachable | App-side wiring | State |
|---|---|---|---|---|---|
| `wazuh-dashboard` | Wazuh Dashboard | `https://localhost:5601/*` | `http://keycloak:8080` | `siem/wazuh/config/opensearch_dashboards.yml` + `siem/wazuh/indexer-security/config.yml` | live ✓ |
| `grafana` | Grafana | `http://localhost:3000/*` | `http://keycloak:8080` | `docker-compose.observability.yml` env `GF_AUTH_GENERIC_OAUTH_*` | live ✓ |
| `shuffle` | Shuffle | `http://localhost:3001/*` | `http://keycloak:8080` | Shuffle admin UI → SSO → enable OpenID with discovery URL `http://keycloak:8080/realms/ngn-sip-lab/.well-known/openid-configuration` | client created; admin UI step pending |
| `homer` | Homer 7 | `http://localhost:9080/*` | `http://keycloak:8080` | `infra/homer/webapp/settings.js` `oauth.{config_url,client_id}` | client created; app config pending |

All clients use `client-secret` auth with secret `change-me-local-only`. Rotate per `siem/wazuh/indexer-security/README.md`.

## Why the front/back URL split matters

Keycloak 26 in dev mode is configured with:

```yaml
KC_HOSTNAME: "http://localhost:8080"
KC_HOSTNAME_STRICT: "false"
KC_HOSTNAME_BACKCHANNEL_DYNAMIC: "true"
```

Effect on OIDC metadata returned to clients:
- The **browser** sees `http://localhost:8080/...` for the `authorization_endpoint` (it is the host port mapping), so the redirect to log in works without `/etc/hosts` tricks.
- The **app server** (Wazuh dashboard, Grafana, Shuffle) sees `http://keycloak:8080/...` for the `token_endpoint` because it fetched metadata across the Docker bridge and `BACKCHANNEL_DYNAMIC=true` keeps backchannel URLs aligned with the request Host header.

Every app's config below MUST use the matching pair:
- `authorization_url` / `auth_url` → `http://localhost:8080`
- `token_url` / `userinfo_url` → `http://keycloak:8080`

Mixing them breaks the flow (browser cannot reach `keycloak:8080`, server inside the container cannot reach `localhost:8080`).

## Role mapping

The realm's `wazuh-client-roles` protocol mapper flattens client-role assignments into a top-level `roles` claim. To grant a user full access to an app:

1. In `master` realm console → Manage → Realms → `ngn-sip-lab`.
2. Users → `lab-admin` → Role mapping → Assign role → choose the client (`grafana`, `shuffle`, etc.) → assign a role named `all_access`.
3. The next OIDC token for that user will carry `roles: ["all_access"]`.

App-side mapping then translates `all_access` to the application's own admin role (e.g. Wazuh indexer's `roles_mapping.yml` adds `all_access` to the OpenSearch `all_access` role).

## Restart sequence after editing this stack

```bash
docker restart ngn-sip-keycloak-keycloak-1
docker compose -f docker-compose.observability.yml up -d grafana
docker restart ngn-sip-wazuh-dashboard-1
# Shuffle / Homer: complete app-side wiring first.
```

## Hardening before public exposure (campus VM)

1. Rotate all client secrets; store in sealed-secrets, not in this file.
2. Replace `http://localhost:8080` with an FQDN behind TLS (step-CA cert).
3. Set `KC_HOSTNAME_STRICT=true` and remove the dev-mode `start-dev` flag in Keycloak compose.
4. Disable the local-auth fallback on each app once SSO is verified end-to-end.
5. Add the `examiner` read-only user with role mapping limited to dashboard `read` actions across all apps.
