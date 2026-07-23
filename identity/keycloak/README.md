# Keycloak OIDC for Wazuh dashboard (local lab)

This directory contains the local Keycloak realm export used by the Wazuh 4.14.5 dashboard OIDC integration.

## Files

- `realm-export.json`: `ngn-sip-lab` realm, `wazuh-dashboard` confidential client, initial `lab-admin` user.
- `themes/`: placeholder for optional Keycloak branding themes.

## Local bootstrap (fresh clone)

1. Ensure `.env` contains (or inherits defaults from `.env.example`):
   - `DEV_BIND_IP=127.0.0.1`
   - `KEYCLOAK_ADMIN`
   - `KEYCLOAK_ADMIN_PASSWORD`
   - `KEYCLOAK_REALM=ngn-sip-lab`
   - `KEYCLOAK_WAZUH_CLIENT_ID=wazuh-dashboard`
   - `KEYCLOAK_WAZUH_CLIENT_SECRET` (must match client secret in the imported realm)
2. Start Keycloak:
   ```bash
   make keycloak-up
   ```
3. Wait until healthy:
   ```bash
   docker compose -f docker-compose.keycloak.yml ps
   ```
4. Open admin console:
   - `http://127.0.0.1:8080/admin`
   - Log in with `KEYCLOAK_ADMIN` and `KEYCLOAK_ADMIN_PASSWORD`.
5. Confirm imported realm:
   - Realm: `ngn-sip-lab`
   - User: `lab-admin` (temporary password, reset required on first login)
   - Client: `wazuh-dashboard`

## Realm defaults imported

- Access token lifespan: 5 minutes.
- SSO session idle/max: 30 minutes.
- Realm role: `wazuh-admin`.
- `wazuh-admin` is composite and grants client role `all_access` on `wazuh-dashboard` (used by OpenSearch backend role mapping).

## Secret rotation after first start

1. In Keycloak admin, rotate `wazuh-dashboard` client secret.
2. Update `.env` value `KEYCLOAK_WAZUH_CLIENT_SECRET`.
3. Persist updated realm export if you need deterministic fresh-clone bootstrap:
   - Export realm and replace `identity/keycloak/realm-export.json`.

## Production-mode upgrade path (campus VM)

`start-dev` is for local lab only. For production-like deployment:

1. Run Keycloak in `start` mode.
2. Back Keycloak with PostgreSQL (external DB, no embedded dev DB).
3. Serve HTTPS with trusted certificates (step-CA chain), and expose only through hardened ingress/reverse proxy.
4. Disable default credentials and enforce rotated secrets + least-privilege roles.
