# Keycloak OIDC integration for Wazuh dashboard

This document captures the local-lab OIDC design that switches Wazuh dashboard login to Keycloak while preserving internal-user fallback.

## Architecture and auth flow

```mermaid
flowchart LR
    U[Browser user] -->|HTTPS :5601| WD[Wazuh Dashboard]
    WD -->|OIDC authorize| KC[Keycloak realm ngn-sip-lab]
    KC -->|Auth code + ID/Access tokens| WD
    WD -->|Token validation via discovery/JWKS| KC
    WD -->|HTTPS :9200| IDX[Wazuh Indexer / OpenSearch Security]
    IDX -->|RBAC decision| IDX

    KC -. realm role .-> R1[wazuh-admin]
    R1 -. composite maps to .-> R2[client role all_access]
    R2 -. token claim resource_access.wazuh-dashboard.roles .-> IDX
```

## Bootstrap from fresh clone

1. Ensure `.env` is present (copy from `.env.example` if needed) and contains Keycloak variables.
2. Start Keycloak:
   ```bash
   make keycloak-up
   ```
3. Wait for health:
   - `docker compose -f docker-compose.keycloak.yml ps`
   - or `curl -sf http://127.0.0.1:8080/health/ready`
4. Open `http://127.0.0.1:8080/admin` and log in with `KEYCLOAK_ADMIN` credentials.
5. Confirm realm auto-imported from `identity/keycloak/realm-export.json`:
   - realm: `ngn-sip-lab`
   - client: `wazuh-dashboard`
   - user: `lab-admin` (temporary password; first login forces reset)
6. Restart dashboard to pick up OIDC settings:
   ```bash
   docker compose -f docker-compose.wazuh.yml restart wazuh-dashboard
   ```
7. Manual smoke:
   - open `https://localhost:5601`
   - verify Keycloak login option is shown
   - verify basic/internal login still exists as fallback option

## Notes on current local-lab posture

- Keycloak runs in `start-dev` mode on loopback bind (`127.0.0.1:8080`) for reproducible local setup.
- Wazuh dashboard talks to Keycloak over the internal Docker network hostname `keycloak`.
- OIDC issuer used by dashboard config: `http://keycloak:8080/realms/ngn-sip-lab`.

## Hardening debt (tracked for campus VM rollout)

1. Move Keycloak to production mode (`start`) with a PostgreSQL backend.
2. Enable HTTPS for Keycloak and trust chain alignment with step-CA.
3. Rotate `wazuh-dashboard` client secret and re-export sanitized realm.
4. Align Wazuh dashboard/indexer trust to step-CA cert chain end-to-end.
