# Wazuh Indexer Security Config (OIDC backend)

These two files extend the stock Wazuh indexer security configuration with:

- `config.yml`: adds `openid_auth_domain` (order 0, http/transport enabled) pointing at the Keycloak realm `ngn-sip-lab` at `http://keycloak:8080`. `subject_key=preferred_username`, `roles_key=roles` (matches the realm's `wazuh-client-roles` protocol mapper that flattens client roles into a top-level `roles` claim).
- `roles_mapping.yml`: adds `all_access` and `wazuh-admin` to the `all_access` OpenSearch role's `backend_roles` list, so Keycloak users carrying either role get full SIEM access.

Live state at the indexer is persisted in the `.opendistro_security` index, so changes survive container restarts as long as the indexer data volume persists. On a clean rebuild the files must be re-pushed.

## Apply on a fresh stack

Preferred (idempotent, waits for a healthy indexer, resolves the container
name from `COMPOSE_PROJECT_NAME`):

```bash
make wazuh-sso-apply           # or: bash scripts/apply_wazuh_sso.sh
```

Manual equivalent (container name is `${COMPOSE_PROJECT_NAME:-ngn-sip}-wazuh-indexer-1`;
with the default project name that is `ngn-sip-wazuh-indexer-1`):

```bash
# 1. Copy the two YAMLs into the running indexer:
docker cp siem/wazuh/indexer-security/config.yml \
  ngn-sip-wazuh-indexer-1:/usr/share/wazuh-indexer/config/opensearch-security/config.yml
docker cp siem/wazuh/indexer-security/roles_mapping.yml \
  ngn-sip-wazuh-indexer-1:/usr/share/wazuh-indexer/config/opensearch-security/roles_mapping.yml

# 2. Push to the cluster via securityadmin.sh
docker exec ngn-sip-wazuh-indexer-1 sh -c '
  export JAVA_HOME=/usr/share/wazuh-indexer/jdk
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
    -cd /usr/share/wazuh-indexer/config/opensearch-security/ -icl -nhnv \
    -cacert /usr/share/wazuh-indexer/config/certs/root-ca.pem \
    -cert  /usr/share/wazuh-indexer/config/certs/admin.pem \
    -key   /usr/share/wazuh-indexer/config/certs/admin-key.pem \
    -h localhost'
```

Login chain that now works end-to-end:

```
Browser -> https://localhost:5601
  -> Wazuh dashboard renders OIDC login button
  -> /auth/openid/login redirects to http://localhost:8080/realms/ngn-sip-lab/protocol/openid-connect/auth?client_id=wazuh-dashboard&...
  -> Keycloak authenticates lab-admin
  -> 302 back to https://localhost:5601/auth/openid/login?code=...
  -> Dashboard server exchanges code at http://keycloak:8080/.../token (backchannel via Docker bridge)
  -> Dashboard forwards ID token to wazuh-indexer; indexer's openid_auth_domain validates against Keycloak's well-known endpoint, extracts roles claim, maps to all_access OpenSearch role
  -> User in.
```

## Companion changes that this config depends on

- `docker-compose.keycloak.yml`: sets `KC_HOSTNAME=http://localhost:8080`, `KC_HOSTNAME_STRICT=false`, `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true`. This is what produces split front- vs back-channel metadata so browser sees `localhost:8080` while the dashboard server keeps using `keycloak:8080` for token exchange.
- `siem/wazuh/config/opensearch_dashboards.yml`: template with `__KEYCLOAK_REALM__` / `__KEYCLOAK_WAZUH_CLIENT_ID__` / `__KEYCLOAK_WAZUH_CLIENT_SECRET__` placeholders, sed-rendered from env at container start by the wazuh-dashboard entrypoint wrapper in `docker-compose.wazuh.yml` (the Wazuh dashboard does not expand `${VAR:default}` syntax itself).
