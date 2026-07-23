# Wazuh 4.14.5 TLS setup (local Compose)

## Why this change exists

Wazuh 4.14.x enables the OpenSearch security plugin by default. The former local override (`plugins.security.disabled: true`) leaves indexer bootstrap in a broken state and can keep the service in `health: starting`.

This repo now follows the upstream Wazuh 4.14 cert-generator pattern, adapted to this lab's conventions (loopback binds, short dash hostnames, named volumes, no checked-in certs).

## Design

1. **One-shot cert init service**  
   `wazuh-certs-generator` (`wazuh/wazuh-certs-generator:0.0.4`) writes certs into the named volume `wazuh_certs` and exits.  
   If cert files already exist in the volume, it exits 0 immediately and skips regeneration.

2. **Explicit startup ordering**  
   `wazuh-indexer`, `wazuh-manager`, and `wazuh-dashboard` depend on the generator with `condition: service_completed_successfully`.

3. **TLS everywhere in Wazuh stack**
   - Indexer HTTP + transport TLS are enabled in `siem/wazuh/indexer/opensearch-local.yml`.
   - Manager talks to indexer via HTTPS and mounts manager cert material from `wazuh_certs`.
   - Dashboard talks to indexer via HTTPS and serves HTTPS itself.
   - Healthchecks were updated to HTTPS (`curl -k` where appropriate).

4. **Password/hash alignment with `.env`**
   `siem/wazuh/config/internal_users.yml` is treated as a template.  
   On indexer startup, an entrypoint wrapper renders:
   - `admin` hash from `WAZUH_INDEXER_PASSWORD`
   - `kibanaserver` hash from `WAZUH_DASHBOARD_PASSWORD`

   This avoids drift between static hashes and real `.env` credentials while keeping defaults in `.env.example` safe (`change-me-local-only` style).

## Files involved

- `docker-compose.wazuh.yml`
- `siem/wazuh/indexer/opensearch-local.yml`
- `siem/wazuh/config/certs.yml`
- `siem/wazuh/config/internal_users.yml`
- `siem/wazuh/config/opensearch_dashboards.yml`
- `siem/wazuh/integrations/install_integrations.sh`

## Wazuh API change in 4.14.5 (integration installer)

`/manager/files` is no longer available in this image/API profile.  
Integration install now uses:

- `GET /manager/configuration?raw=true`
- `PUT /manager/configuration`

over HTTPS (`-k` by default, or `WAZUH_API_CACERT` when provided).

## Rotation note

For production/campus VM usage:

1. rotate `WAZUH_INDEXER_PASSWORD`, `WAZUH_API_PASSWORD`, `WAZUH_DASHBOARD_PASSWORD` in `.env`
2. recreate the Wazuh stack so indexer renders new internal user hashes
3. verify:
   - `curl -ks -u admin:<new-password> https://127.0.0.1:9200/_cluster/health`
   - dashboard and manager healthchecks are healthy
