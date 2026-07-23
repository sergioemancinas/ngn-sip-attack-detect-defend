# Internet Exposure Checklist (lab-secure → internet-secure)

This testbed is **lab-secure by design, not internet-secure.** It is meant to
run on a loopback-bound developer machine or a tunnel-gated VM. Every host port
binds to `DEV_BIND_IP` (default `127.0.0.1`), all credentials are lab-obvious
placeholders, and several conveniences (anonymous Grafana viewing, a demo CA,
demo SIP passwords, `RELAY_ALLOW_PRIVATE=1`) trade hardening for a friction-free
demo.

**Do not expose any part of this stack to an untrusted network without
completing every item below.** They are ordered by blast radius.

## 1. Secrets - rotate every placeholder

Every `change-me-local-only` / `ChangeMeLocal1!` default must be replaced with a
unique, strong value from a secret manager (not committed). At minimum:

- `CLICKHOUSE_PASSWORD`, `POSTGRES_PASSWORD`
- `WAZUH_INDEXER_PASSWORD`, `WAZUH_API_PASSWORD`, `WAZUH_DASHBOARD_PASSWORD`
- `KEYCLOAK_ADMIN_PASSWORD`, and every OIDC client secret
  (`KEYCLOAK_CLIENT_SECRET`, `GRAFANA_OIDC_CLIENT_SECRET`,
  `SHUFFLE_OIDC_CLIENT_SECRET`, `HOMER_OIDC_CLIENT_SECRET`,
  `KEYCLOAK_WAZUH_CLIENT_SECRET`)
- `NEXTAUTH_SECRET` - `openssl rand -base64 32`
- `KAMCMD_BLOCK_RELAY_TOKEN` (≥32 chars), `SHUFFLE_DEFAULT_APIKEY` (≥36 chars),
  `AUTH_FOR_ORBORUS`, `SHUFFLE_ENCRYPTION_MODIFIER`
- Rotate the Keycloak realm's `lab-admin` password (it ships with a forced
  `UPDATE_PASSWORD` action; do not keep the documented default).

## 2. Network posture - never publish management planes

- Only the SIP edge (Kamailio `5060`, rtpengine media range) should ever face
  the internet. **Every management plane stays private**: Grafana, the Wazuh
  dashboard, Shuffle, ClickHouse, OpenSearch, Ollama, Keycloak admin, the
  Next.js dashboard, Homer.
- Reach the management planes only over an authenticated tunnel (WireGuard) or
  behind the bundled Caddy reverse proxy with real TLS - never by widening
  `DEV_BIND_IP`.
- `make check-local-exposure` fails if any container publishes to `0.0.0.0`;
  keep it in your pre-exposure gate.

## 3. kamcmd-relay (ban enforcement)

- Set `RELAY_ALLOW_PRIVATE=0`. In the lab it is `1` so a 172.x test attacker is
  bannable; internet-facing, private sources must never be bannable
  (blocklist-poisoning / self-DoS via spoofed SIP-over-UDP source addresses).
- Confirm `RELAY_TOKEN` is a real secret (the relay fails closed without one).
- The relay and `kamailio-autoban` mount the Docker socket read-only to run
  `docker exec kamcmd`. On an internet-facing host, front the socket with a
  scoped proxy (e.g. `tecnativa/docker-socket-proxy`, exec-only) so a relay
  compromise cannot become full host control.

## 4. Identity - Keycloak

- Run Keycloak with `start` (not `start-dev`), `KC_HOSTNAME_STRICT=true`,
  `KC_HTTP_ENABLED=false`, and TLS terminated at the proxy.
- Replace the imported realm's demo secrets; disable any test users.

## 5. SIP edge hardening

- Disable the demo SIP accounts (`1000pass` / `1001pass` in
  `infra/asterisk/etc/pjsip.conf`); require real registration auth.
- Keep the Kamailio `secfilter`, PIKE rate-limiting, and `ban_table` /
  `DROP_IF_BANNED` route active; tune `autoban` thresholds
  (`MIN_LEVEL`, `ML_MIN_PROBA`, `LLM_MIN_CONF`) for the real traffic profile.
- Provision real TLS/SRTP rather than the lab defaults.

## 6. Observability / SIEM

- Grafana: set `GF_AUTH_ANONYMOUS_ENABLED=false` and disable iframe embedding
  unless a trusted portal needs it.
- Wazuh: replace the demo certificate authority and `kibanaserver` default;
  apply the indexer OIDC config (`make wazuh-sso-apply`) so the dashboard is
  SSO-gated, not basic-auth.
- Dashboard: `DASHBOARD_ALLOW_INSECURE=false` with a real `NEXTAUTH_SECRET`.

## 7. Capacity / resilience

- The live-exposure experiment hit a disk-capacity limit under sustained flood.
  Confirm ClickHouse TTL retention caps on the high-volume tables and log
  rotation on Vector/Wazuh before any real-traffic run, and monitor disk.

## 8. Repository / supply chain (if forking for real use)

- Enable branch protection, required review, and secret scanning.
- Keep image tags and dependencies pinned (Dependabot is configured); review the
  OpenSSF Scorecard report.
- **Base-image pinning posture:** all container base images are pinned to
  explicit tags (e.g. `python:3.11-slim`, `node:22.12.0-alpine3.20`), and the
  Dependabot `docker` ecosystem tracks them. Digest pinning (the gold standard,
  demonstrated by `infra/asterisk/Dockerfile`) is deliberately not applied
  repo-wide yet: it should be done together with a build-verification pass so a
  moved-or-wrong digest cannot silently break the fresh-clone build. A release
  SBOM (`.github/workflows/release.yml`) records the exact resolved dependency
  set per release.

---

See also `SECURITY.md` (disclosure policy) and `docs/02_threat_model.md` (trust
boundaries, abuse cases, accepted-risk register).
