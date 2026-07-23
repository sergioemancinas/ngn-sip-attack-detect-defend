# SOC tools SSO runbook (Grafana, Shuffle, Homer)

How to turn on Keycloak OIDC for the three SOC tools. This is preparation only:
everything below is **inert by default**. The compose files keep their current
behavior until you set the documented `.env` vars and run the provisioning
script. Nothing here deploys or restarts containers for you.

The dashboard already uses this exact pattern (Keycloak OIDC over split-horizon);
this runbook mirrors it for Grafana, Shuffle, and Homer.

## Split-horizon recap

Keycloak runs in dev mode with `KC_HOSTNAME=http://localhost:8080` and
`KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true`. That gives every client two horizons:

- **Browser horizon** (front-channel, `authorization` step): `http://localhost:8080`.
  A tunnelled browser can reach this; it cannot resolve `keycloak:8080`.
- **Backend horizon** (back-channel: token, userinfo, JWKS/certs): `http://keycloak:8080`.
  The app container resolves this over the `sip_lab` bridge; it cannot reach
  `localhost:8080` from inside the container.

Each tool below is wired so the authorization URL points at `localhost:8080`
while token/userinfo/certs point at `keycloak:8080`. Mixing them breaks login.

The realm issuer stays `http://localhost:8080/realms/ngn-sip-lab`. I do not
change `KC_HOSTNAME`, so the existing `wazuh-dashboard` client is unaffected.

## Prerequisites

- Keycloak up and healthy (`make keycloak-up`; realm `ngn-sip-lab` imported).
- `.env` present at the repo root with `KEYCLOAK_ADMIN` and
  `KEYCLOAK_ADMIN_PASSWORD` (defaults are in `.env.example`).
- `curl` and `python3` on the host (the script uses only these).

## Step 0: provision the Keycloak clients

This creates/updates the `grafana`, `shuffle`, and `homer` clients (confidential,
client-secret) with both the `http://localhost:<port>/...` and
`https://<host>.ngn-sip.lab/...` redirect URIs, then prints each client secret.

```bash
# Preview only (no Keycloak calls, no changes):
DRY_RUN=1 bash scripts/setup_keycloak_sso_clients.sh

# Apply (idempotent; safe to re-run):
bash scripts/setup_keycloak_sso_clients.sh
```

Optional overrides (env or `.env`), with their safe defaults:

| Var | Default | Purpose |
|---|---|---|
| `KC_BASE_URL` | `http://localhost:8080` | Admin REST + token endpoint base |
| `KEYCLOAK_REALM` | `ngn-sip-lab` | Target realm |
| `SSO_LOCAL_BASE` | `http://localhost` | Front-channel host base for redirect URIs |
| `SSO_FQDN_BASE_DOMAIN` | `ngn-sip.lab` | FQDN base for the `https://<host>.<domain>` redirect URIs |
| `GRAFANA_HTTP_PORT` / `SHUFFLE_FRONTEND_PORT` / `HOMER_HTTP_PORT` | `3000` / `3001` / `9080` | Front-channel ports |
| `GRAFANA_OIDC_CLIENT_SECRET` / `SHUFFLE_OIDC_CLIENT_SECRET` / `HOMER_OIDC_CLIENT_SECRET` | `change-me-local-only` | Secret set on each client and printed back |

Copy the printed secrets into `.env` (next sections) so each tool matches Keycloak.

Role mapping (optional): assign each user a client role and surface it in the
`roles` claim. See `docs/sso/keycloak_architecture.md` for the realm role to
client role mapping pattern already used by `wazuh-admin`.

## Grafana

Grafana OIDC is already wired in `docker-compose.observability.yml`; only the
client secret and root URL are now `.env`-overridable. The anonymous read-only
viewer (used by the embedded dashboard panels) stays enabled.

Front-channel auth, back-channel token/userinfo (already set in compose):

- auth: `http://localhost:8080/realms/ngn-sip-lab/protocol/openid-connect/auth`
- token: `http://keycloak:8080/realms/ngn-sip-lab/protocol/openid-connect/token`
- userinfo: `http://keycloak:8080/realms/ngn-sip-lab/protocol/openid-connect/userinfo`

Keycloak redirect URI: `http://localhost:3000/login/generic_oauth`
(and `https://grafana.ngn-sip.lab/login/generic_oauth` for the FQDN).

`.env`:

```bash
GRAFANA_OIDC_CLIENT_SECRET=<secret printed by the script>
# For FQDN access behind the proxy:
GRAFANA_ROOT_URL=https://grafana.ngn-sip.lab
```

Apply and test:

```bash
docker compose -f docker-compose.observability.yml up -d grafana
# Open http://localhost:3000 -> "Sign in with Keycloak" -> log in as lab-admin.
# Local admin login and the anonymous viewer both still work.
```

## Shuffle

Shuffle reads only one SSO env var, `SSO_REDIRECT_URL` (added to `shuffle-backend`
in `docker-compose.soar.yml`, empty by default = unchanged behavior). The OpenID
client id, client secret, authorization URL, and token URL live in the org's
`sso_config` object, stored in OpenSearch - settable either in the Shuffle admin
UI **or over the REST API**: `POST /api/v1/orgs/<org_id>` with
`{"editing": "sso_config", "sso_config": {...}}` (the `editing` flag is
mandatory; without it the backend answers 200 and silently discards the
payload). Automated by:

```bash
./scripts/provision_shuffle.sh --sso
```

Keycloak redirect URI: `http://localhost:3001/api/v1/login_openid`
(and `https://shuffle.ngn-sip.lab/api/v1/login_openid` for the FQDN).

Flow quirk (verified against Shuffle 2.2.0 + Keycloak): when a client secret is
configured, Shuffle's on-prem OpenID login uses `response_type=id_token` with
`response_mode=form_post` (implicit flow) - not the authorization-code flow -
so the Keycloak `shuffle` client must have **Implicit flow enabled**
(`scripts/setup_keycloak_sso_clients.sh` does this for the shuffle client only).
With the secret left empty Shuffle switches to code + PKCE as a public client.
Note the implicit-flow `state` embeds the client secret base64-encoded in the
browser URL - acceptable for this loopback lab, another reason to keep real
deployments behind TLS and rotate the secret.

`.env`:

```bash
# Front-end URL Shuffle redirects back to after OpenID login:
SHUFFLE_SSO_REDIRECT_URL=http://localhost:3001
# or, behind the proxy: SHUFFLE_SSO_REDIRECT_URL=https://shuffle.ngn-sip.lab
```

Apply:

```bash
docker compose -f docker-compose.soar.yml up -d shuffle-backend
```

Then run `./scripts/provision_shuffle.sh --sso`, or enter the same values in
the Shuffle UI (Admin -> your org -> OpenID Connect) - the split-horizon pair:

- Client ID: `shuffle`
- Client secret: `<SHUFFLE_OIDC_CLIENT_SECRET printed by the script>`
- Authorization URL (browser): `http://localhost:8080/realms/ngn-sip-lab/protocol/openid-connect/auth`
- Token URL (backend): `http://keycloak:8080/realms/ngn-sip-lab/protocol/openid-connect/token`

Save, log out, and confirm the "Use SSO" button logs you in. Local admin login
remains available as fallback.

## Homer

Homer's `oauth2` block lives in `infra/homer/webapp/settings.js` and is rendered
by `docker-compose.homer.yml` from `HOMER_OIDC_*` env. It is gated by
`HOMER_OIDC_ENABLE` (default `false`), so internal DB auth stays primary until
you flip it. When enabled, Homer shows a Keycloak SSO button in addition to the
internal login form.

Keycloak redirect URI: `http://localhost:9080/api/v3/oauth2/auth`
(and `https://homer.ngn-sip.lab/api/v3/oauth2/auth` for the FQDN).

`.env`:

```bash
HOMER_OIDC_ENABLE=true
HOMER_OIDC_CLIENT_ID=homer
HOMER_OIDC_CLIENT_SECRET=<secret printed by the script>
# user_token must be >= 43 chars (Homer requirement); rotate this value:
HOMER_OIDC_USER_TOKEN=<random url-safe string, 43+ chars>
# For FQDN access behind the proxy:
HOMER_OIDC_REDIRECT_URI=https://homer.ngn-sip.lab/api/v3/oauth2/auth
```

The split-horizon URLs are derived automatically from the defaults
`HOMER_OIDC_BROWSER_BASE_URL=http://localhost:8080` (auth) and
`HOMER_OIDC_BACKEND_BASE_URL=http://keycloak:8080` (token/userinfo/certs);
override them only if your hostnames differ.

Apply and test:

```bash
docker compose -f docker-compose.homer.yml up -d homer-webapp
# Open http://localhost:9080 -> Keycloak SSO button -> log in as lab-admin.
```

## `.env` reference (all new/relevant vars)

```bash
# Grafana (docker-compose.observability.yml)
GRAFANA_OIDC_CLIENT_SECRET=change-me-local-only
GRAFANA_ROOT_URL=http://localhost:3000

# Shuffle (docker-compose.soar.yml). Empty = unchanged behavior.
SHUFFLE_SSO_REDIRECT_URL=

# Homer (docker-compose.homer.yml). HOMER_OIDC_ENABLE=false keeps internal auth only.
HOMER_OIDC_ENABLE=false
HOMER_OIDC_CLIENT_ID=homer
HOMER_OIDC_CLIENT_SECRET=change-me-local-only
HOMER_OIDC_REALM=ngn-sip-lab
HOMER_OIDC_BROWSER_BASE_URL=http://localhost:8080
HOMER_OIDC_BACKEND_BASE_URL=http://keycloak:8080
HOMER_OIDC_REDIRECT_URI=http://localhost:9080/api/v3/oauth2/auth
HOMER_OIDC_USER_TOKEN=change-me-local-only-homer-oauth-user-token-rotate

# Client-secret overrides consumed by scripts/setup_keycloak_sso_clients.sh
SHUFFLE_OIDC_CLIENT_SECRET=change-me-local-only
```

These mirror the safe defaults already baked into the compose files, so adding
them to `.env` is optional until you actually enable SSO.

## Disabling / rolling back

- Grafana: it ships with OAuth enabled already; to hide the button set
  `GF_AUTH_GENERIC_OAUTH_ENABLED=false` (not changed by this prep).
- Shuffle: clear `SHUFFLE_SSO_REDIRECT_URL` and disable OpenID in the admin UI.
- Homer: set `HOMER_OIDC_ENABLE=false` and re-create `homer-webapp`.

## Hardening before campus VM exposure

1. Rotate every client secret (script prints them; store them in `.env`, never
   in the repo) and re-run the script.
2. Move the front-channel from `http://localhost:8080` to the TLS FQDN and set
   `KC_HOSTNAME_STRICT=true` in `docker-compose.keycloak.yml`.
3. Disable each tool's local-auth fallback once SSO is verified end-to-end.
4. Keep the issuer consistent so `wazuh-dashboard` continues to work, or migrate
   all clients together if the issuer host changes.
