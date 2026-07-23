#!/usr/bin/env bash
# Idempotent Keycloak SSO client provisioner for the SOC tools (grafana,
# shuffle, homer) and the Next.js stack dashboard (ngn-sip-dashboard).
#
# What it does (via the Keycloak admin REST API + curl):
#   - authenticates to the master realm with the admin creds from .env
#   - creates or updates the grafana / shuffle / homer / ngn-sip-dashboard
#     clients in realm ${KEYCLOAK_REALM:-ngn-sip-lab} as confidential
#     (client-secret) clients
#   - sets the front-channel (http://localhost:<port>/...) AND FQDN
#     (https://<host>.ngn-sip.lab/...) redirect URIs + web origins
#   - prints each effective client secret so YOU can paste it into .env
#
# It does NOT deploy or restart anything and does NOT write secrets to the repo.
# Re-running is safe (idempotent): existing clients are updated in place.
#
# Usage:
#   ! bash scripts/setup_keycloak_sso_clients.sh            # apply to Keycloak
#   ! DRY_RUN=1 bash scripts/setup_keycloak_sso_clients.sh  # preview only (no Keycloak needed)
#
# Inputs (env or .env; safe non-secret defaults shown):
#   KEYCLOAK_ADMIN=admin                 KEYCLOAK_ADMIN_PASSWORD=<required>
#   KC_BASE_URL=http://localhost:8080    KEYCLOAK_REALM=ngn-sip-lab
#   SSO_LOCAL_BASE=http://localhost      SSO_FQDN_BASE_DOMAIN=ngn-sip.lab
#   GRAFANA_HTTP_PORT=3000               GRAFANA_OIDC_CLIENT_SECRET=change-me-local-only
#   SHUFFLE_FRONTEND_PORT=3001           SHUFFLE_OIDC_CLIENT_SECRET=change-me-local-only
#   HOMER_HTTP_PORT=9080                 HOMER_OIDC_CLIENT_SECRET=change-me-local-only
#   DASHBOARD_HTTP_PORT=3002             KEYCLOAK_CLIENT_SECRET=change-me-local-only
#
# Requires: curl, python3 (used only for JSON parsing/encoding; no extra deps).
set -euo pipefail

case "${1:-}" in
  -h|--help) sed -n '2,31p' "$0"; exit 0 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ENV_FILE:-${REPO_ROOT}/.env}"
DRY_RUN="${DRY_RUN:-0}"

# Load .env without clobbering values already exported in the environment, so an
# explicit `VAR=... bash scripts/...` always wins over the .env file.
if [ -f "${ENV_FILE}" ]; then
  while IFS= read -r line || [ -n "${line}" ]; do
    case "${line}" in ''|\#*) continue ;; esac
    key="${line%%=*}"
    val="${line#*=}"
    key="$(printf '%s' "${key}" | tr -d '[:space:]')"
    [ -z "${key}" ] && continue
    val="${val%$'\r'}"
    case "${val}" in
      \"*\") val="${val#\"}"; val="${val%\"}" ;;
      \'*\') val="${val#\'}"; val="${val%\'}" ;;
    esac
    if [ -z "${!key:-}" ]; then export "${key}=${val}"; fi
  done < "${ENV_FILE}"
fi

KC_BASE_URL="${KC_BASE_URL:-http://localhost:8080}"
REALM="${KEYCLOAK_REALM:-ngn-sip-lab}"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
ADMIN_PASS="${KEYCLOAK_ADMIN_PASSWORD:-}"

SSO_LOCAL_BASE="${SSO_LOCAL_BASE:-http://localhost}"
SSO_FQDN_BASE_DOMAIN="${SSO_FQDN_BASE_DOMAIN:-ngn-sip.lab}"

GRAFANA_HTTP_PORT="${GRAFANA_HTTP_PORT:-3000}"
SHUFFLE_FRONTEND_PORT="${SHUFFLE_FRONTEND_PORT:-3001}"
HOMER_HTTP_PORT="${HOMER_HTTP_PORT:-9080}"
DASHBOARD_HTTP_PORT="${DASHBOARD_HTTP_PORT:-3002}"

# Client secrets are parameterized, not hardcoded: they default to the same
# non-secret local placeholder used across the compose files so local SSO works
# out of the box, and the operator overrides them in .env before VM exposure.
GRAFANA_OIDC_CLIENT_SECRET="${GRAFANA_OIDC_CLIENT_SECRET:-change-me-local-only}"
SHUFFLE_OIDC_CLIENT_SECRET="${SHUFFLE_OIDC_CLIENT_SECRET:-change-me-local-only}"
HOMER_OIDC_CLIENT_SECRET="${HOMER_OIDC_CLIENT_SECRET:-change-me-local-only}"
# The Next.js dashboard reuses its runtime var name (KEYCLOAK_CLIENT_SECRET,
# consumed by dashboard/lib/auth.ts + docker-compose.dashboard.yml) so one .env
# entry feeds both Keycloak provisioning and the dashboard container.
DASHBOARD_OIDC_CLIENT_SECRET="${KEYCLOAK_CLIENT_SECRET:-change-me-local-only}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: required command '$1' not found" >&2; exit 1; }; }
need curl
need python3

# Per-tool front-channel + FQDN redirect URIs and web origins.
GRAFANA_REDIRECTS="$(printf '%s\n%s\n%s\n%s' \
  "${SSO_LOCAL_BASE}:${GRAFANA_HTTP_PORT}/login/generic_oauth" \
  "${SSO_LOCAL_BASE}:${GRAFANA_HTTP_PORT}/*" \
  "https://grafana.${SSO_FQDN_BASE_DOMAIN}/login/generic_oauth" \
  "https://grafana.${SSO_FQDN_BASE_DOMAIN}/*")"
GRAFANA_ORIGINS="$(printf '%s\n%s' \
  "${SSO_LOCAL_BASE}:${GRAFANA_HTTP_PORT}" \
  "https://grafana.${SSO_FQDN_BASE_DOMAIN}")"

SHUFFLE_REDIRECTS="$(printf '%s\n%s\n%s\n%s' \
  "${SSO_LOCAL_BASE}:${SHUFFLE_FRONTEND_PORT}/api/v1/login_openid" \
  "${SSO_LOCAL_BASE}:${SHUFFLE_FRONTEND_PORT}/*" \
  "https://shuffle.${SSO_FQDN_BASE_DOMAIN}/api/v1/login_openid" \
  "https://shuffle.${SSO_FQDN_BASE_DOMAIN}/*")"
SHUFFLE_ORIGINS="$(printf '%s\n%s' \
  "${SSO_LOCAL_BASE}:${SHUFFLE_FRONTEND_PORT}" \
  "https://shuffle.${SSO_FQDN_BASE_DOMAIN}")"

HOMER_REDIRECTS="$(printf '%s\n%s\n%s\n%s' \
  "${SSO_LOCAL_BASE}:${HOMER_HTTP_PORT}/api/v3/oauth2/auth" \
  "${SSO_LOCAL_BASE}:${HOMER_HTTP_PORT}/*" \
  "https://homer.${SSO_FQDN_BASE_DOMAIN}/api/v3/oauth2/auth" \
  "https://homer.${SSO_FQDN_BASE_DOMAIN}/*")"
HOMER_ORIGINS="$(printf '%s\n%s' \
  "${SSO_LOCAL_BASE}:${HOMER_HTTP_PORT}" \
  "https://homer.${SSO_FQDN_BASE_DOMAIN}")"

# NextAuth (Keycloak provider) callback is /api/auth/callback/keycloak. The
# 127.0.0.1 variant is required because the compose default
# NEXTAUTH_URL=http://127.0.0.1:3002 makes NextAuth emit a 127.0.0.1 (not
# localhost) redirect_uri.
DASHBOARD_REDIRECTS="$(printf '%s\n%s\n%s\n%s' \
  "${SSO_LOCAL_BASE}:${DASHBOARD_HTTP_PORT}/api/auth/callback/keycloak" \
  "http://127.0.0.1:${DASHBOARD_HTTP_PORT}/api/auth/callback/keycloak" \
  "https://dashboard.${SSO_FQDN_BASE_DOMAIN}/api/auth/callback/keycloak" \
  "https://dashboard.${SSO_FQDN_BASE_DOMAIN}/*")"
DASHBOARD_ORIGINS="$(printf '%s\n%s\n%s' \
  "${SSO_LOCAL_BASE}:${DASHBOARD_HTTP_PORT}" \
  "http://127.0.0.1:${DASHBOARD_HTTP_PORT}" \
  "https://dashboard.${SSO_FQDN_BASE_DOMAIN}")"

print_list() { while IFS= read -r u; do [ -n "${u}" ] && echo "      - ${u}"; done <<EOF
$1
EOF
}

# Build a Keycloak client representation as JSON via python3 (handles arrays and
# quoting safely). Reads inputs from the environment to avoid shell-quoting pitfalls.
make_client_json() {
  CID="$1" CNAME="$2" CSECRET="$3" CREDIRECTS="$4" CORIGINS="$5" CUUID="${6:-}" python3 - <<'PY'
import json, os
body = {
    "clientId": os.environ["CID"],
    "name": os.environ["CNAME"],
    "description": "NGN-SIP SSO client managed by scripts/setup_keycloak_sso_clients.sh",
    "protocol": "openid-connect",
    "enabled": True,
    "publicClient": False,
    "clientAuthenticatorType": "client-secret",
    "secret": os.environ["CSECRET"],
    "standardFlowEnabled": True,
    # Shuffle's on-prem OpenID login sends response_type=id_token (form_post)
    # whenever a client secret is configured (GetOpenIdUrl in shuffle-shared),
    # so its client MUST have the implicit flow enabled or Keycloak rejects
    # the login with unauthorized_client. All other clients use the standard
    # authorization-code flow only.
    "implicitFlowEnabled": os.environ["CID"] == "shuffle",
    "directAccessGrantsEnabled": True,
    "serviceAccountsEnabled": False,
    "frontchannelLogout": True,
    "fullScopeAllowed": True,
    "redirectUris": [u for u in os.environ["CREDIRECTS"].splitlines() if u],
    "webOrigins": [u for u in os.environ["CORIGINS"].splitlines() if u],
    "defaultClientScopes": ["profile", "email", "roles", "web-origins"],
    "attributes": {"post.logout.redirect.uris": "+"},
}
uuid = os.environ.get("CUUID", "")
if uuid:
    body["id"] = uuid
print(json.dumps(body))
PY
}

get_token() {
  curl -fsS --max-time 15 \
    -d "client_id=admin-cli" \
    -d "grant_type=password" \
    -d "username=${ADMIN_USER}" \
    --data-urlencode "password=${ADMIN_PASS}" \
    "${KC_BASE_URL}/realms/master/protocol/openid-connect/token" \
  | python3 -c 'import sys, json; print(json.load(sys.stdin)["access_token"])'
}

client_uuid() {
  curl -fsS --max-time 15 -H "Authorization: Bearer ${TOKEN}" \
    "${KC_BASE_URL}/admin/realms/${REALM}/clients?clientId=$1" \
  | python3 -c 'import sys, json; a = json.load(sys.stdin); print(a[0]["id"] if a else "")'
}

read_secret() {
  curl -fsS --max-time 15 -H "Authorization: Bearer ${TOKEN}" \
    "${KC_BASE_URL}/admin/realms/${REALM}/clients/$1/client-secret" \
  | python3 -c 'import sys, json; print(json.load(sys.stdin).get("value", ""))'
}

upsert_client() {
  local cid="$1" cname="$2" csecret="$3" credirects="$4" corigins="$5"
  local uuid body
  uuid="$(client_uuid "${cid}")"
  if [ -n "${uuid}" ]; then
    body="$(make_client_json "${cid}" "${cname}" "${csecret}" "${credirects}" "${corigins}" "${uuid}")"
    curl -fsS --max-time 20 -X PUT \
      -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
      -d "${body}" "${KC_BASE_URL}/admin/realms/${REALM}/clients/${uuid}" >/dev/null
    echo "  updated client '${cid}' (${uuid})"
  else
    body="$(make_client_json "${cid}" "${cname}" "${csecret}" "${credirects}" "${corigins}")"
    curl -fsS --max-time 20 -X POST \
      -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
      -d "${body}" "${KC_BASE_URL}/admin/realms/${REALM}/clients" >/dev/null
    uuid="$(client_uuid "${cid}")"
    echo "  created client '${cid}' (${uuid})"
  fi
  printf '  >> %-8s client_secret: %s\n' "${cid}" "$(read_secret "${uuid}")"
}

plan_client() {
  local cid="$1" credirects="$2" corigins="$3" csecret="$4"
  echo "  client '${cid}' (confidential / client-secret, secret would be: ${csecret})"
  echo "    redirectUris:"; print_list "${credirects}"
  echo "    webOrigins:";   print_list "${corigins}"
}

if [ "${DRY_RUN}" = "1" ]; then
  echo "DRY_RUN=1 - previewing planned Keycloak config only (no calls to ${KC_BASE_URL}):"
  echo "realm: ${REALM}"
  plan_client grafana "${GRAFANA_REDIRECTS}" "${GRAFANA_ORIGINS}" "${GRAFANA_OIDC_CLIENT_SECRET}"
  plan_client shuffle "${SHUFFLE_REDIRECTS}" "${SHUFFLE_ORIGINS}" "${SHUFFLE_OIDC_CLIENT_SECRET}"
  plan_client homer   "${HOMER_REDIRECTS}"   "${HOMER_ORIGINS}"   "${HOMER_OIDC_CLIENT_SECRET}"
  plan_client ngn-sip-dashboard "${DASHBOARD_REDIRECTS}" "${DASHBOARD_ORIGINS}" "${DASHBOARD_OIDC_CLIENT_SECRET}"
  echo
  echo "Re-run without DRY_RUN to apply. Set KEYCLOAK_ADMIN_PASSWORD first."
  exit 0
fi

[ -n "${ADMIN_PASS}" ] || { echo "ERROR: KEYCLOAK_ADMIN_PASSWORD is not set (export it or add it to ${ENV_FILE})" >&2; exit 1; }

TOKEN="$(get_token)" || { echo "ERROR: could not obtain admin token. Check KEYCLOAK_ADMIN/KEYCLOAK_ADMIN_PASSWORD and that Keycloak is reachable at ${KC_BASE_URL}." >&2; exit 1; }
echo "Authenticated to ${KC_BASE_URL} (master realm) as '${ADMIN_USER}'. Target realm: ${REALM}"

upsert_client grafana "Grafana" "${GRAFANA_OIDC_CLIENT_SECRET}" "${GRAFANA_REDIRECTS}" "${GRAFANA_ORIGINS}"
upsert_client shuffle "Shuffle" "${SHUFFLE_OIDC_CLIENT_SECRET}" "${SHUFFLE_REDIRECTS}" "${SHUFFLE_ORIGINS}"
upsert_client homer   "Homer"   "${HOMER_OIDC_CLIENT_SECRET}"   "${HOMER_REDIRECTS}"   "${HOMER_ORIGINS}"
upsert_client ngn-sip-dashboard "NGN SIP Stack Dashboard" "${DASHBOARD_OIDC_CLIENT_SECRET}" "${DASHBOARD_REDIRECTS}" "${DASHBOARD_ORIGINS}"

cat <<NEXT

Done. Put the printed secrets in .env so the tools match Keycloak:
  GRAFANA_OIDC_CLIENT_SECRET=...   (docker-compose.observability.yml)
  SHUFFLE_OIDC_CLIENT_SECRET=...   (entered in Shuffle admin UI -> OpenID Connect)
  HOMER_OIDC_CLIENT_SECRET=...     (docker-compose.homer.yml)
  KEYCLOAK_CLIENT_SECRET=...       (docker-compose.dashboard.yml, ngn-sip-dashboard)

Then enable per tool and re-create the containers. See docs/sso/sso_runbook.md.
Issuer stays http://localhost:8080 - the wazuh-dashboard client is untouched.
NEXT
