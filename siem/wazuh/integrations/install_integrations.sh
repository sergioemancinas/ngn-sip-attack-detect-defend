#!/usr/bin/env bash
# Idempotently install the Wazuh -> Shuffle integration block into the running
# wazuh-manager container's ossec.conf via the Wazuh API, then restart the manager.
#
# Trigger conditions: alerts at level >=10 from rule_ids 100102/100103/100105/100108
# (defined in siem/wazuh/rules/sip_rules.xml). Hook URL targets the Shuffle backend
# on the shared sip_lab docker network at
# http://shuffle-backend:5001/api/v1/hooks/wazuh-sip-orchestration
# (workflow: soar/shuffle/workflows/sip_response_orchestration.json).
#
# Usage:
#   ./siem/wazuh/integrations/install_integrations.sh           # install + restart
#   ./siem/wazuh/integrations/install_integrations.sh --dry-run # show resulting ossec.conf without writing
#   ./siem/wazuh/integrations/install_integrations.sh --remove  # remove the integration block
#
# Env vars (defaults match docker-compose.wazuh.yml + .env conventions):
#   WAZUH_API_HOST         default 127.0.0.1
#   WAZUH_API_PORT         default 55000
#   WAZUH_API_USER         default wazuh-wui
#   WAZUH_API_PASSWORD     required (read from .env if present)
#   WAZUH_API_CACERT       optional CA file path (defaults to -k for local certs)
#
# Idempotency: re-running is safe. The integration block is bracketed by sentinel
# comments and replaced atomically.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
INTEGRATION_XML="${ROOT_DIR}/siem/wazuh/integrations/wazuh_shuffle_integration.xml"
SENTINEL_OPEN="<!-- ngn-sip-soar:integration:shuffle:begin -->"
SENTINEL_CLOSE="<!-- ngn-sip-soar:integration:shuffle:end -->"

if [ -f "${ROOT_DIR}/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "${ROOT_DIR}/.env"
  set +a
fi

WAZUH_API_HOST="${WAZUH_API_HOST:-127.0.0.1}"
WAZUH_API_PORT="${WAZUH_API_PORT:-55000}"
WAZUH_API_USER="${WAZUH_API_USER:-wazuh-wui}"
WAZUH_API_PASSWORD="${WAZUH_API_PASSWORD:-}"
WAZUH_API_CACERT="${WAZUH_API_CACERT:-}"

if [ -z "${WAZUH_API_PASSWORD}" ]; then
  echo "WAZUH_API_PASSWORD must be set (in .env or env)." >&2
  exit 1
fi

if [ -n "${WAZUH_API_CACERT}" ] && [ ! -f "${WAZUH_API_CACERT}" ]; then
  echo "WAZUH_API_CACERT does not exist: ${WAZUH_API_CACERT}" >&2
  exit 1
fi

if [ -n "${WAZUH_API_CACERT}" ]; then
  CURL_TLS_ARGS=(--cacert "${WAZUH_API_CACERT}")
else
  CURL_TLS_ARGS=(-k)
fi

mode="install"
case "${1:-}" in
  --dry-run) mode="dry-run" ;;
  --remove)  mode="remove"  ;;
  "")        mode="install" ;;
  *)
    echo "Unknown flag: $1" >&2
    exit 2
    ;;
esac

api() {
  local method="$1"; shift
  local path="$1"; shift
  curl -sS "${CURL_TLS_ARGS[@]}" -X "${method}" \
    -H "Authorization: Bearer ${TOKEN}" \
    "$@" \
    "https://${WAZUH_API_HOST}:${WAZUH_API_PORT}${path}"
}

echo "==> Authenticating against Wazuh API at https://${WAZUH_API_HOST}:${WAZUH_API_PORT}"
TOKEN="$(curl -sS "${CURL_TLS_ARGS[@]}" -u "${WAZUH_API_USER}:${WAZUH_API_PASSWORD}" -X POST \
  "https://${WAZUH_API_HOST}:${WAZUH_API_PORT}/security/user/authenticate?raw=true")"

if [ -z "${TOKEN}" ] || [ "${TOKEN:0:3}" != "eyJ" ]; then
  echo "Wazuh API authentication failed; check API_USER/API_PASSWORD and that the manager is up." >&2
  exit 1
fi

echo "==> Fetching current ossec.conf"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
CURRENT="${TMP_DIR}/ossec.current.conf"
api GET "/manager/configuration?raw=true" \
  -H "Accept: application/xml" \
  > "${CURRENT}"

if ! grep -q "<ossec_config>" "${CURRENT}"; then
  echo "Fetched file does not look like ossec.conf:" >&2
  head -20 "${CURRENT}" >&2
  exit 1
fi

NEXT="${TMP_DIR}/ossec.next.conf"
# Strip any prior managed block (idempotent re-run / --remove path).
awk -v open_tag="${SENTINEL_OPEN}" -v close_tag="${SENTINEL_CLOSE}" '
  index($0, open_tag) { skip=1; next }
  index($0, close_tag) { skip=0; next }
  !skip { print }
' "${CURRENT}" > "${NEXT}"

if [ "${mode}" != "remove" ]; then
  if [ ! -f "${INTEGRATION_XML}" ]; then
    echo "Missing ${INTEGRATION_XML}" >&2
    exit 1
  fi
  # Splice integration block before the final </ossec_config>.
  BLOCK="${TMP_DIR}/block.xml"
  {
    echo "  ${SENTINEL_OPEN}"
    # Keep only the inner <integration>...</integration> from the snippet file
    # (drop its outer <ossec_config> wrapper which is only there for editor lint).
    awk '
      /<integration>/{flag=1}
      flag{print}
      /<\/integration>/{flag=0}
    ' "${INTEGRATION_XML}"
    echo "  ${SENTINEL_CLOSE}"
  } > "${BLOCK}"

  awk -v block_file="${BLOCK}" '
    /<\/ossec_config>/ {
      while ((getline line < block_file) > 0) print line
      close(block_file)
    }
    { print }
  ' "${NEXT}" > "${TMP_DIR}/ossec.spliced.conf"
  mv "${TMP_DIR}/ossec.spliced.conf" "${NEXT}"
fi

if [ "${mode}" = "dry-run" ]; then
  echo "==> Dry run: resulting ossec.conf would be:"
  cat "${NEXT}"
  exit 0
fi

echo "==> Uploading patched ossec.conf"
api PUT "/manager/configuration" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${NEXT}" >/dev/null

echo "==> Restarting Wazuh manager to apply integration"
api PUT "/manager/restart" >/dev/null

case "${mode}" in
  install) echo "Shuffle integration block installed." ;;
  remove)  echo "Shuffle integration block removed." ;;
esac
