#!/usr/bin/env bash
# Apply the Wazuh indexer OIDC security config to the RUNNING indexer.
#
# The indexer's OpenSearch security plugin stores its live config in the
# .opendistro_security index, not in files, so mounting
# siem/wazuh/indexer-security/{config.yml,roles_mapping.yml} is not enough:
# they must be pushed with securityadmin.sh. This script does exactly that:
#
#   1. waits until <project>-wazuh-indexer-1 reports a healthy Docker status
#   2. docker cp's config.yml (adds openid_auth_domain -> Keycloak realm
#      ngn-sip-lab) and roles_mapping.yml (maps wazuh-admin/all_access backend
#      roles to all_access) into the container's opensearch-security dir
#   3. runs securityadmin.sh for exactly those two objects (config +
#      rolesmapping), leaving internal_users/roles/tenants untouched so the
#      runtime-hashed admin/kibanaserver passwords survive
#
# Idempotent: re-running pushes the same content over the same two security
# objects; nothing else changes. Safe to run on every bring-up.
#
# Usage:
#   bash scripts/apply_wazuh_sso.sh              # apply
#   DRY_RUN=1 bash scripts/apply_wazuh_sso.sh    # print what would run
#
# Inputs (env or .env):
#   COMPOSE_PROJECT_NAME=ngn-sip     -> container ${COMPOSE_PROJECT_NAME}-wazuh-indexer-1
#   WAZUH_INDEXER_CONTAINER=<name>   -> explicit container name override
#   WAIT_TIMEOUT=180                 -> seconds to wait for a healthy indexer
set -euo pipefail

case "${1:-}" in
  -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ENV_FILE:-${REPO_ROOT}/.env}"
DRY_RUN="${DRY_RUN:-0}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-180}"

# Load .env without clobbering values already exported in the environment.
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

INDEXER_CTR="${WAZUH_INDEXER_CONTAINER:-${COMPOSE_PROJECT_NAME:-ngn-sip}-wazuh-indexer-1}"
SEC_SRC_DIR="${REPO_ROOT}/siem/wazuh/indexer-security"
SEC_DST_DIR="/usr/share/wazuh-indexer/config/opensearch-security"
CERT_DIR="/usr/share/wazuh-indexer/config/certs"
TOOLS_DIR="/usr/share/wazuh-indexer/plugins/opensearch-security/tools"

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found in PATH" >&2; exit 1; }
for f in config.yml roles_mapping.yml; do
  [ -f "${SEC_SRC_DIR}/${f}" ] || { echo "ERROR: missing ${SEC_SRC_DIR}/${f}" >&2; exit 1; }
done

if [ "${DRY_RUN}" = "1" ]; then
  echo "DRY_RUN=1 - would run against container '${INDEXER_CTR}':"
  echo "  docker cp ${SEC_SRC_DIR}/config.yml        ${INDEXER_CTR}:${SEC_DST_DIR}/config.yml"
  echo "  docker cp ${SEC_SRC_DIR}/roles_mapping.yml ${INDEXER_CTR}:${SEC_DST_DIR}/roles_mapping.yml"
  echo "  docker exec ${INDEXER_CTR} securityadmin.sh -f config.yml -t config ..."
  echo "  docker exec ${INDEXER_CTR} securityadmin.sh -f roles_mapping.yml -t rolesmapping ..."
  exit 0
fi

state="$(docker inspect -f '{{.State.Running}}' "${INDEXER_CTR}" 2>/dev/null || echo missing)"
if [ "${state}" != "true" ]; then
  echo "ERROR: container '${INDEXER_CTR}' is not running (state: ${state})." >&2
  echo "Start the Wazuh stack first: make wazuh-up" >&2
  exit 1
fi

echo "Waiting for '${INDEXER_CTR}' to be healthy (timeout ${WAIT_TIMEOUT}s)..."
elapsed=0
while :; do
  health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${INDEXER_CTR}" 2>/dev/null || echo missing)"
  case "${health}" in
    healthy|none) break ;;
    missing) echo "ERROR: container '${INDEXER_CTR}' disappeared while waiting." >&2; exit 1 ;;
  esac
  if [ "${elapsed}" -ge "${WAIT_TIMEOUT}" ]; then
    echo "ERROR: '${INDEXER_CTR}' not healthy after ${WAIT_TIMEOUT}s (status: ${health})." >&2
    exit 1
  fi
  sleep 5
  elapsed=$((elapsed + 5))
done
echo "Indexer is up (health: ${health:-healthy})."

echo "Copying OIDC security config into ${INDEXER_CTR}:${SEC_DST_DIR}/ ..."
docker cp "${SEC_SRC_DIR}/config.yml" "${INDEXER_CTR}:${SEC_DST_DIR}/config.yml"
docker cp "${SEC_SRC_DIR}/roles_mapping.yml" "${INDEXER_CTR}:${SEC_DST_DIR}/roles_mapping.yml"

# Push ONLY the two changed objects (config + rolesmapping). Pushing the whole
# directory (-cd) would also re-push internal_users.yml and friends, which is
# unnecessary here and risks racing the entrypoint's hash templating.
run_securityadmin() {
  local file="$1" type="$2"
  docker exec "${INDEXER_CTR}" bash -c "
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk
    bash ${TOOLS_DIR}/securityadmin.sh \
      -f ${SEC_DST_DIR}/${file} -t ${type} -icl -nhnv \
      -cacert ${CERT_DIR}/root-ca.pem \
      -cert   ${CERT_DIR}/admin.pem \
      -key    ${CERT_DIR}/admin-key.pem \
      -h localhost
  "
}

echo "Pushing security 'config' (openid_auth_domain) via securityadmin.sh ..."
run_securityadmin config.yml config
echo "Pushing security 'rolesmapping' (wazuh-admin -> all_access) via securityadmin.sh ..."
run_securityadmin roles_mapping.yml rolesmapping

cat <<DONE

Done. The indexer now accepts Keycloak OIDC bearer tokens (realm ngn-sip-lab).
Persisted in the .opendistro_security index: survives container restarts as
long as the wazuh_indexer_data volume persists. Re-run after 'make clean' or
any volume wipe. Verify with:
  https://localhost:5601 -> "Log in with Keycloak" -> lab-admin
DONE
