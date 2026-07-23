#!/usr/bin/env bash
# Injection: sippts smap-style INVITE probe against the local Kamailio lab target.
# MITRE: T1190 (Exploit Public-Facing Application)
# Expected detections: Suricata SIDs 1000003, 1000007, and 1000008.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SIPP_IMAGE="${SIPP_IMAGE:-ngn-sip/sipp:3.7.3}"
NETWORK="${ATTACK_NETWORK:-ngn-sip_sip_lab}"
RAW_TARGET_HOST="${TARGET_HOST:-kamailio}"
TARGET_PORT="${TARGET_PORT:-5060}"
EXTENSION="${EXTENSION:-1000}"
CALLS="${CALLS:-5}"
RATE="${RATE:-1}"
OUTPUT_DIR="${OUTPUT_DIR:-./data/pcaps}"
LABEL_SRC_IP="${ATTACKER_SRC_IP:-127.0.0.1}"

if [ "${RAW_TARGET_HOST}" = "127.0.0.1" ] || [ "${RAW_TARGET_HOST}" = "localhost" ]; then
  TARGET_HOST="kamailio"
else
  TARGET_HOST="${RAW_TARGET_HOST}"
fi

require_uint() {
  local name="$1"
  local value="$2"
  if [ -z "${value}" ] || [[ "${value}" == *[!0-9]* ]]; then
    echo "${name} must be a positive integer: ${value}" >&2
    exit 2
  fi
}

require_uint "TARGET_PORT" "${TARGET_PORT}"
require_uint "EXTENSION" "${EXTENSION}"
require_uint "CALLS" "${CALLS}"
require_uint "RATE" "${RATE}"

if [ "${TARGET_PORT}" -le 0 ] || [ "${TARGET_PORT}" -gt 65535 ]; then
  echo "TARGET_PORT out of range: ${TARGET_PORT}" >&2
  exit 2
fi

if [ "${CALLS}" -le 0 ] || [ "${RATE}" -le 0 ]; then
  echo "CALLS and RATE must be greater than zero" >&2
  exit 2
fi

if [ "${NETWORK}" != "ngn-sip_sip_lab" ] && [ "${NETWORK}" != "sip_lab" ]; then
  echo "refusing non-lab Docker network: ${NETWORK}" >&2
  exit 2
fi

if [ "${TARGET_HOST}" != "kamailio" ] || [ "${TARGET_PORT}" != "5060" ]; then
  echo "refusing target outside local Kamailio lab: ${TARGET_HOST}:${TARGET_PORT}" >&2
  exit 2
fi

if ! docker network inspect "${NETWORK}" >/dev/null 2>&1; then
  echo "Docker network not found: ${NETWORK}" >&2
  exit 1
fi

if ! docker image inspect "${SIPP_IMAGE}" >/dev/null 2>&1; then
  echo "SIPp image not found: ${SIPP_IMAGE}" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}/03_injection"

echo "==> SIPp sippts smap-style INVITE ${TARGET_HOST}:${TARGET_PORT} ext=${EXTENSION} calls=${CALLS} rate=${RATE}/s network=${NETWORK}"
docker run --rm -i \
  --network "${NETWORK}" \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --read-only \
  --pids-limit 100 \
  --memory 128m \
  --cpus 0.25 \
  --tmpfs /tmp:mode=1777,size=16m \
  --tmpfs /work:uid=10001,gid=10001,mode=0755,size=16m \
  -e TARGET_HOST="${TARGET_HOST}" \
  -e TARGET_PORT="${TARGET_PORT}" \
  -e CALLS="${CALLS}" \
  -e RATE="${RATE}" \
  --entrypoint /bin/sh \
  "${SIPP_IMAGE}" \
  -ec 'cat > /tmp/sippts_smap_invite.xml
exec /usr/local/bin/sipp "${TARGET_HOST}:${TARGET_PORT}" \
  -sf /tmp/sippts_smap_invite.xml \
  -m "${CALLS}" \
  -r "${RATE}" \
  -t u1 \
  -nostdin' <<XML
<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="sippts smap INVITE">
  <send>
    <![CDATA[
INVITE sip:${EXTENSION}@[remote_ip]:[remote_port] SIP/2.0
Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
From: <sip:smap-[call_number]@[local_ip]>;tag=smap[call_number]
To: <sip:${EXTENSION}@[remote_ip]>
Call-ID: smap-[call_id]
CSeq: smap INVITE
Max-Forwards: 70
User-Agent: sippts smap
Content-Length: 0

    ]]>
  </send>
</scenario>
XML

PYTHONPATH="${REPO_ROOT}${PYTHONPATH:+:${PYTHONPATH}}" python3 -m attacks.orchestrator.label_emitter \
  "${LABEL_SRC_IP}" \
  "sippts_smap_invite" \
  "T1190" \
  "injection" \
  "SIPp smap-style malformed INVITE via ${NETWORK} to ${TARGET_HOST}:${TARGET_PORT}; ext=${EXTENSION}; calls=${CALLS}; rate=${RATE}/s"
