#!/usr/bin/env bash
# Toll fraud: premium-prefix dialplan abuse attempt through Kamailio.
# MITRE: T1496 (Resource Hijacking)
# Detection: premium-rate INVITE URI from a lab SIPp user agent.
# FP scenarios: authorized telecom routing tests using premium or international prefixes.
# Author: ngn-sip-detect-defend - Date: 2026-05-12

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

NETWORK="${ATTACK_NETWORK:-ngn-sip_sip_lab}"
SIPP_IMAGE="ngn-sip/sipp:3.7.3"
REQUESTED_TARGET_HOST="${TARGET_HOST:-kamailio}"
TARGET_PORT="${TARGET_PORT:-5060}"
PREMIUM_NUMBER="${PREMIUM_NUMBER:-+19005550123}"
CALLER_USER="${CALLER_USER:-1000}"
LOCAL_PORT="${LOCAL_PORT:-5076}"
CONTAINER_NAME="ngn-dialplan-abuse-$$"

case "${REQUESTED_TARGET_HOST}" in
  kamailio|127.0.0.1|localhost)
    TARGET_HOST="kamailio"
    ;;
  *)
    echo "refusing non-lab SIP target: ${REQUESTED_TARGET_HOST}" >&2
    exit 2
    ;;
esac

if [ "${TARGET_PORT}" != "5060" ]; then
  echo "refusing non-lab SIP port: ${TARGET_PORT}" >&2
  exit 2
fi

if [[ ! "${PREMIUM_NUMBER}" =~ ^\+1900[0-9]{7}$ ]]; then
  echo "PREMIUM_NUMBER must match +1900xxxxxxx, got: ${PREMIUM_NUMBER}" >&2
  exit 2
fi

DIAL_URI="sip:${PREMIUM_NUMBER}@${TARGET_HOST}"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> SIPp dialplan abuse INVITE ${DIAL_URI} via ${TARGET_HOST}:${TARGET_PORT}"

docker run -d \
  --name "${CONTAINER_NAME}" \
  --network "${NETWORK}" \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:mode=1777,size=16m \
  --tmpfs /work:uid=10001,gid=10001,mode=0755,size=16m \
  --pids-limit 100 \
  --memory 128m \
  --cpus 0.25 \
  --entrypoint sleep \
  "${SIPP_IMAGE}" \
  infinity >/dev/null

ATTACKER_IP="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${CONTAINER_NAME}")"

docker exec -i "${CONTAINER_NAME}" sh -c 'cat > /tmp/dialplan_abuse.xml' <<SCENARIO
<?xml version="1.0" encoding="ISO-8859-1" ?>
<scenario name="Premium-prefix dialplan abuse INVITE">
  <send retrans="500">
    <![CDATA[
INVITE ${DIAL_URI} SIP/2.0
Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
From: <sip:${CALLER_USER}@${TARGET_HOST}>;tag=[call_number]
To: <${DIAL_URI}>
Call-ID: [call_id]
CSeq: 1 INVITE
Contact: <sip:${CALLER_USER}@[local_ip]:[local_port]>
Max-Forwards: 70
User-Agent: ngn-sip-dialplan-abuse
Content-Length: 0

    ]]>
  </send>
  <pause milliseconds="1000"/>
</scenario>
SCENARIO

sipp_rc=0
docker exec "${CONTAINER_NAME}" /usr/local/bin/sipp "${TARGET_HOST}:${TARGET_PORT}" \
  -sf /tmp/dialplan_abuse.xml \
  -m 1 \
  -r 1 \
  -l 1 \
  -i "${ATTACKER_IP}" \
  -p "${LOCAL_PORT}" \
  -timeout 5 \
  -trace_err \
  -nostdin || sipp_rc=$?

if [ "${sipp_rc}" -ne 0 ]; then
  echo "SIPp exited rc=${sipp_rc}; continuing to label the attempted dialplan abuse." >&2
fi

python -m attacks.orchestrator.label_emitter \
  "${ATTACKER_IP:-127.0.0.1}" \
  "dialplan_abuse" \
  "T1496" \
  "tollfraud" \
  "premium_uri=${DIAL_URI}"
