#!/bin/sh
# Wazuh active-response: ban a source IP via Kamailio htable ban_table.
#
# RECONCILIATION (single source of truth): the DEPLOYED ban actuator is
# siem/wazuh/active-response/autoban_loop.sh (the kamailio-autoban sidecar that polls
# ClickHouse and is hardened with the never-ban allowlist + strict IP validation). THIS
# script is the alternative native-Wazuh-active-response actuator: it is NOT wired into any
# <active-response>/<command> block by default, so it does not run in the deployed stack.
# Keep exactly one path live. To use this one instead, add a Wazuh <active-response> block
# triggering on the rules below and disable autoban_loop.sh; otherwise this is reference
# only. Its strict ^[0-9A-Fa-f.:]+$ IP validation has been ported into autoban_loop.sh.
#
# Trigger: rules 100102 / 100103 / 100105 / 100108 (high-confidence brute force, flood).
# Wazuh AR contract: command sent on stdin as JSON; field "command" is "add" or "delete".
# Manual test (example):
#   echo '{"command":"add","parameters":{"alert":{"data":{"srcip":"10.0.0.5"}}}}' | ./kamcmd_block.sh
# MITRE alignment: response action for T1110, T1499. Caller is responsible for TTL policy.
# Deployment notes:
#   - Local Compose: this script runs inside wazuh-manager; reaches kamailio container by name.
#   - Campus VM: kamailio is on the host, this script runs on the host via Wazuh agent AR.
#     Switch the docker-exec branch to a direct kamcmd Unix-socket call there.
# Author: ngn-sip-detect-defend - Date: 2026-04-25

set -eu

LOG_FILE="${WAZUH_AR_LOG:-/var/ossec/logs/active-responses.log}"
KAMAILIO_HOST="${KAMAILIO_HOST:-kamailio}"
HTABLE_NAME="${HTABLE_NAME:-ban_table}"
PROTECTED_CONTAINERS="${PROTECTED_CONTAINERS:-ngn-sip-asterisk-1 ngn-sip-kamailio-1 ngn-sip-rtpengine-1 ngn-sip-prometheus-1 ngn-sip-vector-1 ngn-sip-clickhouse-1 ngn-sip-kamailio-sec-relay-1 ngn-sip-postgres-1}"
NEVER_BAN_IPS="${NEVER_BAN_IPS:-127.0.0.1 ::1}"

log() {
  printf '%s ngn-sip ar=kamcmd_block %s\n' "$(date '+%Y/%m/%d %H:%M:%S')" "$*" >> "$LOG_FILE" 2>/dev/null || true
}

PAYLOAD="$(cat || true)"
if [ -z "$PAYLOAD" ]; then
  log "no payload on stdin; aborting"
  exit 1
fi

SRCIP="$(printf '%s' "$PAYLOAD" | sed -nE 's/.*"srcip"\s*:\s*"([^"]+)".*/\1/p' | head -n1)"
COMMAND="$(printf '%s' "$PAYLOAD" | sed -nE 's/.*"command"\s*:\s*"([^"]+)".*/\1/p' | head -n1)"

if [ -z "$SRCIP" ]; then
  log "no srcip in payload; aborting"
  exit 1
fi

# Validate SRCIP is a bare IPv4/IPv6 literal before acting. The field is parsed
# from alert JSON; reject anything with shell metacharacters or whitespace so a
# malformed or spoofed value cannot reach kamcmd as an unexpected argument.
if ! printf '%s' "$SRCIP" | grep -qE '^[0-9A-Fa-f.:]+$'; then
  log "srcip '$SRCIP' is not a valid IP literal; aborting"
  exit 1
fi

is_protected() {
  _ip="$1"
  for _a in $NEVER_BAN_IPS; do
    [ "$_a" = "$_ip" ] && return 0
  done
  for _c in $PROTECTED_CONTAINERS; do
    _cip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$_c" 2>/dev/null)
    for _a in $_cip; do
      [ -n "$_a" ] && [ "$_a" = "$_ip" ] && return 0
    done
  done
  return 1
}

case "${COMMAND:-add}" in
  delete)
    if command -v kamcmd >/dev/null 2>&1; then
      kamcmd htable.delete "$HTABLE_NAME" "$SRCIP" >/dev/null 2>&1 || true
      log "unbanned $SRCIP via local kamcmd"
    else
      docker exec "$KAMAILIO_HOST" kamcmd htable.delete "$HTABLE_NAME" "$SRCIP" >/dev/null 2>&1 || true
      log "unbanned $SRCIP via docker exec"
    fi
    exit 0
    ;;
  add|*)
    if is_protected "$SRCIP"; then
      log "skipped protected $SRCIP"
      exit 0
    fi
    if command -v kamcmd >/dev/null 2>&1; then
      if kamcmd htable.sets "$HTABLE_NAME" "$SRCIP" 1 >/dev/null 2>&1; then
        log "banned $SRCIP via local kamcmd"
        exit 0
      fi
    fi
    if docker exec "$KAMAILIO_HOST" kamcmd htable.sets "$HTABLE_NAME" "$SRCIP" 1 >/dev/null 2>&1; then
      log "banned $SRCIP via docker exec"
      exit 0
    fi
    log "kamcmd htable.sets failed for $SRCIP - check ban_table htable definition in modules/htable.cfg"
    exit 1
    ;;
esac
