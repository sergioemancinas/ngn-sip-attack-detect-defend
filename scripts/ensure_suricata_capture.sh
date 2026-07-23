#!/bin/sh
# ensure-suricata-capture: watchdog for Suricata EVE freshness when Kamailio
# container restarts recreate the shared network namespace. Suricata pinned via
# network_mode: container:<kamailio> loses eth0 and stops writing eve.json.
#
# Run manually or via cron on the campus VM. Idempotent and safe to re-run.
#
# Tunables (env): SURICATA_CTR, STALE_SECONDS, EVE_HOST_PATH, LOG_TAIL_LINES.
#
# Crontab example (every 2 minutes):
#   */2 * * * * /home/deploy/sip-attack-detect-defend/scripts/ensure_suricata_capture.sh >>/var/log/suricata-capture-watchdog.log 2>&1
set -u

SURICATA="${SURICATA_CTR:-ngn-sip-suricata-1}"
STALE_SECONDS="${STALE_SECONDS:-300}"
EVE_HOST="${EVE_HOST_PATH:-/var/lib/docker/volumes/ngn-sip-ids_suricata_logs/_data/eve.json}"
EVE_IN_CTR="/var/log/suricata/eve.json"
LOG_TAIL_LINES="${LOG_TAIL_LINES:-200}"

log() { printf '%s suricata-capture %s\n' "$(date '+%Y/%m/%d %H:%M:%S')" "$*"; }

now_epoch() { date +%s; }

eve_mtime() {
  if [ -f "$EVE_HOST" ]; then
    stat -c %Y "$EVE_HOST" 2>/dev/null && return 0
  fi
  docker exec "$SURICATA" stat -c %Y "$EVE_IN_CTR" 2>/dev/null
}

eve_size() {
  if [ -f "$EVE_HOST" ]; then
    stat -c %s "$EVE_HOST" 2>/dev/null && return 0
  fi
  docker exec "$SURICATA" stat -c %s "$EVE_IN_CTR" 2>/dev/null
}

capture_stale() {
  _now=$(now_epoch)
  _mtime=$(eve_mtime) || return 0
  _age=$(( _now - _mtime ))
  [ "$_age" -gt "$STALE_SECONDS" ]
}

reopen_error_in_logs() {
  # Check ONLY logs since the container last started. docker retains pre-restart lines, so a
  # --tail/--since-window check keeps matching the old "can't reopen" warning and restarts on
  # every run (a restart loop). Logs-since-start reflect the CURRENT run, so a healthy restart
  # clears it; if capture is still detached after the restart, the new run logs it again.
  _started="$(docker inspect -f '{{.State.StartedAt}}' "$SURICATA" 2>/dev/null)"
  [ -z "$_started" ] && return 1
  docker logs --since "$_started" "$SURICATA" 2>&1 \
    | grep -q "can't reopen interface"
}

restart_suricata() {
  log "restarting $SURICATA (capture stall detected)"
  # `docker restart` recovers a stall only when Kamailio was RESTARTED (same
  # container id). When Kamailio was RECREATED, Suricata's stored
  # network_mode: container:<old-id> is dead and restart fails to rejoin it
  # ("No such container"). Fall back to force-recreate so Suricata re-resolves
  # the Kamailio name to the live netns.
  if ! docker restart "$SURICATA" >/dev/null 2>&1; then
    log "restart failed (Kamailio likely recreated); force-recreating $SURICATA"
    docker compose -f docker-compose.ids.yml up -d --force-recreate "$SURICATA" >/dev/null 2>&1
  fi
}

if ! docker inspect "$SURICATA" >/dev/null 2>&1; then
  log "STATUS: FAILED container $SURICATA not found"
  exit 1
fi

_stale=0
_reopen=0
_age=0
_size=0

if _mtime=$(eve_mtime); then
  _age=$(( $(now_epoch) - _mtime ))
else
  _stale=1
  log "eve.json missing or unreadable (host=$EVE_HOST container=$EVE_IN_CTR)"
fi

if [ "$_stale" -eq 0 ] && [ "$_age" -gt "$STALE_SECONDS" ]; then
  _stale=1
fi

if reopen_error_in_logs; then
  _reopen=1
fi

_size=$(eve_size 2>/dev/null || echo 0)

# Restart ONLY on the real capture-detached signal (recent "can't reopen interface").
# eve.json staleness alone is NOT a failure: an idle stack with no SIP traffic has a stale
# eve.json but healthy capture, restarting on that would loop and prevent stabilisation.
if [ "$_reopen" -eq 0 ]; then
  if [ "$_stale" -eq 1 ]; then
    log "STATUS: OK capture attached, eve.json idle (age=${_age}s, no recent traffic; size=${_size})"
  else
    log "STATUS: OK capture fresh (eve.json age=${_age}s size=${_size})"
  fi
  exit 0
fi

_reason="recent logs show can't reopen interface (capture detached from Kamailio netns)"

if restart_suricata; then
  log "STATUS: REMEDIATED restarted $SURICATA (${_reason})"
  exit 0
fi

log "STATUS: FAILED could not restart $SURICATA (${_reason})"
exit 1
