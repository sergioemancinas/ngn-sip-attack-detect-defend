#!/usr/bin/env bash
#
# Self-healing ossec.conf registration for the NGN-SIP Wazuh manager.
# Registers, idempotently and append-only, everything the manager needs that
# does NOT survive a fresh / --force-recreate:
#   1. the two project <localfile> entries (Kamailio SIP relay + Stage-1 ML), and
#   2. the Wazuh -> Shuffle <integration> block (SOAR forwarding).
#
# WHY THIS EXISTS
#   ossec.conf lives in the container's WRITABLE LAYER — deliberately not
#   bind-mounted, so the pinned 4.14.5 default config and the agent client.keys
#   (both under /var/ossec/etc) survive image pulls. The trade-off: every fresh
#   manager starts from the stock ossec.conf and loses these project additions.
#
#   The two <localfile> entries drive:
#     - /var/ossec/logs/ngnsec/kamailio-sec.log (syslog) -> SIP correlation
#       rules 100100..100199 (siem/wazuh/rules/sip_rules.xml)
#     - /var/ossec/logs/ml/stage1.json          (json)   -> ML rules
#       100150/100151 (siem/wazuh/rules/ml_rules.xml)
#
#   The <integration> block forwards those SIP detections to the Shuffle SOAR
#   (soar/shuffle/workflows/sip_response_orchestration.json). It is self-healed
#   here because pushing it through the Wazuh API (install_integrations.sh) is
#   asynchronous and racy across a container recreate: PUT /manager/configuration
#   returns 200 but the on-disk write can lag or be lost across the accompanying
#   restart. Writing the file directly, before wazuh-control start, is
#   deterministic. install_integrations.sh remains valid for an already-running
#   manager (API-driven update without a container restart).
#
# HOW IT RUNS
#   The stock wazuh-manager image (s6-overlay) runs every /entrypoint-scripts/*.sh
#   in lexicographic order from /etc/cont-init.d/2-manager, BEFORE
#   `wazuh-control start`. docker-compose.wazuh.yml mounts this file read-only at
#   /entrypoint-scripts/10-register-ngn-localfiles.sh, so it runs on every
#   container start and the manager comes up fully configured — no restart, no
#   manual step. Append-only + idempotent: it never rewrites existing config,
#   only inserts a missing block before the first </ossec_config>, so the pinned
#   default config and client.keys are preserved.
set -uo pipefail

CONF=/var/ossec/etc/ossec.conf
# Read-only copy of siem/wazuh/integrations/wazuh_shuffle_integration.xml mounted
# by docker-compose.wazuh.yml. Optional: if absent, only localfiles are handled.
INTEGRATION_SRC=/ngn-bootstrap/wazuh_shuffle_integration.xml

log() { echo "[ngn-localfiles] $*"; }

if [ ! -f "$CONF" ]; then
  log "ossec.conf not found at $CONF; skipping (manager init will create it)"
  exit 0
fi

# Ensure the log directories exist with manager ownership so logcollector does
# not emit spurious "file not found" noise before the relay / scorer sidecars
# create them. Non-fatal if it fails.
mkdir -p /var/ossec/logs/ngnsec /var/ossec/logs/ml 2>/dev/null || true
chown wazuh:wazuh /var/ossec/logs/ngnsec /var/ossec/logs/ml 2>/dev/null || true

# Insert stdin lines before the FIRST </ossec_config> only, passing everything
# else through verbatim. $1 = human label, $2 = unique marker already present ->
# skip. The block to insert is read from a temp file passed as $3.
splice_before_first_close() {
  block_file="$1"
  awk -v block_file="$block_file" '
    /<\/ossec_config>/ && !d {
      while ((getline line < block_file) > 0) print line
      close(block_file)
      d=1
    }
    { print }
  ' "$CONF" > "$CONF.ngnnew" && [ -s "$CONF.ngnnew" ]
}

commit_new() {
  mv "$CONF.ngnnew" "$CONF"
  chown root:wazuh "$CONF" 2>/dev/null || true
  chmod 640 "$CONF" 2>/dev/null || true
}

add_localfile() {
  fmt="$1"; loc="$2"
  if grep -qF "$loc" "$CONF"; then
    log "localfile already registered: $loc"
    return 0
  fi
  cp -a "$CONF" "$CONF.ngnbak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
  tmp=$(mktemp)
  {
    echo "  <localfile>"
    echo "    <log_format>${fmt}</log_format>"
    echo "    <location>${loc}</location>"
    echo "  </localfile>"
  } > "$tmp"
  if splice_before_first_close "$tmp"; then
    commit_new
    log "localfile registered: $loc"
  else
    rm -f "$CONF.ngnnew"
    log "WARN failed to register localfile $loc; leaving ossec.conf unchanged"
  fi
  rm -f "$tmp"
}

add_integration() {
  [ -f "$INTEGRATION_SRC" ] || { log "integration source not mounted; skipping SOAR block"; return 0; }
  # Idempotency marker: the hook_url is unique to this integration.
  hook=$(grep -o 'http://shuffle-backend[^<]*' "$INTEGRATION_SRC" | head -1)
  if [ -n "$hook" ] && grep -qF "$hook" "$CONF"; then
    log "shuffle integration already registered"
    return 0
  fi
  # Extract only the <integration>...</integration> element (drop the file's
  # outer <ossec_config> wrapper, which exists only for editor linting).
  tmp=$(mktemp)
  awk '/<integration>/{f=1} f{print} /<\/integration>/{f=0}' "$INTEGRATION_SRC" > "$tmp"
  if [ ! -s "$tmp" ]; then
    log "WARN integration source had no <integration> block; skipping"
    rm -f "$tmp"; return 0
  fi
  cp -a "$CONF" "$CONF.ngnbak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
  if splice_before_first_close "$tmp"; then
    commit_new
    log "shuffle integration registered"
  else
    rm -f "$CONF.ngnnew"
    log "WARN failed to register shuffle integration; leaving ossec.conf unchanged"
  fi
  rm -f "$tmp"
}

add_localfile syslog /var/ossec/logs/ngnsec/kamailio-sec.log
add_localfile json   /var/ossec/logs/ml/stage1.json
add_integration

log "done"
exit 0
