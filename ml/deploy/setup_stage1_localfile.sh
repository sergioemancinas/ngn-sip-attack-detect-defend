#!/usr/bin/env bash
#
# Register the Stage 1 ML scorer log as a Wazuh manager <localfile> so rules
# 100150/100151 (ml_rules.xml) fire on live Stage 1 detections. Run once
# against a running manager; it is idempotent. Mirrors
# siem/wazuh/setup_kamailio_localfile.sh (same rationale below).
#
# Why a script and not a compose mount: the manager's localfiles live in
# /var/ossec/etc/ossec.conf, which is in the container's writable layer (this
# project deliberately does not bind-mount the whole ossec.conf to avoid
# freezing the pinned 4.14.5 default config, and recreating the manager would
# drop the agent client.keys that also live under /var/ossec/etc). Applying
# the localfile in place keeps the running manager authoritative; this script
# reproduces it after any manual rebuild.
#
# Pipeline: ml/deploy/scorer.py (stage1-scorer container) -> writes
# wazuh_manager_logs:/var/ossec/logs/ml/stage1.json (shared volume, see
# docker-compose.ml.yml stage1-scorer.volumes) -> this <localfile>
# -> logcollector (log_format json) -> analysisd -> rules 100150/100151
# (ml/deploy/ml_rules.xml, loaded via wazuh-manager's
# /wazuh-config-mount/etc/rules mount) -> alerts.json -> ml/stage2/worker.py
# (stage2-worker container, tails the same shared volume) -> ngn_sip.llm_verdicts.
set -euo pipefail

# Container name follows COMPOSE_PROJECT_NAME (default ngn-sip); override by
# passing the name as $1.
MANAGER="${1:-${COMPOSE_PROJECT_NAME:-ngn-sip}-wazuh-manager-1}"

# NOTE: run the remote logic via `docker exec <ctr> sh -c '<script>'` rather
# than `sh -s` over a heredoc — the latter silently produced no output and did
# not apply under some Docker/BuildKit stdin handling. Single-quoted body, so
# it is the container's shell that expands the vars, not the host.
docker exec "$MANAGER" sh -c '
set -e
CONF=/var/ossec/etc/ossec.conf
LOGPATH=/var/ossec/logs/ml/stage1.json
if grep -q "ml/stage1.json" "$CONF"; then
  echo "localfile already registered"
else
  cp "$CONF" "$CONF.bak.$(date +%Y%m%d%H%M%S)"
  awk "/<\/ossec_config>/ && !d {
        print \"  <localfile>\";
        print \"    <log_format>json</log_format>\";
        print \"    <location>$LOGPATH</location>\";
        print \"  </localfile>\";
        d=1
      } {print}" "$CONF" > "$CONF.new"
  mv "$CONF.new" "$CONF"
  echo "localfile added"
fi
/var/ossec/bin/wazuh-control restart >/dev/null 2>&1
echo "manager restarted; Stage 1 ML localfile active"
'
