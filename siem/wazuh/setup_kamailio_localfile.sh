#!/usr/bin/env bash
#
# Register the Kamailio NGN-SEC relay file as a Wazuh manager <localfile> so the
# SIP correlation rules (sip_rules.xml, ids 100100..100199) fire on live attack
# traffic. Run once against a running manager; it is idempotent.
#
# Why a script and not a compose mount: the manager's localfiles live in
# /var/ossec/etc/ossec.conf, which is in the container's writable layer (this
# project deliberately does not bind-mount the whole ossec.conf to avoid
# freezing the pinned 4.14.5 default config, and recreating the manager would
# drop the agent client.keys that also live under /var/ossec/etc). Applying the
# localfile in place keeps the running manager authoritative; this script
# reproduces it after any manual rebuild.
#
# Pipeline: Kamailio (NGN-SEC xlog) -> kamailio-sec-relay sidecar (syslog
# reformat) -> wazuh_manager_logs:/var/ossec/logs/ngnsec/kamailio-sec.log
# -> this <localfile> -> logcollector -> analysisd -> alerts.json -> Vector
# -> ClickHouse ngn_sip.wazuh_alerts.
set -euo pipefail

# Container name follows COMPOSE_PROJECT_NAME (default ngn-sip); override via $1.
MANAGER="${1:-${COMPOSE_PROJECT_NAME:-ngn-sip}-wazuh-manager-1}"

# NOTE: run via `docker exec <ctr> sh -c '<script>'`, NOT `sh -s` over a
# heredoc. Without -i, docker exec does not attach stdin, so the heredoc is
# silently discarded and sh -s runs an empty script (exit 0, registers
# nothing). Single-quoted body -> the container's shell expands the vars.
docker exec "$MANAGER" sh -c '
set -e
CONF=/var/ossec/etc/ossec.conf
LOGPATH=/var/ossec/logs/ngnsec/kamailio-sec.log
if grep -q "ngnsec/kamailio-sec.log" "$CONF"; then
  echo "localfile already registered"
else
  cp "$CONF" "$CONF.bak.$(date +%Y%m%d%H%M%S)"
  awk "/<\/ossec_config>/ && !d {
        print \"  <localfile>\";
        print \"    <log_format>syslog</log_format>\";
        print \"    <location>$LOGPATH</location>\";
        print \"  </localfile>\";
        d=1
      } {print}" "$CONF" > "$CONF.new"
  mv "$CONF.new" "$CONF"
  echo "localfile added"
fi
/var/ossec/bin/wazuh-control restart >/dev/null 2>&1
echo "manager restarted; SIP localfile active"
'
