#!/bin/sh
# kamailio-autoban: the automated active-response ("Defend") stage of the ingress
# pipeline. Polls ClickHouse for sources of HIGH-severity SIP detections
# (rule_level >= 10 in the 100100..100199 range: scanner, flood, brute-force) and
# bans each at the Kamailio edge by setting ban_table via kamcmd, so the
# DROP_IF_BANNED route drops all further traffic from that source.
#
# This is the lab-grade closed loop (detect -> decide -> respond at the SBC). The
# production-grade equivalent is native Wazuh active-response on the host agent
# or a Shuffle SOAR playbook; this sidecar achieves the same outcome with only
# the Docker socket (no host root, no manager image change), consistent with the
# kamailio-sec-relay sidecar.
#
# Tunables (env): MIN_LEVEL, WINDOW_SECONDS, POLL_SECONDS.
# To pause for clean measurement campaigns: `docker stop kamailio-autoban`.
set -u
KAMAILIO="${KAMAILIO_CTR:-ngn-sip-kamailio-1}"
CLICKHOUSE="${CLICKHOUSE_CTR:-ngn-sip-clickhouse-1}"
HTABLE="${HTABLE_NAME:-ban_table}"
ALLOW_HTABLE="${ALLOW_HTABLE:-ban_allowlist}"
MIN_LEVEL="${MIN_LEVEL:-10}"
WINDOW_SECONDS="${WINDOW_SECONDS:-180}"
POLL_SECONDS="${POLL_SECONDS:-5}"
SEEN=/tmp/autoban.seen; : > "$SEEN"

# ML/LLM-driven banning (2026-07-01). In addition to the deterministic Wazuh
# high-severity trigger, the autoban can act on the Stage-1 ML attack verdict
# (ngn_sip.ml_scores) and the Stage-2 LLM malicious verdict (ngn_sip.llm_verdicts).
# Both are gated and thresholded so they can be toggled for clean measurement
# campaigns, and both are scoped to external sources only (RFC1918 excluded) so
# ML/LLM confidence cannot ban the internal test orchestrator; the never-ban
# allowlist still applies on top as the final safeguard.
ENABLE_ML_BAN="${ENABLE_ML_BAN:-1}"
ML_MIN_PROBA="${ML_MIN_PROBA:-0.90}"
ENABLE_LLM_BAN="${ENABLE_LLM_BAN:-1}"
LLM_MIN_CONF="${LLM_MIN_CONF:-0.70}"

# Never-ban allowlist (anti-spoofing safeguard, RFC 3261 Sec 26). SIP over UDP has a
# spoofable source address, so an attacker can forge a peer/internal IP to get it banned
# and DoS the stack via DROP_IF_BANNED (blocklist poisoning). We therefore (1) resolve the
# protected stack containers' IPs on the sip_lab network and skip them, (2) honor a static
# NEVER_BAN_IPS list, and (3) push the allowlist into Kamailio's ban_allowlist htable so the
# edge route refuses to drop a protected source even if its IP somehow reaches ban_table.
PROTECTED_CONTAINERS="${PROTECTED_CONTAINERS:-ngn-sip-asterisk-1 ngn-sip-kamailio-1 ngn-sip-rtpengine-1 ngn-sip-prometheus-1 ngn-sip-vector-1 ngn-sip-clickhouse-1 ngn-sip-kamailio-sec-relay-1 ngn-sip-postgres-1}"
NEVER_BAN_IPS="${NEVER_BAN_IPS:-127.0.0.1 ::1}"
ALLOWLIST=""

log() { printf '%s autoban %s\n' "$(date '+%Y/%m/%d %H:%M:%S')" "$*"; }

valid_ip() { printf '%s' "$1" | grep -qE '^[0-9A-Fa-f.:]+$'; }

# Ban audit trail in ClickHouse (design rule: response actions must be
# measurable, auditable, reversible). Every ban / protected-skip / rejected input is
# written to ngn_sip.ban_audit so the defend action has an evidence record.
ch() { docker exec "$CLICKHOUSE" sh -lc "clickhouse-client --user ngn --password \"\$CLICKHOUSE_PASSWORD\" -q \"$1\"" 2>/dev/null; }

audit_init() {
  ch "CREATE TABLE IF NOT EXISTS ngn_sip.ban_audit (event_time DateTime64(3) DEFAULT now64(3), src_ip String, action LowCardinality(String), reason String, min_level UInt16, ttl_seconds UInt32) ENGINE = MergeTree ORDER BY event_time TTL toDateTime(event_time) + INTERVAL 365 DAY"
}

audit() { # action src_ip reason
  # Neutralise injection from the src_ip field: the reject_invalid path passes an
  # unvalidated value, and ch() interpolates it through both a docker-exec sh -lc layer
  # and a ClickHouse SQL string. Strip everything but IP-literal characters, then
  # single-quote-escape the (hardcoded) reason. action ($1) is always a literal.
  _ipsafe=$(printf '%s' "$2" | tr -cd '0-9A-Fa-f.:_-' | cut -c1-64)
  _esc=$(printf '%s' "$3" | sed "s/'/''/g")
  ch "INSERT INTO ngn_sip.ban_audit (src_ip, action, reason, min_level, ttl_seconds) VALUES ('$_ipsafe','$1','$_esc',${MIN_LEVEL},3600)"
}

is_protected() {
  _ip="$1"
  for _a in $ALLOWLIST; do [ "$_a" = "$_ip" ] && return 0; done
  return 1
}

refresh_allowlist() {
  _acc="$NEVER_BAN_IPS"
  for _c in $PROTECTED_CONTAINERS; do
    _cip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$_c" 2>/dev/null)
    _acc="$_acc $_cip"
  done
  ALLOWLIST="$_acc"
  # Mirror the allowlist into Kamailio so DROP_IF_BANNED can honor it (defense in depth).
  for _a in $ALLOWLIST; do
    valid_ip "$_a" && docker exec "$KAMAILIO" /usr/sbin/kamcmd htable.sets "$ALLOW_HTABLE" "$_a" 1 >/dev/null 2>&1
  done
}

log "started (min_level=$MIN_LEVEL window=${WINDOW_SECONDS}s poll=${POLL_SECONDS}s ml_ban=$ENABLE_ML_BAN@${ML_MIN_PROBA} llm_ban=$ENABLE_LLM_BAN@${LLM_MIN_CONF})"
audit_init
refresh_allowlist
log "never-ban allowlist: $ALLOWLIST"

# Run a ClickHouse query inside the container and stream one IP per line.
chq() { docker exec "$CLICKHOUSE" sh -lc "clickhouse-client --user ngn --password \"\$CLICKHOUSE_PASSWORD\" -q \"$1\"" 2>/dev/null; }

# Apply the ban path to a stream of candidate IPs (stdin), tagging the audit
# record with the given reason. Same validation, allowlist, idempotent-ban, and
# audit machinery for every candidate source (Wazuh, ML, LLM).
process_stream() { # reason
  _reason="$1"
  while IFS= read -r ip; do
    [ -z "$ip" ] && continue
    # Reject anything that is not a bare IP literal before it reaches kamcmd
    # (parity with kamcmd_block.sh; prevents argument injection from alert data).
    if ! valid_ip "$ip"; then
      log "REJECTED non-IP literal '$ip'"
      audit reject_invalid "$ip" "not an IP literal"
      continue
    fi
    # Never ban a protected stack source, even if a verdict names it (spoofing guard).
    if is_protected "$ip"; then
      if ! grep -qxF "skip:$ip" "$SEEN" 2>/dev/null; then
        echo "skip:$ip" >> "$SEEN"
        log "SKIPPED protected source $ip (never-ban allowlist)"
        audit skip_protected "$ip" "in never-ban allowlist"
      fi
      continue
    fi
    # Re-issue the ban every poll while the source stays in the detection window:
    # htable.sets is idempotent and refreshes ban_table's autoexpire TTL, so a
    # persistent attacker stays blocked. Log/audit only the first time to avoid spam.
    if docker exec "$KAMAILIO" /usr/sbin/kamcmd htable.sets "$HTABLE" "$ip" 1 >/dev/null 2>&1; then
      if ! grep -qxF "$ip" "$SEEN" 2>/dev/null; then
        echo "$ip" >> "$SEEN"
        log "BANNED $ip ($_reason)"
        audit ban "$ip" "$_reason"
      fi
    else
      log "ban FAILED for $ip (kamcmd error)"
      audit ban_failed "$ip" "kamcmd error"
    fi
  done
}

# Candidate sources. Wazuh is the deterministic backstop (as before). ML and LLM
# are scoped to external sources (RFC1918 excluded) so a high-confidence verdict
# cannot ban the internal test orchestrator; the allowlist still applies on top.
EXTERNAL_ONLY="ip NOT LIKE '10.%' AND ip NOT LIKE '172.%' AND ip NOT LIKE '192.168.%' AND ip NOT LIKE '127.%'"
Q_WAZUH="SELECT DISTINCT replaceOne(toString(srcip), '::ffff:', '') FROM ngn_sip.wazuh_alerts WHERE rule_id BETWEEN 100100 AND 100199 AND rule_level >= ${MIN_LEVEL} AND alert_time > now() - INTERVAL ${WINDOW_SECONDS} SECOND AND srcip != '' FORMAT TabSeparated"
Q_ML="SELECT DISTINCT ip FROM (SELECT replaceOne(toString(src_ip), '::ffff:', '') ip FROM ngn_sip.ml_scores WHERE predicted_class NOT IN ('benign','') AND proba >= ${ML_MIN_PROBA} AND scored_at > now() - INTERVAL ${WINDOW_SECONDS} SECOND) WHERE ${EXTERNAL_ONLY} FORMAT TabSeparated"
Q_LLM="SELECT DISTINCT ip FROM (SELECT replaceOne(toString(src_ip), '::ffff:', '') ip FROM ngn_sip.llm_verdicts WHERE lower(verdict) IN ('malicious','attack','block') AND confidence >= ${LLM_MIN_CONF} AND verdict_time > now() - INTERVAL ${WINDOW_SECONDS} SECOND) WHERE ${EXTERNAL_ONLY} FORMAT TabSeparated"

while true; do
  refresh_allowlist
  chq "$Q_WAZUH" | process_stream "high-severity SIP detection rule_level>=${MIN_LEVEL}"
  [ "$ENABLE_ML_BAN"  = "1" ] && chq "$Q_ML"  | process_stream "Stage-1 ML attack verdict proba>=${ML_MIN_PROBA}"
  [ "$ENABLE_LLM_BAN" = "1" ] && chq "$Q_LLM" | process_stream "Stage-2 LLM malicious verdict conf>=${LLM_MIN_CONF}"
  sleep "$POLL_SECONDS"
done
