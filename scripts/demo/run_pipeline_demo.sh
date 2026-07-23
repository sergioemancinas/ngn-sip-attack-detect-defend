#!/usr/bin/env bash
# Demo-day live walkthrough: one labeled sippts recon attack through the full
# Kamailio -> Suricata/Wazuh -> Stage 1 ML -> Stage 2 LLM -> autoban -> SOAR
# pipeline. Read-only except the delegated attack step (labeled_attack_demo.sh).
#
# Run on the campus VM from the repo root (typically ~/sip-attack-detect-defend):
#   bash scripts/demo/run_pipeline_demo.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "${HOME}/sip-attack-detect-defend" ]; then
  REPO_ROOT="${HOME}/sip-attack-detect-defend"
elif [ -f "${SCRIPT_DIR}/../../.env" ]; then
  REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
else
  REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
fi

CH_CTR="${CLICKHOUSE_CTR:-ngn-sip-clickhouse-1}"
KAM_CTR="${KAMAILIO_CTR:-ngn-sip-kamailio-1}"
PAUSE_SEC="${DEMO_PAUSE_SEC:-3}"
ML_WAIT_SEC="${DEMO_ML_WAIT_SEC:-120}"
BAN_WAIT_SEC="${DEMO_BAN_WAIT_SEC:-45}"

P="$(grep ^CLICKHOUSE_PASSWORD= "${REPO_ROOT}/.env" 2>/dev/null | cut -d= -f2- || true)"
if [ -z "${P}" ] && [ -f .env ]; then
  P="$(grep ^CLICKHOUSE_PASSWORD= .env | cut -d= -f2-)"
fi
if [ -z "${P}" ]; then
  echo "ERROR: CLICKHOUSE_PASSWORD not found in ${REPO_ROOT}/.env" >&2
  exit 1
fi

q() {
  docker exec "${CH_CTR}" clickhouse-client --user ngn --password "${P}" -q "$1"
}

banner() {
  printf '\n'
  printf '================================================================\n'
  printf '  %s\n' "$1"
  printf '================================================================\n'
}

subheading() {
  printf '\n--- %s ---\n' "$1"
}

ip_sql() {
  printf "replaceOne(toString(%s), '::ffff:', '') = '%s'" "$1" "$2"
}

count_for_ip() {
  local table="$1" col="$2" ip="$3" time_col="${4:-}"
  local where
  where="$(ip_sql "${col}" "${ip}")"
  if [ -n "${time_col}" ]; then
    where="${where} AND ${time_col} >= now() - INTERVAL 15 MINUTE"
  fi
  q "SELECT count() FROM ngn_sip.${table} WHERE ${where}" 2>/dev/null || echo 0
}

wait_for_count() {
  local label="$1" table="$2" col="$3" ip="$4" max_sec="$5"
  local time_col="${6:-}"
  local n=0 elapsed=0
  while [ "${elapsed}" -lt "${max_sec}" ]; do
    n="$(count_for_ip "${table}" "${col}" "${ip}" "${time_col}")"
    if [ "${n:-0}" -gt 0 ] 2>/dev/null; then
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  return 1
}

# Stage latches for the summary line
LIT_SIP=0
LIT_SURICATA=0
LIT_WAZUH=0
LIT_ML=0
LIT_LLM=0
LIT_BAN_AUDIT=0
LIT_BAN_TABLE=0
LIT_SOAR=0

banner 'NGN SIP ATTACK-DETECT-DEFEND | END-TO-END PIPELINE DEMO'
printf 'Repo: %s | ClickHouse: %s | Kamailio: %s\n' "${REPO_ROOT}" "${CH_CTR}" "${KAM_CTR}"

banner 'STAGE 0 | STACK HEALTH'
RUNNING="$(docker ps --filter name=ngn-sip --filter status=running --format '{{.Names}}' 2>/dev/null | wc -l | tr -d ' ')"
TOTAL="$(docker ps -a --filter name=ngn-sip --format '{{.Names}}' 2>/dev/null | wc -l | tr -d ' ')"
printf 'ngn-sip containers running: %s (of %s total)\n' "${RUNNING:-0}" "${TOTAL:-0}"
subheading 'Critical services'
for c in "${KAM_CTR}" "${CH_CTR}" ngn-sip-ids-suricata-1 ngn-sip-wazuh-wazuh-manager-1; do
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "${c}"; then
    printf '  [up]   %s\n' "${c}"
  else
    printf '  [down] %s\n' "${c}"
  fi
done
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qE 'stage1|ngn-sip-stage1'; then
  docker ps --format '  [up]   {{.Names}}' 2>/dev/null | grep -E 'stage1|ngn-sip-stage1' | head -3
else
  printf '  [warn] stage1 scorer container not found by name (ml_scores may be stale)\n'
fi
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'kamailio-autoban'; then
  printf '  [up]   kamailio-autoban sidecar\n'
else
  printf '  [warn] kamailio-autoban not running (ban_audit will not populate)\n'
fi

banner 'STAGE 0b | BASELINE COUNTS (before attack)'
q "SELECT
  (SELECT count() FROM ngn_sip.sip_events WHERE event_time >= now() - INTERVAL 1 HOUR) AS sip_events_1h,
  (SELECT count() FROM ngn_sip.suricata_alerts WHERE event_time >= now() - INTERVAL 1 HOUR) AS suricata_1h,
  (SELECT count() FROM ngn_sip.wazuh_alerts WHERE alert_time >= now() - INTERVAL 1 HOUR AND rule_id BETWEEN 100100 AND 100199) AS wazuh_sip_1h,
  (SELECT count() FROM ngn_sip.ml_scores WHERE scored_at >= now() - INTERVAL 1 HOUR) AS ml_scores_1h,
  (SELECT count() FROM ngn_sip.llm_verdicts WHERE verdict_time >= now() - INTERVAL 1 HOUR) AS llm_verdicts_1h,
  (SELECT count() FROM ngn_sip.ban_audit WHERE event_time >= now() - INTERVAL 1 HOUR) AS ban_audit_1h,
  (SELECT count() FROM ngn_sip.soar_cases WHERE case_time >= now() - INTERVAL 1 HOUR) AS soar_cases_1h
FORMAT PrettyCompact" 2>/dev/null || true

banner 'STAGE 1 | LABELED ATTACK (sippts recon, T1595)'
printf 'Delegating to scripts/labeled_attack_demo.sh (ground-truth label + sippts scan)...\n\n'
ATTACK_OUT="$(bash "${REPO_ROOT}/scripts/labeled_attack_demo.sh" 2>&1)" || true
printf '%s\n' "${ATTACK_OUT}"
ATK_IP="$(printf '%s\n' "${ATTACK_OUT}" | sed -n 's/^==> attacker IP: //p' | tail -1)"
if [ -z "${ATK_IP}" ]; then
  echo "ERROR: could not parse attacker IP from labeled_attack_demo.sh output" >&2
  exit 1
fi
printf '\nTracking attacker src_ip through the pipeline: %s\n' "${ATK_IP}"
sleep "${PAUSE_SEC}"

banner 'PIPELINE TRACE | SAME src_ip THROUGH EVERY STAGE'

subheading "SIP seen (ngn_sip.sip_events)"
q "SELECT event_time, src_ip, method, user_agent
   FROM ngn_sip.sip_events
   WHERE $(ip_sql src_ip "${ATK_IP}") AND event_time >= now() - INTERVAL 15 MINUTE
   ORDER BY event_time DESC LIMIT 10
   FORMAT PrettyCompact" 2>/dev/null || true
if [ "$(count_for_ip sip_events src_ip "${ATK_IP}" event_time)" -gt 0 ] 2>/dev/null; then
  LIT_SIP=1
fi
sleep "${PAUSE_SEC}"

subheading 'Suricata alerts (ngn_sip.suricata_alerts)'
q "SELECT event_time, src_ip, signature_id, signature, severity
   FROM ngn_sip.suricata_alerts
   WHERE $(ip_sql src_ip "${ATK_IP}") AND event_time >= now() - INTERVAL 15 MINUTE
   ORDER BY event_time DESC LIMIT 10
   FORMAT PrettyCompact" 2>/dev/null || true
if [ "$(count_for_ip suricata_alerts src_ip "${ATK_IP}" event_time)" -gt 0 ] 2>/dev/null; then
  LIT_SURICATA=1
fi
sleep "${PAUSE_SEC}"

subheading 'Wazuh SIP rule fired (ngn_sip.wazuh_alerts, rules 100100-100199)'
q "SELECT alert_time, srcip, rule_id, rule_level, rule_description
   FROM ngn_sip.wazuh_alerts
   WHERE $(ip_sql srcip "${ATK_IP}") AND rule_id BETWEEN 100100 AND 100199
     AND alert_time >= now() - INTERVAL 15 MINUTE
   ORDER BY alert_time DESC LIMIT 10
   FORMAT PrettyCompact" 2>/dev/null || true
WAZUH_N="$(q "SELECT count() FROM ngn_sip.wazuh_alerts
   WHERE $(ip_sql srcip "${ATK_IP}") AND rule_id BETWEEN 100100 AND 100199
     AND rule_level >= 10 AND alert_time >= now() - INTERVAL 15 MINUTE" 2>/dev/null || echo 0)"
if [ "${WAZUH_N:-0}" -gt 0 ] 2>/dev/null; then
  LIT_WAZUH=1
fi
sleep "${PAUSE_SEC}"

subheading 'Stage 1 ML verdict (ngn_sip.ml_scores, ngn-sip-stage1-scorer)'
if ! wait_for_count 'ml_scores' ml_scores src_ip "${ATK_IP}" "${ML_WAIT_SEC}" scored_at; then
  printf '(no ml_scores row yet after %ss wait; scorer may be on a 5-minute window)\n' "${ML_WAIT_SEC}"
fi
q "SELECT scored_at, bucket, src_ip, predicted_class, proba, anomaly_score
   FROM ngn_sip.ml_scores
   WHERE $(ip_sql src_ip "${ATK_IP}") AND scored_at >= now() - INTERVAL 30 MINUTE
   ORDER BY scored_at DESC LIMIT 5
   FORMAT PrettyCompact" 2>/dev/null || true
if [ "$(count_for_ip ml_scores src_ip "${ATK_IP}" scored_at)" -gt 0 ] 2>/dev/null; then
  LIT_ML=1
fi
sleep "${PAUSE_SEC}"

subheading 'Stage 2 LLM verdict (ngn_sip.llm_verdicts, advisory only)'
q "SELECT verdict_time, src_ip, verdict, confidence, guardrail_json_pass, model, latency_ms
   FROM ngn_sip.llm_verdicts
   WHERE $(ip_sql src_ip "${ATK_IP}") AND verdict_time >= now() - INTERVAL 30 MINUTE
   ORDER BY verdict_time DESC LIMIT 5
   FORMAT PrettyCompact" 2>/dev/null || true
if [ "$(count_for_ip llm_verdicts src_ip "${ATK_IP}" verdict_time)" -gt 0 ] 2>/dev/null; then
  LIT_LLM=1
else
  printf '(no llm_verdicts row: Stage 2 worker may be stopped or still processing)\n'
fi
sleep "${PAUSE_SEC}"

subheading 'Autoban action (ngn_sip.ban_audit, kamailio-autoban sidecar)'
if ! wait_for_count 'ban_audit' ban_audit src_ip "${ATK_IP}" "${BAN_WAIT_SEC}" event_time; then
  printf '(no ban_audit row yet after %ss; autoban polls every 5s on Wazuh level >= 10)\n' "${BAN_WAIT_SEC}"
fi
q "SELECT event_time, src_ip, action, reason, min_level
   FROM ngn_sip.ban_audit
   WHERE src_ip = '${ATK_IP}' AND event_time >= now() - INTERVAL 30 MINUTE
   ORDER BY event_time DESC LIMIT 5
   FORMAT PrettyCompact" 2>/dev/null || true
BAN_N="$(q "SELECT count() FROM ngn_sip.ban_audit
   WHERE src_ip = '${ATK_IP}' AND action = 'ban' AND event_time >= now() - INTERVAL 30 MINUTE" 2>/dev/null || echo 0)"
if [ "${BAN_N:-0}" -gt 0 ] 2>/dev/null; then
  LIT_BAN_AUDIT=1
fi

subheading 'Live Kamailio ban_table (edge block state)'
BAN_DUMP="$(docker exec "${KAM_CTR}" kamcmd htable.dump ban_table 2>/dev/null || true)"
printf '%s\n' "${BAN_DUMP}"
if printf '%s\n' "${BAN_DUMP}" | grep -qF "${ATK_IP}"; then
  LIT_BAN_TABLE=1
fi
sleep "${PAUSE_SEC}"

subheading 'Stage 3 SOAR case (ngn_sip.soar_cases, Shuffle orchestration)'
q "SELECT case_time, src_ip, wazuh_rule_id, wazuh_rule_level, graded_action,
          stage2_verdict, ml_predicted_label, ml_attack_score, notify_sent
   FROM ngn_sip.soar_cases
   WHERE src_ip = '${ATK_IP}' AND case_time >= now() - INTERVAL 30 MINUTE
   ORDER BY case_time DESC LIMIT 5
   FORMAT PrettyCompact" 2>/dev/null || true
SOAR_N="$(q "SELECT count() FROM ngn_sip.soar_cases
   WHERE src_ip = '${ATK_IP}' AND case_time >= now() - INTERVAL 30 MINUTE" 2>/dev/null || echo 0)"
if [ "${SOAR_N:-0}" -gt 0 ] 2>/dev/null; then
  LIT_SOAR=1
else
  printf '(no soar_cases row: SOAR workflow may be paused or dedup-suppressed)\n'
fi

banner 'DEMO SUMMARY'
CORE_LIT=$((LIT_SIP + LIT_SURICATA + LIT_WAZUH + LIT_BAN_AUDIT + LIT_BAN_TABLE))
CORE_MAX=5
ENRICH_LIT=$((LIT_ML + LIT_LLM + LIT_SOAR))

printf 'Attacker src_ip: %s\n' "${ATK_IP}"
printf 'Stages: sip=%s suricata=%s wazuh=%s ml=%s llm=%s ban_audit=%s ban_table=%s soar=%s\n' \
  "${LIT_SIP}" "${LIT_SURICATA}" "${LIT_WAZUH}" "${LIT_ML}" "${LIT_LLM}" \
  "${LIT_BAN_AUDIT}" "${LIT_BAN_TABLE}" "${LIT_SOAR}"

if [ "${CORE_LIT}" -eq "${CORE_MAX}" ]; then
  if [ "${ENRICH_LIT}" -eq 3 ]; then
    printf 'RESULT: PASS (all stages lit: SIP, Suricata, Wazuh, ML, LLM, autoban, SOAR)\n'
  else
    printf 'RESULT: PASS (core detect-defend path lit: SIP, Suricata, Wazuh, autoban audit + ban_table; enrichment ML=%s LLM=%s SOAR=%s)\n' \
      "${LIT_ML}" "${LIT_LLM}" "${LIT_SOAR}"
  fi
elif [ "${CORE_LIT}" -ge 3 ]; then
  printf 'RESULT: PARTIAL (core=%s/%s: sip=%s suricata=%s wazuh=%s ban_audit=%s ban_table=%s; check Suricata attachment or autoban sidecar)\n' \
    "${CORE_LIT}" "${CORE_MAX}" "${LIT_SIP}" "${LIT_SURICATA}" "${LIT_WAZUH}" "${LIT_BAN_AUDIT}" "${LIT_BAN_TABLE}"
else
  printf 'RESULT: PARTIAL (only %s/%s core stages; verify stack health and Suricata after any Kamailio restart)\n' \
    "${CORE_LIT}" "${CORE_MAX}"
fi
printf 'PIPELINE_DEMO_DONE\n'
