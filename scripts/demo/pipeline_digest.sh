#!/usr/bin/env bash
# One-page pipeline digest for demo day or daily ops. Read-only ClickHouse queries.
#
# Usage (campus VM, repo root):
#   bash scripts/demo/pipeline_digest.sh           # last 24 hours
#   bash scripts/demo/pipeline_digest.sh 6           # last 6 hours
#   bash scripts/demo/pipeline_digest.sh 24 --markdown
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
WINDOW_HOURS=24
MARKDOWN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --markdown) MARKDOWN=1; shift ;;
    -h|--help)
      sed -n '2,8p' "$0"
      exit 0
      ;;
    *)
      WINDOW_HOURS="${1%h}"
      shift
      ;;
  esac
done

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

RUNNING="$(docker ps --filter name=ngn-sip --filter status=running --format '{{.Names}}' 2>/dev/null | wc -l | tr -d ' ')"
TOTAL="$(docker ps -a --filter name=ngn-sip --format '{{.Names}}' 2>/dev/null | wc -l | tr -d ' ')"
GENERATED="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

if [ "${MARKDOWN}" -eq 0 ]; then
  printf 'NGN SIP PIPELINE DIGEST | window=%sh | generated=%s\n' "${WINDOW_HOURS}" "${GENERATED}"
  printf 'Containers (ngn-sip project): %s running / %s total\n\n' "${RUNNING:-0}" "${TOTAL:-0}"

  printf '=== Per-stage volume and freshness (last %sh) ===\n' "${WINDOW_HOURS}"
  q "SELECT
    'sip_events' AS stage,
    count() AS events,
    max(event_time) AS latest
  FROM ngn_sip.sip_events WHERE event_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
  UNION ALL
  SELECT 'suricata_alerts', count(), max(event_time)
  FROM ngn_sip.suricata_alerts WHERE event_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
  UNION ALL
  SELECT 'wazuh_alerts_sip', count(), max(alert_time)
  FROM ngn_sip.wazuh_alerts
  WHERE alert_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR AND rule_id BETWEEN 100100 AND 100199
  UNION ALL
  SELECT 'ml_scores', count(), max(scored_at)
  FROM ngn_sip.ml_scores WHERE scored_at >= now() - INTERVAL ${WINDOW_HOURS} HOUR
  UNION ALL
  SELECT 'llm_verdicts', count(), max(verdict_time)
  FROM ngn_sip.llm_verdicts WHERE verdict_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
  UNION ALL
  SELECT 'ban_audit', count(), max(event_time)
  FROM ngn_sip.ban_audit WHERE event_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
  UNION ALL
  SELECT 'soar_cases', count(), max(case_time)
  FROM ngn_sip.soar_cases WHERE case_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
  UNION ALL
  SELECT 'attack_labels', count(), max(label_time)
  FROM ngn_sip.attack_labels WHERE label_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
  ORDER BY stage
  FORMAT PrettyCompact"

  printf '\n=== Top labeled attacker sources (attack_labels, non-benign) ===\n'
  q "
WITH labels AS (
  SELECT
    replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
    anyHeavy(mitre_technique) AS mitre,
    anyHeavy(phase) AS phase,
    max(label_time) AS last_label
  FROM ngn_sip.attack_labels
  WHERE label_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR AND phase != 'benign'
  GROUP BY src_ip
),
ml AS (
  SELECT
    replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
    argMax(predicted_class, scored_at) AS stage1_class,
    round(argMax(proba, scored_at), 3) AS stage1_proba
  FROM ngn_sip.ml_scores
  WHERE scored_at >= now() - INTERVAL ${WINDOW_HOURS} HOUR
  GROUP BY src_ip
),
llm AS (
  SELECT
    replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
    argMax(verdict, verdict_time) AS stage2_verdict,
    round(argMax(confidence, verdict_time), 3) AS stage2_conf
  FROM ngn_sip.llm_verdicts
  WHERE verdict_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
  GROUP BY src_ip
),
bans AS (
  SELECT src_ip, countIf(action = 'ban') AS ban_events, max(event_time) AS last_ban
  FROM ngn_sip.ban_audit
  WHERE event_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
  GROUP BY src_ip
)
SELECT
  l.src_ip,
  l.mitre,
  l.phase,
  coalesce(m.stage1_class, '-') AS stage1,
  coalesce(toString(m.stage1_proba), '-') AS proba,
  coalesce(ll.stage2_verdict, '-') AS stage2,
  if(b.ban_events > 0, 'yes', 'no') AS banned
FROM labels l
LEFT JOIN ml m ON l.src_ip = m.src_ip
LEFT JOIN llm ll ON l.src_ip = ll.src_ip
LEFT JOIN bans b ON l.src_ip = b.src_ip
ORDER BY l.last_label DESC
LIMIT 15
FORMAT PrettyCompact"

  printf '\n=== C3 detector comparison headline (source-IP level, labeled campaign) ===\n'
  printf 'Suricata/Wazuh IOC: recall ~0.71, FP rate 1.00 on tool-shaped benign (sippts probes).\n'
  printf 'Wazuh PIKE (rate-based): FP 0.00, recall ~0.14 (narrow but specific).\n'
  printf 'XGBoost behavioural ML (leakage-free grouped-CV): F1 0.75 [0.68, 0.81], ROC-AUC 0.947.\n'
  printf 'Refs: docs/results/RESULTS_c3_comparison_2026-06-02.md, RESULTS_stage1_grouped_2026-06-10.md\n'

  printf '\n=== ban_audit tallies (last %sh) ===\n' "${WINDOW_HOURS}"
  q "SELECT action, count() AS n
     FROM ngn_sip.ban_audit
     WHERE event_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
     GROUP BY action ORDER BY n DESC
     FORMAT PrettyCompact"

  printf '\nDIGEST_DONE\n'
else
  printf '# NGN SIP Pipeline Digest\n\n'
  printf 'Window: last %s hours | Generated: %s | Containers: %s/%s running\n\n' \
    "${WINDOW_HOURS}" "${GENERATED}" "${RUNNING:-0}" "${TOTAL:-0}"

  printf '## Stage volume and freshness\n\n'
  printf '| stage | events | latest |\n'
  printf '|---|---:|---|\n'
  q "SELECT
    stage, toString(events), toString(latest)
  FROM (
    SELECT 'sip_events' AS stage, count() AS events, max(event_time) AS latest
    FROM ngn_sip.sip_events WHERE event_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
    UNION ALL
    SELECT 'suricata_alerts', count(), max(event_time)
    FROM ngn_sip.suricata_alerts WHERE event_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
    UNION ALL
    SELECT 'wazuh_alerts_sip', count(), max(alert_time)
    FROM ngn_sip.wazuh_alerts
    WHERE alert_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR AND rule_id BETWEEN 100100 AND 100199
    UNION ALL
    SELECT 'ml_scores', count(), max(scored_at)
    FROM ngn_sip.ml_scores WHERE scored_at >= now() - INTERVAL ${WINDOW_HOURS} HOUR
    UNION ALL
    SELECT 'llm_verdicts', count(), max(verdict_time)
    FROM ngn_sip.llm_verdicts WHERE verdict_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
    UNION ALL
    SELECT 'ban_audit', count(), max(event_time)
    FROM ngn_sip.ban_audit WHERE event_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
    UNION ALL
    SELECT 'soar_cases', count(), max(case_time)
    FROM ngn_sip.soar_cases WHERE case_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
    UNION ALL
    SELECT 'attack_labels', count(), max(label_time)
    FROM ngn_sip.attack_labels WHERE label_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
  )
  ORDER BY stage
  FORMAT TSV" | while IFS=$'\t' read -r stage events latest; do
    printf '| %s | %s | %s |\n' "${stage}" "${events}" "${latest}"
  done

  printf '\n## Top labeled attacker sources\n\n'
  printf '| src_ip | MITRE | phase | stage1 | proba | stage2 | banned |\n'
  printf '|---|---|---|---|---:|---|---|\n'
  q "
WITH labels AS (
  SELECT
    replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
    anyHeavy(mitre_technique) AS mitre,
    anyHeavy(phase) AS phase,
    max(label_time) AS last_label
  FROM ngn_sip.attack_labels
  WHERE label_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR AND phase != 'benign'
  GROUP BY src_ip
),
ml AS (
  SELECT
    replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
    argMax(predicted_class, scored_at) AS stage1_class,
    round(argMax(proba, scored_at), 3) AS stage1_proba
  FROM ngn_sip.ml_scores
  WHERE scored_at >= now() - INTERVAL ${WINDOW_HOURS} HOUR
  GROUP BY src_ip
),
llm AS (
  SELECT
    replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
    argMax(verdict, verdict_time) AS stage2_verdict
  FROM ngn_sip.llm_verdicts
  WHERE verdict_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
  GROUP BY src_ip
),
bans AS (
  SELECT src_ip, countIf(action = 'ban') AS ban_events
  FROM ngn_sip.ban_audit
  WHERE event_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
  GROUP BY src_ip
)
SELECT
  l.src_ip, l.mitre, l.phase,
  coalesce(m.stage1_class, '-'),
  coalesce(toString(m.stage1_proba), '-'),
  coalesce(ll.stage2_verdict, '-'),
  if(b.ban_events > 0, 'yes', 'no')
FROM labels l
LEFT JOIN ml m ON l.src_ip = m.src_ip
LEFT JOIN llm ll ON l.src_ip = ll.src_ip
LEFT JOIN bans b ON l.src_ip = b.src_ip
ORDER BY l.last_label DESC
LIMIT 15
FORMAT TSV" | while IFS=$'\t' read -r ip mitre phase s1 proba s2 banned; do
    printf '| %s | %s | %s | %s | %s | %s | %s |\n' "${ip}" "${mitre}" "${phase}" "${s1}" "${proba}" "${s2}" "${banned}"
  done

  printf '\n## C3 headline\n\n'
  printf '- Suricata/Wazuh IOC: recall ~0.71, FP rate 1.00 on tool-shaped benign\n'
  printf '- Wazuh PIKE: FP 0.00, recall ~0.14\n'
  printf '- XGBoost grouped-CV: F1 **0.75 [0.68, 0.81]**, ROC-AUC 0.947\n\n'

  printf '## ban_audit tallies\n\n'
  printf '| action | count |\n'
  printf '|---|---:|\n'
  q "SELECT action, count()
     FROM ngn_sip.ban_audit
     WHERE event_time >= now() - INTERVAL ${WINDOW_HOURS} HOUR
     GROUP BY action ORDER BY count() DESC
     FORMAT TSV" | while IFS=$'\t' read -r action n; do
    printf '| %s | %s |\n' "${action}" "${n}"
  done
fi
