#!/usr/bin/env bash
# Three-arm detection comparison (master-plan C3): signature (Suricata) vs
# correlation/SIEM (Wazuh) vs ML, evaluated at the source-IP level against the
# attack_labels ground truth for a single attack-matrix campaign.
#
# Each attack-matrix run uses a distinct static source IP, so detection is
# scored per source: an arm "flags" a labeled source if it produced any alert
# from that source IP within the campaign window. Recall = flagged attack
# sources / attack sources; FP rate = flagged benign sources / benign sources.
#
# Usage (on the VM, repo root):
#   bash scripts/eval_c3_arms.sh '2026-06-02 16:30:00'   # campaign start (UTC)
set -euo pipefail
START="${1:?pass the campaign start time, UTC, e.g. '2026-06-02 16:30:00'}"
P="$(grep ^CLICKHOUSE_PASSWORD= .env | cut -d= -f2-)"
q() { docker exec ngn-sip-clickhouse-1 sh -lc "clickhouse-client --user ngn --password '$P' -q \"$1\""; }

echo "=== C3 three-arm comparison | campaign since ${START} (UTC) ==="

echo "--- labeled sources in campaign (per class) ---"
q "SELECT phase, uniqExact(src_ip) AS sources, count() AS label_rows
   FROM ngn_sip.attack_labels WHERE label_time >= toDateTime('${START}')
   GROUP BY phase ORDER BY sources DESC FORMAT PrettyCompact"

# NOTE: attack_labels.src_ip is stored IPv4-mapped (::ffff:172.18.x.x) while the
# alert tables use plain IPv4, so the join must strip the ::ffff: prefix.
echo "--- binary attack-vs-benign, per arm (source-IP level) ---"
q "
WITH
  labels AS (
    SELECT replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
           if(anyHeavy(phase)='benign','benign','attack') AS truth
    FROM ngn_sip.attack_labels WHERE label_time >= toDateTime('${START}')
    GROUP BY src_ip
  ),
  suri AS (SELECT DISTINCT replaceOne(toString(src_ip), '::ffff:', '') AS src_ip FROM ngn_sip.suricata_alerts WHERE event_time >= toDateTime('${START}')),
  waz  AS (SELECT DISTINCT replaceOne(toString(srcip), '::ffff:', '') AS src_ip FROM ngn_sip.wazuh_alerts
           WHERE alert_time >= toDateTime('${START}') AND rule_id BETWEEN 100100 AND 100199),
  wazp AS (SELECT DISTINCT replaceOne(toString(srcip), '::ffff:', '') AS src_ip FROM ngn_sip.wazuh_alerts
           WHERE alert_time >= toDateTime('${START}') AND rule_id = 100103)
SELECT
  truth,
  count()                                       AS sources,
  countIf(src_ip GLOBAL IN suri)                AS suricata_flagged,
  countIf(src_ip GLOBAL IN waz)                 AS wazuh_any_flagged,
  countIf(src_ip GLOBAL IN wazp)                AS wazuh_pike_flagged
FROM labels GROUP BY truth ORDER BY truth FORMAT PrettyCompact"

echo "--- per-class recall (attack classes only), Suricata vs Wazuh ---"
q "
WITH
  labels AS (
    SELECT replaceOne(toString(src_ip), '::ffff:', '') AS src_ip, anyHeavy(phase) AS cls
    FROM ngn_sip.attack_labels
    WHERE label_time >= toDateTime('${START}') AND phase != 'benign'
    GROUP BY src_ip
  ),
  suri AS (SELECT DISTINCT replaceOne(toString(src_ip), '::ffff:', '') AS src_ip FROM ngn_sip.suricata_alerts WHERE event_time >= toDateTime('${START}')),
  waz  AS (SELECT DISTINCT replaceOne(toString(srcip), '::ffff:', '') AS src_ip FROM ngn_sip.wazuh_alerts
           WHERE alert_time >= toDateTime('${START}') AND rule_id BETWEEN 100100 AND 100199)
SELECT
  cls AS phase,
  count()                          AS sources,
  countIf(src_ip GLOBAL IN suri)   AS suricata_recall_n,
  countIf(src_ip GLOBAL IN waz)    AS wazuh_recall_n
FROM labels GROUP BY cls ORDER BY cls FORMAT PrettyCompact"

echo "--- Wazuh rule_id breakdown in campaign ---"
q "SELECT rule_id, any(rule_description) d, uniqExact(srcip) sources, count() alerts
   FROM ngn_sip.wazuh_alerts
   WHERE alert_time >= toDateTime('${START}') AND rule_id BETWEEN 100100 AND 100199
   GROUP BY rule_id ORDER BY rule_id FORMAT PrettyCompact"
