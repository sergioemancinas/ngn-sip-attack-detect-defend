#!/usr/bin/env bash
# Export the labeled SIP feature dataset to a versioned CSV for reproducibility
# and IEEE DataPort packaging. Joins sip_features_5min
# to attack_labels by source IP, emitting one row per labeled feature window with
# the full feature vector + the ground-truth class (benign or attack phase).
set -uo pipefail
cd ~/sip-attack-detect-defend || exit 1
P="$(grep ^CLICKHOUSE_PASSWORD= .env | cut -d= -f2-)"
DATE="$(date +%F)"
OUT="${HOME}/sip-dataset-${DATE}.csv"

read -r -d '' Q <<'SQL'
SELECT
  f.window_start                        AS window_start,
  toString(f.src_ip)                    AS src_ip,
  l.phase                               AS class,
  l.attack_id                           AS attack_id,
  l.mitre_technique                     AS mitre_technique,
  l.notes                               AS variant,
  f.total_msgs                          AS total_msgs,
  f.register_count                      AS register_count,
  f.invite_count                        AS invite_count,
  f.options_count                       AS options_count,
  f.auth_4xx_count                      AS auth_4xx_count,
  f.success_2xx                         AS success_2xx,
  f.error_5xx                           AS error_5xx,
  uniqMerge(f.distinct_ua)              AS distinct_ua,
  uniqMerge(f.distinct_to_uri)          AS distinct_to_uri,
  uniqMerge(f.distinct_call_id)         AS distinct_call_id,
  f.sum_body_size                       AS sum_body_size,
  f.sample_count                        AS sample_count
FROM ngn_sip.sip_features_5min f
INNER JOIN ngn_sip.attack_labels l ON f.src_ip = l.src_ip
GROUP BY window_start, src_ip, class, attack_id, mitre_technique, variant,
         total_msgs, register_count, invite_count, options_count,
         auth_4xx_count, success_2xx, error_5xx, sum_body_size, sample_count
ORDER BY window_start, src_ip
FORMAT CSVWithNames
SQL

printf '%s' "$Q" | curl -s "http://127.0.0.1:8123/?user=ngn&password=${P}" --data-binary @- > "$OUT"
echo "rows (incl header): $(wc -l < "$OUT")"
echo "class balance:"
tail -n +2 "$OUT" | cut -d, -f3 | sort | uniq -c
echo "written: $OUT"
echo "EXPORT_DONE"
