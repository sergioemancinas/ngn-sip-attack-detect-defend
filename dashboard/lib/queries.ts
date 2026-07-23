export const SIP_RESPONSES_QUERY = `
SELECT
  if(response_code = 0, concat(if(method = '', 'OTHER', method), ' req'), concat(toString(response_code), ' ', if(response_phrase = '', 'response', response_phrase))) AS label,
  count() AS value
FROM sip_events
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
GROUP BY label
ORDER BY value DESC
LIMIT 24
`;

export const TOP_SOURCES_QUERY = `
WITH sources AS (
  SELECT
    replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
    count() AS event_count,
    'sip_events' AS origin
  FROM sip_events
  WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
  GROUP BY src_ip
  UNION ALL
  SELECT src_ip, count() AS event_count, 'suricata_alerts' AS origin
  FROM suricata_alerts
  WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
  GROUP BY src_ip
),
aggregated AS (
  SELECT src_ip, sum(event_count) AS total
  FROM sources
  GROUP BY src_ip
  ORDER BY total DESC
  LIMIT {limit:UInt32}
),
labels AS (
  SELECT
    replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
    anyHeavy(mitre_technique) AS mitre_technique,
    anyHeavy(attack_id) AS attack_id
  FROM attack_labels
  WHERE label_time >= now() - INTERVAL {hours:UInt32} HOUR
  GROUP BY src_ip
),
bans AS (
  SELECT src_ip, countIf(action = 'ban') AS ban_count
  FROM ban_audit
  WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
  GROUP BY src_ip
)
SELECT
  a.src_ip AS src_ip,
  a.total AS total,
  if(l.src_ip != '', 1, 0) AS is_labeled_attack,
  coalesce(l.mitre_technique, '') AS mitre_technique,
  coalesce(l.attack_id, '') AS attack_id,
  coalesce(b.ban_count, 0) AS ban_count
FROM aggregated a
LEFT JOIN labels l ON l.src_ip = a.src_ip
LEFT JOIN bans b ON b.src_ip = a.src_ip
ORDER BY a.total DESC
`;

export const CDR_BY_SRC_IP_QUERY = `
SELECT
  replaceOne(toString(src_ip), '::ffff:', '') AS group_key,
  count() AS call_count,
  countIf(method = 'INVITE') AS invite_count,
  countIf(method = 'REGISTER') AS register_count,
  countIf(response_code BETWEEN 200 AND 299) AS success_2xx,
  countIf(response_code IN (401, 403, 407)) AS auth_failures,
  round(avgIf(response_code, response_code > 0), 1) AS avg_response_code,
  NULL AS mos,
  NULL AS packet_loss_pct,
  NULL AS delay_ms
FROM sip_events
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
GROUP BY group_key
ORDER BY call_count DESC
LIMIT {limit:UInt32}
`;

export const CDR_BY_RESPONSE_QUERY = `
SELECT
  if(response_code = 0, method, toString(response_code)) AS group_key,
  count() AS call_count,
  countIf(method = 'INVITE') AS invite_count,
  countIf(method = 'REGISTER') AS register_count,
  countIf(response_code BETWEEN 200 AND 299) AS success_2xx,
  countIf(response_code IN (401, 403, 407)) AS auth_failures,
  round(avgIf(response_code, response_code > 0), 1) AS avg_response_code,
  NULL AS mos,
  NULL AS packet_loss_pct,
  NULL AS delay_ms
FROM sip_events
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
GROUP BY group_key
ORDER BY call_count DESC
LIMIT {limit:UInt32}
`;

export const REGISTER_TIMESERIES_QUERY = `
SELECT
  toStartOfFiveMinutes(event_time) AS bucket,
  countIf(response_code BETWEEN 200 AND 299 OR (response_code = 0 AND method = 'REGISTER')) AS success_count,
  countIf(response_code IN (401, 403, 407)) AS auth_401_count,
  count() AS total
FROM sip_events
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND method = 'REGISTER'
GROUP BY bucket
ORDER BY bucket
`;

export const SURICATA_RATE_QUERY = `
SELECT
  toStartOfFiveMinutes(event_time) AS bucket,
  count() AS alert_count
FROM suricata_alerts
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
GROUP BY bucket
ORDER BY bucket
`;

export const WAZUH_SIP_QUERY = `
SELECT
  rule_id,
  anyHeavy(rule_description) AS rule_description,
  max(rule_level) AS max_level,
  count() AS hit_count
FROM wazuh_alerts
WHERE alert_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND rule_id BETWEEN 100100 AND 100199
GROUP BY rule_id
ORDER BY hit_count DESC
LIMIT 50
`;

export const WAZUH_TIMESERIES_QUERY = `
SELECT
  toStartOfFiveMinutes(alert_time) AS bucket,
  count() AS hit_count
FROM wazuh_alerts
WHERE alert_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND rule_id BETWEEN 100100 AND 100199
GROUP BY bucket
ORDER BY bucket
`;

export const ML_SCORES_TIMESERIES_QUERY = `
SELECT
  toStartOfFiveMinutes(scored_at) AS bucket,
  predicted_class,
  round(avg(proba), 3) AS avg_proba,
  count() AS score_count
FROM ml_scores
WHERE scored_at >= now() - INTERVAL {hours:UInt32} HOUR
GROUP BY bucket, predicted_class
ORDER BY bucket, predicted_class
`;

export const ML_SCORES_SUMMARY_QUERY = `
SELECT
  predicted_class,
  round(avg(proba), 3) AS avg_proba,
  count() AS score_count
FROM ml_scores
WHERE scored_at >= now() - INTERVAL {hours:UInt32} HOUR
GROUP BY predicted_class
ORDER BY score_count DESC
`;

export const LLM_VERDICTS_TIMESERIES_QUERY = `
SELECT
  toStartOfFiveMinutes(verdict_time) AS bucket,
  verdict,
  round(avg(confidence), 3) AS avg_confidence,
  count() AS verdict_count
FROM llm_verdicts
WHERE verdict_time >= now() - INTERVAL {hours:UInt32} HOUR
GROUP BY bucket, verdict
ORDER BY bucket, verdict
`;

export const LLM_VERDICTS_SUMMARY_QUERY = `
SELECT
  verdict,
  round(avg(confidence), 3) AS avg_confidence,
  count() AS verdict_count
FROM llm_verdicts
WHERE verdict_time >= now() - INTERVAL {hours:UInt32} HOUR
GROUP BY verdict
ORDER BY verdict_count DESC
`;

export const LLM_VERDICTS_RECENT_QUERY = `
SELECT
  verdict_time,
  replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
  verdict,
  round(confidence, 3) AS confidence,
  alert_rule_id
FROM llm_verdicts
WHERE verdict_time >= now() - INTERVAL {hours:UInt32} HOUR
ORDER BY verdict_time DESC
LIMIT {limit:UInt32}
`;

export const WAZUH_AGENT_SUMMARY_QUERY = `
SELECT
  anyHeavy(agent_id) AS agent_id,
  anyHeavy(agent_name) AS agent_name,
  count() AS alert_count
FROM wazuh_alerts
WHERE alert_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND rule_id BETWEEN 100100 AND 100199
`;

export const WAZUH_MITRE_QUERY = `
SELECT
  arrayJoin(rule_mitre_id) AS mitre_id,
  count() AS hit_count
FROM wazuh_alerts
WHERE alert_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND rule_id BETWEEN 100100 AND 100199
  AND length(rule_mitre_id) > 0
GROUP BY mitre_id
ORDER BY hit_count DESC
LIMIT 12
`;

export const WAZUH_RECENT_QUERY = `
SELECT
  alert_time,
  rule_id,
  rule_level,
  rule_description,
  srcip,
  agent_name
FROM wazuh_alerts
WHERE alert_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND rule_id BETWEEN 100100 AND 100199
ORDER BY alert_time DESC
LIMIT {limit:UInt32}
`;

export const BAN_AUDIT_SUMMARY_QUERY = `
SELECT
  action,
  count() AS action_count
FROM ban_audit
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
GROUP BY action
ORDER BY action_count DESC
`;

export const BAN_AUDIT_RECENT_QUERY = `
SELECT
  event_time,
  src_ip,
  action,
  reason,
  min_level,
  ttl_seconds
FROM ban_audit
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
ORDER BY event_time DESC
LIMIT {limit:UInt32}
`;

export const SOAR_CASES_SUMMARY_QUERY = `
SELECT
  graded_action,
  count() AS case_count
FROM soar_cases
WHERE case_time >= now() - INTERVAL {hours:UInt32} HOUR
GROUP BY graded_action
ORDER BY case_count DESC
`;

export const SOAR_CASES_RECENT_QUERY = `
SELECT
  case_time,
  src_ip,
  graded_action,
  wazuh_rule_id,
  wazuh_rule_level,
  stage2_verdict,
  ml_predicted_label,
  ml_attack_score
FROM soar_cases
WHERE case_time >= now() - INTERVAL {hours:UInt32} HOUR
ORDER BY case_time DESC
LIMIT {limit:UInt32}
`;

export const ATTACK_TIMELINE_QUERY = `
SELECT
  label_time AS event_time,
  replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
  'attack_label' AS event_type,
  mitre_technique AS detail,
  phase AS severity
FROM attack_labels
WHERE label_time >= now() - INTERVAL {hours:UInt32} HOUR
UNION ALL
SELECT
  event_time,
  src_ip,
  action AS event_type,
  reason AS detail,
  toString(min_level) AS severity
FROM ban_audit
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
ORDER BY event_time DESC
LIMIT {limit:UInt32}
`;

export const SIP_METHOD_MIX_QUERY = `
SELECT
  if(method = '', 'OTHER', upper(method)) AS method,
  count() AS cnt
FROM sip_events
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
GROUP BY method
ORDER BY cnt DESC
LIMIT 16
`;

export const SIP_RESPONSE_CODES_QUERY = `
SELECT
  response_code,
  anyHeavy(response_phrase) AS response_phrase,
  count() AS cnt
FROM sip_events
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND response_code > 0
GROUP BY response_code
ORDER BY cnt DESC
LIMIT 24
`;

export const SIP_RESPONSE_CLASS_QUERY = `
SELECT
  multiIf(
    response_code = 0, 'requests',
    response_code BETWEEN 200 AND 299, '2xx success',
    response_code BETWEEN 400 AND 499, '4xx client',
    response_code BETWEEN 500 AND 599, '5xx server',
    'other'
  ) AS response_class,
  count() AS cnt
FROM sip_events
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
GROUP BY response_class
ORDER BY cnt DESC
`;

export const SIP_EVENTS_RECENT_QUERY = `
SELECT
  event_time,
  replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
  if(method = '', 'OTHER', upper(method)) AS method,
  if(
    response_code = 0,
    if(method = '', 'req', concat(method, ' req')),
    toString(response_code)
  ) AS response
FROM sip_events
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
ORDER BY event_time DESC
LIMIT {limit:UInt32}
`;

export const SURICATA_RECENT_QUERY = `
SELECT
  event_time,
  signature AS rule,
  toString(severity) AS level,
  src_ip AS src
FROM suricata_alerts
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
ORDER BY event_time DESC
LIMIT {limit:UInt32}
`;

export const ML_SCORES_RECENT_QUERY = `
SELECT
  toString(scored_at) AS event_time,
  replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
  predicted_class,
  round(proba, 3) AS proba
FROM ml_scores
WHERE scored_at >= now() - INTERVAL {hours:UInt32} HOUR
ORDER BY scored_at DESC
LIMIT {limit:UInt32}
`;

export const RESPONSE_LIVE_BAN_QUERY = `
SELECT
  event_time,
  src_ip AS src,
  action,
  '' AS detail
FROM ban_audit
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
ORDER BY event_time DESC
LIMIT {limit:UInt32}
`;

export const RESPONSE_LIVE_SOAR_QUERY = `
SELECT
  toString(case_time) AS event_time,
  src_ip AS src,
  graded_action AS action,
  concat('rule ', toString(wazuh_rule_id)) AS detail
FROM soar_cases
WHERE case_time >= now() - INTERVAL {hours:UInt32} HOUR
ORDER BY case_time DESC
LIMIT {limit:UInt32}
`;

export const STACK_FRESHNESS_QUERY = `
SELECT
  'sip_events' AS component,
  'ClickHouse ingest / Suricata SIP path' AS description,
  count() AS row_count,
  max(event_time) AS latest_event
FROM sip_events
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
UNION ALL
SELECT
  'suricata',
  'Suricata IDS (EVE alerts)',
  count(),
  max(event_time)
FROM suricata_alerts
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
UNION ALL
SELECT
  'wazuh_sip',
  'Wazuh SIP rules 100100-100199',
  count(),
  max(alert_time)
FROM wazuh_alerts
WHERE alert_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND rule_id BETWEEN 100100 AND 100199
UNION ALL
SELECT
  'ml_stage1',
  'Stage 1 ML scorer (ml_scores)',
  count(),
  max(scored_at)
FROM ml_scores
WHERE scored_at >= now() - INTERVAL {hours:UInt32} HOUR
UNION ALL
SELECT
  'llm_stage2',
  'Stage 2 LLM triage (llm_verdicts)',
  count(),
  max(verdict_time)
FROM llm_verdicts
WHERE verdict_time >= now() - INTERVAL {hours:UInt32} HOUR
UNION ALL
SELECT
  'autoban',
  'kamailio-autoban (ban_audit)',
  count(),
  max(event_time)
FROM ban_audit
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
UNION ALL
SELECT
  'soar',
  'Shuffle SOAR (soar_cases)',
  count(),
  max(case_time)
FROM soar_cases
WHERE case_time >= now() - INTERVAL {hours:UInt32} HOUR
`;

export const SIP_EVENTS_BY_SOURCE_QUERY = `
SELECT
  source,
  count() AS row_count,
  max(event_time) AS latest_event
FROM sip_events
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
GROUP BY source
ORDER BY row_count DESC
`;

export const DEMO_LATEST_ATTACKER_QUERY = `
SELECT replaceOne(toString(src_ip), '::ffff:', '') AS src_ip
FROM attack_labels
WHERE label_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND phase != 'benign'
ORDER BY label_time DESC
LIMIT 1
`;

export const DEMO_BEST_ATTACKER_QUERY = `
WITH candidates AS (
  SELECT
    replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
    max(label_time) AS latest_label
  FROM attack_labels
  WHERE label_time >= now() - INTERVAL {hours:UInt32} HOUR
    AND phase != 'benign'
  GROUP BY src_ip
  ORDER BY latest_label DESC
  LIMIT 25
)
SELECT
  c.src_ip AS src_ip,
  (
    if((SELECT count() FROM sip_events se
        WHERE replaceOne(toString(se.src_ip), '::ffff:', '') = c.src_ip
          AND se.event_time >= now() - INTERVAL {hours:UInt32} HOUR) > 0, 1, 0)
    + if((SELECT count() FROM suricata_alerts sa
        WHERE sa.src_ip = c.src_ip
          AND sa.event_time >= now() - INTERVAL {hours:UInt32} HOUR) > 0, 1, 0)
    + if((SELECT count() FROM wazuh_alerts wa
        WHERE wa.srcip = c.src_ip
          AND wa.alert_time >= now() - INTERVAL {hours:UInt32} HOUR
          AND wa.rule_id BETWEEN 100100 AND 100199) > 0, 1, 0)
    + if((SELECT count() FROM ml_scores ms
        WHERE replaceOne(toString(ms.src_ip), '::ffff:', '') = c.src_ip
          AND ms.scored_at >= now() - INTERVAL {hours:UInt32} HOUR) > 0, 1, 0)
    + if((SELECT count() FROM llm_verdicts lv
        WHERE replaceOne(toString(lv.src_ip), '::ffff:', '') = c.src_ip
          AND lv.verdict_time >= now() - INTERVAL {hours:UInt32} HOUR) > 0, 1, 0)
    + if((SELECT count() FROM ban_audit ba
        WHERE ba.src_ip = c.src_ip
          AND ba.event_time >= now() - INTERVAL {hours:UInt32} HOUR) > 0, 1, 0)
  ) AS stage_hits,
  c.latest_label AS latest_label
FROM candidates c
ORDER BY stage_hits DESC, latest_label DESC
LIMIT 1
`;

export const DEMO_LATEST_BANNED_QUERY = `
SELECT src_ip
FROM ban_audit
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND action = 'ban'
ORDER BY event_time DESC
LIMIT 1
`;

export const DEMO_ATTACK_META_QUERY = `
SELECT
  anyHeavy(attack_id) AS attack_id,
  anyHeavy(mitre_technique) AS mitre_technique,
  anyHeavy(phase) AS phase
FROM attack_labels
WHERE label_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND replaceOne(toString(src_ip), '::ffff:', '') = {srcIp:String}
GROUP BY replaceOne(toString(src_ip), '::ffff:', '')
`;

export const DEMO_ATTACK_LABEL_EVENTS_QUERY = `
SELECT
  toString(label_time) AS event_time,
  'attack_label' AS stage,
  mitre_technique AS key,
  phase AS value,
  attack_id AS detail
FROM attack_labels
WHERE label_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND replaceOne(toString(src_ip), '::ffff:', '') = {srcIp:String}
ORDER BY label_time ASC
LIMIT {limit:UInt32}
`;

export const DEMO_SIP_BURST_QUERY = `
SELECT
  toString(bucket) AS event_time,
  'sip' AS stage,
  method AS key,
  toString(cnt) AS value,
  concat('SIP ', method, ' burst') AS detail
FROM (
  SELECT toStartOfMinute(event_time) AS bucket, method, count() AS cnt
  FROM sip_events
  WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
    AND replaceOne(toString(src_ip), '::ffff:', '') = {srcIp:String}
  GROUP BY bucket, method
)
ORDER BY bucket ASC
LIMIT {limit:UInt32}
`;

export const DEMO_SURICATA_EVENTS_QUERY = `
SELECT
  event_time,
  'suricata' AS stage,
  signature AS key,
  toString(sig_id) AS value,
  category AS detail
FROM suricata_alerts
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND src_ip = {srcIp:String}
ORDER BY event_time ASC
LIMIT {limit:UInt32}
`;

export const DEMO_WAZUH_EVENTS_QUERY = `
SELECT
  toString(alert_time) AS event_time,
  'wazuh' AS stage,
  toString(rule_id) AS key,
  toString(rule_level) AS value,
  rule_description AS detail
FROM wazuh_alerts
WHERE alert_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND srcip = {srcIp:String}
  AND rule_id BETWEEN 100100 AND 100199
ORDER BY alert_time ASC
LIMIT {limit:UInt32}
`;

export const DEMO_ML_EVENTS_QUERY = `
SELECT
  toString(scored_at) AS event_time,
  'ml' AS stage,
  predicted_class AS key,
  toString(round(proba, 3)) AS value,
  'Stage 1 scorer' AS detail
FROM ml_scores
WHERE scored_at >= now() - INTERVAL {hours:UInt32} HOUR
  AND replaceOne(toString(src_ip), '::ffff:', '') = {srcIp:String}
ORDER BY scored_at ASC
LIMIT {limit:UInt32}
`;

export const DEMO_LLM_EVENTS_QUERY = `
SELECT
  toString(verdict_time) AS event_time,
  'llm' AS stage,
  verdict AS key,
  toString(round(confidence, 3)) AS value,
  'Advisory triage' AS detail
FROM llm_verdicts
WHERE verdict_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND replaceOne(toString(src_ip), '::ffff:', '') = {srcIp:String}
ORDER BY verdict_time ASC
LIMIT {limit:UInt32}
`;

export const DEMO_BAN_EVENTS_QUERY = `
SELECT
  event_time,
  'ban' AS stage,
  action AS key,
  reason AS value,
  concat('min_level=', toString(min_level)) AS detail
FROM ban_audit
WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
  AND src_ip = {srcIp:String}
ORDER BY event_time ASC
LIMIT {limit:UInt32}
`;

// Live honeypot: external (non-internal) sources hitting the public SIP edge, with the
// methods they used, first/last seen, and whether autoban has banned them.
export const EXTERNAL_ATTACKERS_QUERY = `
WITH banned AS (
  SELECT DISTINCT src_ip FROM ban_audit
  WHERE action = 'ban' AND event_time >= now() - INTERVAL {hours:UInt32} HOUR
)
SELECT
  ip,
  count() AS events,
  arrayStringConcat(arraySlice(groupUniqArray(method), 1, 8), ', ') AS methods,
  arrayStringConcat(arraySlice(groupUniqArrayIf(user_agent, user_agent != ''), 1, 5), ' | ') AS user_agents,
  min(event_time) AS first_seen,
  max(event_time) AS last_seen,
  ip IN (SELECT src_ip FROM banned) AS banned
FROM (
  SELECT
    replaceOne(toString(src_ip), '::ffff:', '') AS ip,
    method,
    user_agent,
    event_time
  FROM sip_events
  WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR
)
WHERE NOT (
  -- RFC1918 / loopback / link-local / CGNAT / unspecified. Anchored prefix
  -- matches on the IPv4-mapped-stripped literal, so public addresses that
  -- merely contain these octet sequences (41.127.x.x, 3.172.18.x) are kept.
  ip LIKE '10.%'
  OR ip LIKE '192.168.%'
  OR ip LIKE '127.%'
  OR ip LIKE '169.254.%'
  OR (ip LIKE '172.%' AND toUInt8OrZero(splitByChar('.', ip)[2]) BETWEEN 16 AND 31)
  OR (ip LIKE '100.%' AND toUInt8OrZero(splitByChar('.', ip)[2]) BETWEEN 64 AND 127)
  OR ip = '0.0.0.0'
  OR ip = '::'
  OR ip = '::1'
  OR lower(ip) LIKE 'fe80:%'
  OR lower(ip) LIKE 'fc%'
  OR lower(ip) LIKE 'fd%'
)
GROUP BY ip
ORDER BY events DESC
LIMIT {limit:UInt32}
`;
