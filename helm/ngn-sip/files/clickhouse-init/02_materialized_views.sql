-- 5-minute per-IP feature windows for Stage 1 ML.
-- Auto-populated from sip_events via materialized view; ML service polls this table.

CREATE TABLE IF NOT EXISTS ngn_sip.sip_features_5min (
    window_start     DateTime,
    src_ip           IPv6,
    total_msgs       UInt32,
    register_count   UInt32,
    invite_count     UInt32,
    options_count    UInt32,
    auth_4xx_count   UInt32,
    success_2xx      UInt32,
    error_5xx        UInt32,
    distinct_ua      AggregateFunction(uniq, String),
    distinct_to_uri  AggregateFunction(uniq, String),
    distinct_call_id AggregateFunction(uniq, String),
    sum_body_size    UInt64,
    sample_count     UInt32
)
ENGINE = SummingMergeTree
PARTITION BY toDate(window_start)
ORDER BY (window_start, src_ip)
TTL window_start + INTERVAL 365 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS ngn_sip.mv_sip_features_5min
TO ngn_sip.sip_features_5min
AS SELECT
    toStartOfFiveMinute(event_time) AS window_start,
    src_ip,
    count()                                         AS total_msgs,
    countIf(method = 'REGISTER')                    AS register_count,
    countIf(method = 'INVITE')                      AS invite_count,
    countIf(method = 'OPTIONS')                     AS options_count,
    countIf(response_code IN (401, 403, 407))       AS auth_4xx_count,
    countIf(response_code BETWEEN 200 AND 299)      AS success_2xx,
    countIf(response_code >= 500)                   AS error_5xx,
    uniqState(user_agent)                           AS distinct_ua,
    uniqState(to_uri)                               AS distinct_to_uri,
    uniqState(call_id)                              AS distinct_call_id,
    sum(body_size)                                  AS sum_body_size,
    count()                                         AS sample_count
FROM ngn_sip.sip_events
GROUP BY window_start, src_ip;
