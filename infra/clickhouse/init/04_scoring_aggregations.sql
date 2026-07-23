-- Enterprise scoring engine schema and rollups.
-- Extends 01_events_schema.sql, 02_materialized_views.sql, and 03_audit_schema.sql.

CREATE DATABASE IF NOT EXISTS ngn_sip;

CREATE TABLE IF NOT EXISTS ngn_sip.event_scores (
    event_time          DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    ingested_at         DateTime64(3, 'UTC') DEFAULT now64(3),
    event_id            UUID DEFAULT generateUUIDv4(),
    source              Enum8('wazuh' = 1, 'stage1' = 2, 'stage2' = 3, 'fusion' = 4, 'manual' = 5),
    source_event_id     String,
    source_event_hash   String,
    src_ip              IPv6,
    dst_ip              IPv6,
    technique           LowCardinality(String) DEFAULT '',
    mitre_ids           Array(String) DEFAULT [],
    event_type          LowCardinality(String) DEFAULT '',
    method              LowCardinality(String) DEFAULT '',
    wazuh_rule_id       UInt32 DEFAULT 0,
    wazuh_rule_level    UInt8 DEFAULT 0,
    stage1_model        LowCardinality(String) DEFAULT '',
    stage1_probability  Float64 DEFAULT 0,
    stage2_model        LowCardinality(String) DEFAULT '',
    stage2_verdict      LowCardinality(String) DEFAULT '',
    stage2_confidence   Float64 DEFAULT 0,
    cvss_vector         String DEFAULT '',
    cvss_score          Float64 DEFAULT 0,
    fused_probability   Float64 DEFAULT 0,
    risk_score          Float64,
    risk_bucket         Enum8('none' = 0, 'low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    half_life_seconds   UInt32 DEFAULT 86400,
    payload_json        String CODEC(ZSTD(3)),
    provenance_json     String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toDate(event_time)
ORDER BY (event_time, src_ip, technique, source)
TTL toDateTime(event_time) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS ngn_sip.score_audit (
    audit_time          DateTime64(3, 'UTC') DEFAULT now64(3),
    score_event_id      UUID,
    source              Enum8('wazuh' = 1, 'stage1' = 2, 'stage2' = 3, 'fusion' = 4, 'manual' = 5),
    source_event_hash   String,
    source_event_refs   Array(String) DEFAULT [],
    scorer_version      LowCardinality(String),
    scorer_config_hash  String,
    cvss_vector         String,
    fusion_weights_json String CODEC(ZSTD(3)),
    calibration_json    String CODEC(ZSTD(3)),
    provenance_hash     String,
    notes               String DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toDate(audit_time)
ORDER BY (audit_time, source_event_hash, score_event_id)
TTL toDateTime(audit_time) + INTERVAL 365 DAY;

CREATE TABLE IF NOT EXISTS ngn_sip.score_5min (
    event_time   DateTime,
    src_ip       IPv6,
    technique    LowCardinality(String),
    source       Enum8('wazuh' = 1, 'stage1' = 2, 'stage2' = 3, 'fusion' = 4, 'manual' = 5),
    score_sum    AggregateFunction(sum, Float64),
    score_count  AggregateFunction(count),
    max_score    SimpleAggregateFunction(max, Float64),
    mitre_ids    Array(String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(event_time)
ORDER BY (event_time, src_ip, technique, source)
TTL event_time + INTERVAL 730 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS ngn_sip.mv_event_scores_to_score_5min
TO ngn_sip.score_5min
AS SELECT
    toStartOfFiveMinute(toDateTime(event_time)) AS event_time,
    src_ip,
    technique,
    source,
    sumState(risk_score) AS score_sum,
    countState() AS score_count,
    max(risk_score) AS max_score,
    arrayDistinct(arrayFlatten(groupArray(mitre_ids))) AS mitre_ids
FROM ngn_sip.event_scores
GROUP BY event_time, src_ip, technique, source;

CREATE TABLE IF NOT EXISTS ngn_sip.score_1h (
    event_time   DateTime,
    src_ip       IPv6,
    technique    LowCardinality(String),
    source       Enum8('wazuh' = 1, 'stage1' = 2, 'stage2' = 3, 'fusion' = 4, 'manual' = 5),
    score_sum    Float64,
    score_count  UInt64,
    max_score    Float64,
    mitre_ids    Array(String)
)
ENGINE = SummingMergeTree((score_sum, score_count))
PARTITION BY toDate(event_time)
ORDER BY (event_time, src_ip, technique, source)
TTL event_time + INTERVAL 730 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS ngn_sip.mv_score_5min_to_score_1h
TO ngn_sip.score_1h
AS SELECT
    toStartOfHour(event_time) AS event_time,
    src_ip,
    technique,
    source,
    sum(finalizeAggregation(score_sum)) AS score_sum,
    sum(finalizeAggregation(score_count)) AS score_count,
    max(max_score) AS max_score,
    arrayDistinct(arrayFlatten(groupArray(mitre_ids))) AS mitre_ids
FROM ngn_sip.score_5min
GROUP BY event_time, src_ip, technique, source;

CREATE TABLE IF NOT EXISTS ngn_sip.score_1d (
    event_time   DateTime,
    src_ip       IPv6,
    technique    LowCardinality(String),
    source       Enum8('wazuh' = 1, 'stage1' = 2, 'stage2' = 3, 'fusion' = 4, 'manual' = 5),
    score_sum    Float64,
    score_count  UInt64,
    max_score    Float64,
    mitre_ids    Array(String)
)
ENGINE = SummingMergeTree((score_sum, score_count))
PARTITION BY toYYYYMM(event_time)
ORDER BY (event_time, src_ip, technique, source)
TTL event_time + INTERVAL 730 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS ngn_sip.mv_score_1h_to_score_1d
TO ngn_sip.score_1d
AS SELECT
    toStartOfDay(event_time) AS event_time,
    src_ip,
    technique,
    source,
    sum(score_sum) AS score_sum,
    sum(score_count) AS score_count,
    max(max_score) AS max_score,
    arrayDistinct(arrayFlatten(groupArray(mitre_ids))) AS mitre_ids
FROM ngn_sip.score_1h
GROUP BY event_time, src_ip, technique, source;

CREATE VIEW IF NOT EXISTS ngn_sip.stage1_score_features_5min AS
WITH base AS (
    SELECT
        toStartOfFiveMinute(toDateTime(event_time)) AS window_start,
        src_ip,
        count() AS event_count,
        avg(risk_score) AS mean_score,
        quantileTDigest(0.50)(risk_score) AS p50_score,
        quantileTDigest(0.95)(risk_score) AS p95_score,
        quantileTDigest(0.99)(risk_score) AS p99_score,
        max(risk_score) AS max_score,
        sumMap([method], [toUInt64(1)]) AS method_histogram,
        sumMap([event_type], [toUInt64(1)]) AS event_type_histogram,
        countIf(source = 'wazuh') AS wazuh_count,
        countIf(source = 'stage1') AS stage1_count,
        countIf(source = 'stage2') AS stage2_count,
        countIf(source = 'fusion') AS fusion_count
    FROM ngn_sip.event_scores
    GROUP BY window_start, src_ip
)
SELECT
    *,
    event_count - lagInFrame(event_count, 1, event_count) OVER (PARTITION BY src_ip ORDER BY window_start) AS event_count_delta,
    mean_score - lagInFrame(mean_score, 1, mean_score) OVER (PARTITION BY src_ip ORDER BY window_start) AS mean_score_delta
FROM base;

CREATE VIEW IF NOT EXISTS ngn_sip.stage1_score_features_1h AS
WITH base AS (
    SELECT
        toStartOfHour(toDateTime(event_time)) AS window_start,
        src_ip,
        count() AS event_count,
        avg(risk_score) AS mean_score,
        quantileTDigest(0.50)(risk_score) AS p50_score,
        quantileTDigest(0.95)(risk_score) AS p95_score,
        quantileTDigest(0.99)(risk_score) AS p99_score,
        max(risk_score) AS max_score,
        sumMap([method], [toUInt64(1)]) AS method_histogram,
        sumMap([event_type], [toUInt64(1)]) AS event_type_histogram,
        countIf(source = 'wazuh') AS wazuh_count,
        countIf(source = 'stage1') AS stage1_count,
        countIf(source = 'stage2') AS stage2_count,
        countIf(source = 'fusion') AS fusion_count
    FROM ngn_sip.event_scores
    GROUP BY window_start, src_ip
)
SELECT
    *,
    event_count - lagInFrame(event_count, 1, event_count) OVER (PARTITION BY src_ip ORDER BY window_start) AS event_count_delta,
    mean_score - lagInFrame(mean_score, 1, mean_score) OVER (PARTITION BY src_ip ORDER BY window_start) AS mean_score_delta
FROM base;

CREATE VIEW IF NOT EXISTS ngn_sip.stage2_rag_context_24h AS
SELECT *
FROM (
    SELECT
        event_time,
        src_ip,
        dst_ip,
        technique,
        mitre_ids,
        event_type,
        method,
        source,
        risk_score,
        risk_bucket,
        cvss_vector,
        source_event_hash,
        payload_json,
        provenance_json,
        row_number() OVER (PARTITION BY src_ip ORDER BY risk_score DESC, event_time DESC) AS rank_within_src
    FROM ngn_sip.event_scores
    WHERE event_time >= now64(3) - INTERVAL 24 HOUR
)
WHERE rank_within_src <= 20;

