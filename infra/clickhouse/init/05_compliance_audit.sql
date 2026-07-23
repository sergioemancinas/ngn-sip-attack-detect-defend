-- Compliance evidence and immutable audit stream for scoring and reference-network evidence.

CREATE DATABASE IF NOT EXISTS ngn_sip;

CREATE TABLE IF NOT EXISTS ngn_sip.compliance_evidence (
    evidence_time  DateTime64(3, 'UTC') DEFAULT now64(3),
    framework      LowCardinality(String),
    control_id     LowCardinality(String),
    control_title  String,
    maturity       Enum8('planned' = 1, 'implemented' = 2, 'gap' = 3),
    evidence_type  LowCardinality(String),
    artifact_ref   String,
    query_text     String CODEC(ZSTD(3)),
    result_hash    String,
    owner          LowCardinality(String) DEFAULT 'ngn-sip-lab',
    retention_days UInt16 DEFAULT 2555,
    payload_json   String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(evidence_time)
ORDER BY (framework, control_id, evidence_time)
TTL toDateTime(evidence_time) + INTERVAL 2555 DAY;

CREATE TABLE IF NOT EXISTS ngn_sip.audit_log (
    event_time      DateTime64(3, 'UTC') DEFAULT now64(3),
    actor           LowCardinality(String),
    action          LowCardinality(String),
    object_type     LowCardinality(String),
    object_id       String,
    source_ip       IPv6,
    request_id      String,
    previous_hash   String,
    entry_hash      String,
    payload_json    String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (event_time, entry_hash);

-- Operational immutability rule:
-- grant INSERT and SELECT to collectors/readers; reserve ALTER, DELETE, TRUNCATE, and DROP for break-glass admins only.
CREATE MATERIALIZED VIEW IF NOT EXISTS ngn_sip.mv_score_audit_to_audit_log
TO ngn_sip.audit_log
AS SELECT
    audit_time AS event_time,
    'scoring-engine' AS actor,
    'score_audit_written' AS action,
    'score' AS object_type,
    toString(score_event_id) AS object_id,
    toIPv6('::') AS source_ip,
    provenance_hash AS request_id,
    '0000000000000000000000000000000000000000000000000000000000000000' AS previous_hash,
    lower(hex(SHA256(concat(
        toString(audit_time),
        toString(score_event_id),
        source_event_hash,
        scorer_version,
        scorer_config_hash,
        provenance_hash
    )))) AS entry_hash,
    concat(
        '{"source":"', toString(source),
        '","source_event_hash":"', source_event_hash,
        '","scorer_version":"', scorer_version,
        '","scorer_config_hash":"', scorer_config_hash,
        '"}'
    ) AS payload_json
FROM ngn_sip.score_audit;

