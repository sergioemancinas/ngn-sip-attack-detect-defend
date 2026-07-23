-- Stage 3 SOAR case/evidence table for the Shuffle orchestration workflow
-- (soar/shuffle/workflows/sip_response_orchestration.json): one append-only
-- row per orchestration execution with the graded action, the Stage 1/2
-- enrichment snapshot, and dedup/notification metadata. DDL is the schema
-- documented in docs/09_soar_runbook.md.
-- Loaded into the ngn_sip database by the ClickHouse entrypoint on first
-- boot; IF NOT EXISTS keeps it a no-op when the table was already created
-- manually per the runbook.

CREATE TABLE IF NOT EXISTS ngn_sip.soar_cases
(
    case_time            DateTime64(3, 'UTC') DEFAULT now64(3),
    case_id              String,
    src_ip               String,
    wazuh_rule_id        UInt32,
    wazuh_rule_level     UInt16,
    graded_action        LowCardinality(String),
    stage2_verdict       LowCardinality(String) DEFAULT '',
    stage2_confidence    Float32 DEFAULT 0,
    ml_attack_score      Float32 DEFAULT 0,
    ml_predicted_label   LowCardinality(String) DEFAULT '',
    suricata_alert_count UInt32 DEFAULT 0,
    dedup_key            String,
    workflow_id          LowCardinality(String),
    execution_id         String,
    notify_sent          UInt8 DEFAULT 0,
    evidence_json        String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toDate(case_time)
ORDER BY (case_time, src_ip, case_id)
TTL toDateTime(case_time) + INTERVAL 365 DAY;
