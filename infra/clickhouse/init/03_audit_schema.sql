-- Stage 2 LLM verdict audit trail.
-- Every triage call writes one row: input alert hash, RAG context refs, verdict, guardrail outcomes.

CREATE TABLE IF NOT EXISTS ngn_sip.llm_verdicts (
    verdict_time           DateTime64(3, 'UTC') DEFAULT now64(3),
    alert_id               String,
    alert_rule_id          UInt32,
    alert_hash             String,
    src_ip                 IPv6,
    verdict                LowCardinality(String),
    confidence             Float32,
    reasoning              String,
    rag_context_ids        Array(String),
    guardrail_json_pass    UInt8,
    guardrail_ner_pass     UInt8,
    guardrail_self_consist UInt8,
    latency_ms             UInt32,
    model                  LowCardinality(String) DEFAULT 'qwen2.5:7b-instruct-q4_K_M'
)
ENGINE = MergeTree
PARTITION BY toDate(verdict_time)
ORDER BY (verdict_time, alert_id)
TTL toDateTime(verdict_time) + INTERVAL 365 DAY;
