-- Wazuh alerts ingested from alerts.json by Vector.

CREATE TABLE IF NOT EXISTS ngn_sip.wazuh_alerts
(
    alert_time       DateTime64(3),
    agent_id         String,
    agent_name       String,
    rule_id          UInt32,
    rule_level       UInt8,
    rule_description String,
    rule_groups      Array(String),
    rule_mitre_id    Array(String),
    srcip            String,
    location         String,
    raw_message      String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(alert_time)
ORDER BY (alert_time, rule_id)
TTL toDateTime(alert_time) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;
