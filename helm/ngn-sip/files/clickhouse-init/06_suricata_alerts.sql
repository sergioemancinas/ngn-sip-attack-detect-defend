-- Suricata EVE alerts ingested from /var/log/suricata/eve.json by Vector.
-- Loaded into the ngn_sip database by the ClickHouse entrypoint on first boot.

CREATE TABLE IF NOT EXISTS ngn_sip.suricata_alerts
(
    event_time      DateTime64(3),
    event_type      LowCardinality(String),
    src_ip          String,
    src_port        UInt16,
    dest_ip         String,
    dest_port       UInt16,
    proto           LowCardinality(String),
    sig_id          UInt32,
    sig_rev         UInt8,
    signature       String,
    category        LowCardinality(String),
    severity        UInt8,
    sip_method      LowCardinality(String),
    sip_request_uri String,
    sip_user_agent  String,
    sip_call_id     String,
    raw_message     String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (event_time, src_ip, sig_id)
TTL toDateTime(event_time) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- 5-minute aggregation for Stage 1 ML features. Same SummingMergeTree pattern
-- as sip_features_5min in 02_materialized_views.sql.
CREATE TABLE IF NOT EXISTS ngn_sip.suricata_alerts_5min
(
    bucket          DateTime,
    src_ip          String,
    sig_id          UInt32,
    severity        UInt8,
    alert_count     UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(bucket)
ORDER BY (bucket, src_ip, sig_id);

CREATE MATERIALIZED VIEW IF NOT EXISTS ngn_sip.mv_suricata_alerts_5min
TO ngn_sip.suricata_alerts_5min AS
SELECT
    toStartOfFiveMinutes(event_time) AS bucket,
    src_ip,
    sig_id,
    severity,
    count()                          AS alert_count
FROM ngn_sip.suricata_alerts
GROUP BY bucket, src_ip, sig_id, severity;
