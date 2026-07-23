-- ngn-sip ClickHouse schema: raw SIP signaling events + ground-truth labels + raw log stream.
-- Source: Vector (HEP/syslog from Kamailio + Asterisk + attack orchestrator).
-- Engine: MergeTree, partitioned by day, ordered by (event_time, src_ip, method).
-- TTL: 90 days for raw events; rollups in 02_materialized_views.sql retain longer.

CREATE DATABASE IF NOT EXISTS ngn_sip;

CREATE TABLE IF NOT EXISTS ngn_sip.sip_events (
    event_time      DateTime64(3, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    ingested_at     DateTime64(3, 'UTC') DEFAULT now64(3),
    source          LowCardinality(String),
    src_ip          IPv6,
    src_port        UInt16,
    dst_ip          IPv6,
    dst_port        UInt16,
    transport       LowCardinality(String),
    method          LowCardinality(String),
    response_code   UInt16,
    response_phrase String,
    call_id         String,
    from_uri        String,
    to_uri          String,
    user_agent      String,
    cseq            String,
    body_size       UInt32,
    raw_message     String CODEC(ZSTD(3)),
    attack_id       LowCardinality(String) DEFAULT '',
    mitre_technique LowCardinality(String) DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toDate(event_time)
ORDER BY (event_time, src_ip, method)
TTL toDateTime(event_time) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS ngn_sip.attack_labels (
    label_time      DateTime64(3, 'UTC'),
    src_ip          IPv6,
    attack_id       LowCardinality(String),
    mitre_technique LowCardinality(String),
    phase           LowCardinality(String),
    notes           String
)
ENGINE = MergeTree
PARTITION BY toDate(label_time)
ORDER BY (label_time, src_ip)
TTL toDateTime(label_time) + INTERVAL 365 DAY;

-- Raw log stream from Vector, pre-parsing.
-- Columns match Vector's default field names so the ClickHouse sink works without remap.
CREATE TABLE IF NOT EXISTS ngn_sip.raw_logs (
    timestamp   DateTime64(3, 'UTC') DEFAULT now64(3),
    source      LowCardinality(String) DEFAULT '',
    host        String DEFAULT '',
    file        String DEFAULT '',
    message     String,
    level       LowCardinality(String) DEFAULT '',
    module      String DEFAULT ''
)
ENGINE = MergeTree
PARTITION BY toDate(timestamp)
ORDER BY (timestamp, source)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;
