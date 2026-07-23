-- Ban audit trail for the kamailio-autoban active-response sidecar: every
-- ban / protected-skip / rejected input gets an evidence record so the defend
-- action is measurable, auditable, and reversible.
-- Loaded into the ngn_sip database by the ClickHouse entrypoint on first boot.
-- siem/wazuh/active-response/autoban_loop.sh creates the same table at
-- runtime; both use IF NOT EXISTS so whichever runs first wins and the other
-- is a no-op.

CREATE TABLE IF NOT EXISTS ngn_sip.ban_audit
(
    event_time  DateTime64(3) DEFAULT now64(3),
    src_ip      String,
    action      LowCardinality(String),
    reason      String,
    min_level   UInt16,
    ttl_seconds UInt32
)
ENGINE = MergeTree
ORDER BY event_time
-- Bound audit growth, consistent with soar_cases (365d) and the other tables'
-- TTL discipline. 1 year is ample retention for lab enforcement evidence.
TTL toDateTime(event_time) + INTERVAL 365 DAY;
