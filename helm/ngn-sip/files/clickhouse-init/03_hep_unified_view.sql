-- C1 HEP bridge: helper view for response-level telemetry QA (non-destructive).
-- Suricata rows remain source='suricata'; HEP rows arrive as source='hep'.

CREATE VIEW IF NOT EXISTS ngn_sip.sip_events_by_source AS
SELECT
    source,
    count() AS rows,
    countIf(response_code > 0) AS responses,
    countIf(response_code = 0 AND method != '') AS requests,
    min(event_time) AS first_event,
    max(event_time) AS last_event
FROM ngn_sip.sip_events
GROUP BY source;

CREATE VIEW IF NOT EXISTS ngn_sip.sip_response_codes AS
SELECT
    response_code,
    response_phrase,
    source,
    count() AS cnt
FROM ngn_sip.sip_events
WHERE response_code > 0
GROUP BY response_code, response_phrase, source
ORDER BY cnt DESC;
