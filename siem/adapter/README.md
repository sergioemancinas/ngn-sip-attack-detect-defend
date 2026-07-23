# Kamailio to Wazuh NGN-SEC adapter

Bridges the SIP detections already in ClickHouse to the Wazuh SIP
correlation ruleset. Without it, most of the 100100..100134 rules are
dead because Kamailio does not emit the `NGN-SEC` reason strings they
match (measured under live internet exposure: 4 of 35 rules fired). The
adapter reads `sip_events` and `suricata_alerts` and emits, in the exact
format the `kamailio` decoder parses:

    NGN-SEC <event_type> src=<ip> ua="<ua>" reason="<reason>"

## Mapping (validated against live data)

| Source condition (ClickHouse) | NGN-SEC line | Wazuh rules |
|---|---|---|
| `method=REGISTER` | `REGISTER reason=register` | 100108 (flood) |
| `method=INVITE` | `INVITE reason=invite` | 100111 (flood) |
| INVITE `to_uri` premium prefix (1900/1809/1268/1976/976/979) | `INVITE reason=dst=+<num>` | 100118 / 100119 (toll fraud) |
| `method=OPTIONS` | `OPTIONS reason=keepalive` | 100125 / 100126 / 100127 |
| `method=SUBSCRIBE` / `NOTIFY` | matching event_type | 100122 / 100123 |
| Suricata sid 1000006 | `INVITE reason=malformed_via` | 100113 |
| Suricata sid 1000007 | `INVITE reason=malformed_cseq` | 100114 |

Per-source, per-condition rate caps (`MAX_PER_SRC`) let the Wazuh
frequency rules trip without recreating a log flood. Sources are scoped
to external addresses (`EXTERNAL_ONLY=1`) so lab hosts are not emitted.

Credential brute force is intentionally not mapped from 401/403: the
response row carries the server address (0.0.0.0), not the attacker, and
does not share `call_id` with the REGISTER in this schema. That signal
is covered by the REGISTER-volume and REGISTER+scanner-UA rules
(100108/100109), which key on the real request source.

## Deploy

1. Add the localfile to the manager `ossec.conf` (next to the existing
   `ngnsec/kamailio-sec.log` entry) and restart the manager:
   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>/var/ossec/logs/ngnsec/kamailio-ngnsec.log</location>
   </localfile>
   ```
2. Bring up the adapter:
   ```
   docker compose -p ngn-sip \
     -f docker-compose.wazuh.yml -f docker-compose.adapter.yml \
     up -d --build kamailio-wazuh-adapter
   ```
3. Verify it reaches ClickHouse and emits lines:
   ```
   docker logs ngn-sip-kamailio-wazuh-adapter-1 --tail 20
   docker exec ngn-sip-wazuh-manager-1 tail -f /var/ossec/logs/ngnsec/kamailio-ngnsec.log
   ```
4. Confirm the previously-dead rules now fire:
   ```
   docker exec ngn-sip-clickhouse-1 clickhouse-client -q \
     "SELECT rule_id, count() FROM ngn_sip.wazuh_alerts WHERE rule_id BETWEEN 100108 AND 100134 AND alert_time > now() - INTERVAL 10 MINUTE GROUP BY rule_id ORDER BY rule_id"
   ```

`CLICKHOUSE_USER`/`CLICKHOUSE_PASSWORD` default to the `ngn` app user;
set them in the VM `.env`. If the HTTP user is rejected, confirm the
running ClickHouse password (there is known `.env` drift on this stack).
