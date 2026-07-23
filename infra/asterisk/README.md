# Asterisk

Asterisk 20 LTS PBX service. Dockerfile and `etc/` configuration (PJSIP endpoints, dial plan) for terminating lab SIPp UAs and routing calls through Kamailio.

## Detection relevance

- `chan_pjsip` auth-failure events feed Wazuh rules 100104/100105 (`siem/wazuh/decoders/asterisk.xml`).
- Premium-prefix dial patterns trigger Wazuh 100133 when logged in Asterisk `message` fields.

Logs are tailed by Vector into ClickHouse raw log tables and parsed by the Wazuh manager decoders.
