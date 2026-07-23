# Wazuh manager advanced hardening and tuning

Apply these settings on local/dev only with loopback-bound ports (`DEV_BIND_IP=127.0.0.1`).

## Files

- `ossec_advanced.conf`: hardened/tuned manager blocks to append to `ossec.conf`.
- `ossec_docker_listener.conf`: legacy standalone docker-listener snippet (already included in `ossec_advanced.conf`).

## Apply procedure

1. Start or refresh Wazuh:
   ```bash
   DEV_BIND_IP=127.0.0.1 docker compose -f docker-compose.wazuh.yml up -d
   ```
1. Ensure Kamailio logs are mounted into manager at:
   `/wazuh-logcollector/var/log/kamailio/kamailio.log`.
   If this path is not mounted, wire the `wazuh-logcollector` volume/bind first.
1. Copy the advanced configuration file into the manager container:
   ```bash
   docker cp siem/wazuh/manager/ossec_advanced.conf ngn-sip-wazuh-wazuh-manager-1:/tmp/ossec_advanced.conf
   ```
1. Append it as an additional `<ossec_config>` block (idempotent guard included):
   ```bash
   docker exec ngn-sip-wazuh-wazuh-manager-1 /bin/sh -lc "python3 - <<'PY'
   from pathlib import Path

   conf_path = Path('/var/ossec/etc/ossec.conf')
   extra_path = Path('/tmp/ossec_advanced.conf')
   marker = '<location>/wazuh-logcollector/var/log/kamailio/kamailio.log</location>'

   conf = conf_path.read_text()
   extra = extra_path.read_text().strip()

   if marker not in conf:
       conf_path.write_text(conf.rstrip() + '\n\n' + extra + '\n')
   PY"
   ```
1. Restart Wazuh manager:
   ```bash
   docker exec ngn-sip-wazuh-wazuh-manager-1 /var/ossec/bin/wazuh-control restart
   ```
1. Verify key blocks were loaded:
   ```bash
   docker exec ngn-sip-wazuh-wazuh-manager-1 /bin/sh -lc "grep -nE 'logall|jsonout_output|vulnerability-detector|open-scap|docker-listener|kamailio.log' /var/ossec/etc/ossec.conf"
   ```

## What each tuning achieves

| Section | Setting highlights | Operational impact |
|---|---|---|
| `<global>` | `logall=yes`, `jsonout_output=yes`, `alerts_log=yes`, `email_notification=no` | Keeps full event/archive visibility in files and JSON index pipeline while disabling noisy email transport. |
| `<alerts>` | `log_alert_level=3`, `email_alert_level=12` | Retains lower-severity events in alert logs while reserving email-level threshold for only high-critical events if email is enabled later. |
| `<remote>` | `queue_size=262144`, `connection_overtake_time=600`, `rids_closing_time=30m` | Improves manager resilience under higher agent/event concurrency and reduces stale connection churn. |
| `<vulnerability-detector>` | Enabled with Debian, Ubuntu (Canonical), and RedHat providers | Enables CVE correlation coverage for the Linux families used across lab images/hosts. |
| `<rootcheck>` | `frequency=3600` | Schedules hourly rootkit/policy checks for tighter integrity monitoring cadence. |
| `<wodle name='syscollector'>` | `disabled=no`, `interval=1h` | Maintains hourly host inventory updates for software/package/port context used by vulnerability and threat triage. |
| `<wodle name='docker-listener'>` | Included at `interval=1m` | Keeps container lifecycle telemetry flowing into Wazuh rules (already part of this baseline). |
| `<wodle name='open-scap'>` | Enabled with `interval=1d` | Enables daily OpenSCAP evaluation scheduling. |
| `<localfile>` | Kamailio file targets via `/wazuh-logcollector/.../kamailio.log` | Ingests SIP proxy logs into manager analysis without requiring direct container shell access. |
| `<integration>` stubs | Commented Slack and PagerDuty templates | Provides ready-to-wire integrations without shipping webhook/API secrets in git. |
