# SOAR

This directory holds the SOAR layer for the lab.

## Active: Shuffle

`shuffle/` is the single SOAR. Stage 3 orchestrates the response to Wazuh alerts: normalize, deduplicate, enrich from ClickHouse (Stage 1/2 + Suricata), apply a graded policy, optionally ban via the kamcmd contract, write `ngn_sip.soar_cases`, and notify operators. The deterministic backstop remains `kamailio-autoban` (`siem/wazuh/active-response/autoban_loop.sh`), which always polls and writes `ngn_sip.ban_audit`.

- Compose: `docker-compose.soar.yml` (`make soar-up`).
- Workflow (Stage 3): `shuffle/workflows/sip_response_orchestration.json`.
- Runbook: `docs/09_soar_runbook.md`.
- Wiring: `siem/wazuh/integrations/` posts level >= 10 SIP alerts to the Shuffle hook.

ClickHouse (`ngn_sip.soar_cases`) is the case/audit store; there is no separate case-management service.
