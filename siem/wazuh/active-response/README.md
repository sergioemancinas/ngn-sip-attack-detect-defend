# Wazuh Active Response

Kamailio edge containment scripts and the deployed autoban sidecar that closes the detect-defend loop.

## Deployed path: `kamailio-autoban`

`autoban_loop.sh` runs as the `kamailio-autoban` container sidecar (not native Wazuh AR on the manager image). It:

1. Polls ClickHouse for high-severity Wazuh SIP alerts (`rule_level >= 10`, SIDs 100100–100199).
2. Sets `ban_table` on Kamailio via `kamcmd htable.sets` (1-hour TTL).
3. Skips protected stack IPs via `ban_allowlist` and `NEVER_BAN_IPS` (RFC 3261 Sec 26 anti-spoofing).
4. Writes every ban, skip, and reject to `ngn_sip.ban_audit`.

Tunables: `MIN_LEVEL`, `WINDOW_SECONDS`, `POLL_SECONDS`. Pause for clean campaigns: `docker stop kamailio-autoban`.

## Native Wazuh AR (optional)

`kamcmd_block.sh` is the Wazuh active-response script for direct manager invocation. The lab intentionally documents the autoban sidecar as the authoritative backstop (`docs/09_soar_runbook.md`).

## Evidence

- Ban table demo: `kamcmd htable.dump ban_table` after a triggered ban (see `docs/09_soar_runbook.md`)
- E2E verify: replay `scripts/demo/run_pipeline_demo.sh` and check `ngn_sip.ban_audit`
