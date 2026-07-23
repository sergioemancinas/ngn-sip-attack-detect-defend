# Kamailio Tests

Placeholder for Kamailio-specific SIP and configuration regression checks. Runtime verification today uses:

- `make smoke` (authenticated SIPp REGISTER + INVITE path)
- `kamcmd htable.*` ban table round-trip
- Wazuh `wazuh-logtest` against NGN-SEC fixtures

Automated cfg syntax checks can be added here when the CI runner has Kamailio packages available.
