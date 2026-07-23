# Asterisk Tests

Placeholder for Asterisk-focused smoke and regression checks. Current verification:

- `make smoke` full REGISTER/INVITE/BYE through Kamailio to Asterisk
- Wazuh decoder coverage for `chan_pjsip` auth failures (rules 100104, 100105)

Add scripted `asterisk -rx` health checks here when CI gains an Asterisk test container.
