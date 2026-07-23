# Kamailio

SIP Session Border Controller (SBC) edge for the lab stack. Dockerfile and modular config under this directory.

## Key paths

| Path | Purpose |
|---|---|
| `kamailio.cfg` | Main entry; `HEP_CAPTURE_ENABLE` toggle for C1 capture |
| `modules/` | PIKE rate limiting, `ban_table`/`ban_allowlist`, NGN-SEC xlog filter, gated secfilter/TLS/digest/topoh |
| `modules/siptrace.cfg` | HEPv3 duplicate to `heplify-server:9060` |
| `modules/htable.cfg` | `ban_table` htable (`autoexpire=3600`) for active response |

Wazuh decoders expect `NGN-SEC` xlog lines with `event_type`, `srcip`, `user_agent`, and `reason` (`siem/wazuh/decoders/kamailio.xml`).

## Verify

```bash
docker compose exec kamailio kamcmd htable.dump ban_table
```

See `docs/03_attack_playbook.md` for attack-facing behaviour. Public SIP exposure is gated behind `SIP_BIND_IP` (loopback by default); see the port comments in `docker-compose.yml`.
