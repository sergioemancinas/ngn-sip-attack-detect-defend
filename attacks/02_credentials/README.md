# 02 - Credentials

Phase 2 attack scripts. Targets SIP digest authentication via brute-force and weak-credential abuse.

## Scripts

| Script | Tool | MITRE | Expected detection |
|---|---|---|---|
| `sippts_svcrack.sh` | sippts svcrack | T1110.001 | Wazuh sid 100102 (Kamailio auth-fail burst), 100105 (Asterisk PJSIP burst) |

## Wordlist

`wordlists/short.txt` holds 30 well-known weak SIP creds (1234, 0000, voicemail, asterisk, ...). Replace with rockyou or a project-specific list when running adversarial-strength evaluations.

## Run

```bash
python -m attacks.orchestrator.run_phase --phase 2
```

Tool wrappers run against the `ngn-sip/attacker:v1` image (sippts v4.1.2), shipped by `docker-compose.attack.yml`.
