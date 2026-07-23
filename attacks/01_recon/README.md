# 01 - Reconnaissance

Phase 1 attack scripts. Each script enumerates the SIP listener and writes a ground-truth label to `ngn_sip.attack_labels` so the synthetic dataset is reproducibly labeled.

## Scripts

| Script | Tool | MITRE | Expected detection |
|---|---|---|---|
| `sipvicious_svmap.sh` | sipvicious / sippts svmap | T1595.001 | Wazuh sid 100107 (scanner UA), Suricata custom rule |
| `sippts_options_scan.sh` | sippts scan -m OPTIONS | T1595 | Suricata SIP rule on OPTIONS volume from one source |

## Run

```bash
make up                                                # core SIP stack
make obs-up                                            # ClickHouse must be reachable
python -m attacks.orchestrator.run_phase --phase 1     # runs every script in this directory
```

Tool wrappers run against the `ngn-sip/attacker:v1` image (sippts v4.1.2), shipped by `docker-compose.attack.yml`.
