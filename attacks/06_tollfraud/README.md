# 06 - Toll Fraud

Phase 6 attack scripts. Attempts premium-prefix dialplan abuse through Kamailio and writes a ground-truth label to `ngn_sip.attack_labels`.

## Scripts

| Script | Tool | MITRE | Expected detection |
|---|---|---|---|
| `dialplan_abuse.sh` | SIPp (`ngn-sip/sipp:3.7.3`) | T1496 | Premium-rate INVITE URI from a lab SIPp user agent |

`dialplan_abuse.sh` sends a single INVITE toward a US premium-rate destination, `sip:${PREMIUM_NUMBER}@kamailio` with `PREMIUM_NUMBER` defaulting to `+19005550123` (validated against `^\+1900[0-9]{7}$`), from caller `1000`, tagged `User-Agent: ngn-sip-dialplan-abuse`. It launches a hardened, detached SIPp container (`--cap-drop ALL`, `--read-only`, `--memory 128m`, `--cpus 0.25`) on the lab bridge, resolves the container's own IP, then runs SIPp for one call (`-m 1 -r 1 -l 1`, 5s timeout). The target is locked to `kamailio:5060`; other hosts/ports are refused.

If SIPp exits non-zero the run continues and still labels the attempted abuse. The label is emitted via `attacks.orchestrator.label_emitter` (category `tollfraud`, technique `T1496`) with a `premium_uri=...` detail.

Known false-positive scenario: authorized telecom routing tests using premium or international prefixes.

## Run

```bash
python -m attacks.orchestrator.run_phase --phase 6
```
