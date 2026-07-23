# 04 - Denial of Service

Phase 4 attack scripts. Drives a high-volume SIP REGISTER flood at Kamailio and writes a ground-truth label to `ngn_sip.attack_labels`.

## Scripts

| Script | Tool | MITRE | Expected detection |
|---|---|---|---|
| `sipp_register_flood.sh` | SIPp (`ngn-sip/sipp:3.7.3`) | T1499 | SIP REGISTER burst, Kamailio pike/secfilter counters, Wazuh/SIEM volume anomalies |

`sipp_register_flood.sh` replays the `sipp_register_flood.xml` scenario, a single REGISTER `send` followed by optional `recv` of 401/403/404/407/200. It generates a per-call CSV injection file spoofing synthetic source identities and IPs from the `198.18.0.0/15` benchmarking prefix (`SYNTHETIC_NET_PREFIX`, default `198.18`), one row per call. Defaults: `REGISTER_RATE=50`/s, `DURATION_SECONDS=30` (so `CALLS = 1500`), `CONCURRENCY_LIMIT=300`. The scenario tags each REGISTER with `User-Agent: ngn-sip-sipp-register-flood` and an `X-Synthetic-Source-IP` header.

SIPp runs in a hardened container (`--cap-drop ALL`, `--read-only`, `--memory 128m`, `--cpus 0.5`) on the lab bridge. The script refuses any target other than `kamailio` unless `ALLOW_NONLOCAL_TARGET=1`, and requires the `ngn-sip_sip_lab` network and the `ngn-sip/sipp:3.7.3` image to already exist. It then emits a label via `attacks.orchestrator.label_emitter` (category `dos`, technique `T1499`).

Known false-positive scenario: mass softphone reconnect after a network outage or PBX restart.

## Run

```bash
python -m attacks.orchestrator.run_phase --phase 4
```
