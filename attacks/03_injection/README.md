# 03 - Injection

Phase 3 attack scripts. Sends crafted / malformed SIP INVITE traffic at the local Kamailio lab target and writes a ground-truth label to `ngn_sip.attack_labels`.

## Scripts

| Script | Tool | MITRE | Expected detection |
|---|---|---|---|
| `sippts_malformed_invite.sh` | SIPp (`ngn-sip/sipp:3.7.3`) | T1190 | Suricata SIDs 1000006, 1000007, 1000008 |
| `sippts_smap_invite.sh` | SIPp (`ngn-sip/sipp:3.7.3`) | T1190 | Suricata SIDs 1000003, 1000007, 1000008 |

Both scripts run SIPp inside a hardened container (`--cap-drop ALL`, `--read-only`, `--memory 128m`, `--cpus 0.25`) attached to the lab bridge, and refuse any target other than `kamailio:5060` on the `ngn-sip_sip_lab` / `sip_lab` network.

- `sippts_malformed_invite.sh` sends an INVITE for `sip:1000@...` with a deliberately malformed `Via` header (`Via: sippts-malformed-[call_number]`, no `SIP/2.0/UDP` transport or branch) and `User-Agent: sippts`. Defaults: `CALLS=10`, `RATE=2`/s.
- `sippts_smap_invite.sh` sends an smap-style probe INVITE with a malformed `CSeq` (`CSeq: smap INVITE`, missing the numeric sequence) and `User-Agent: sippts smap`, targeting a configurable `EXTENSION` (default `1000`). Defaults: `CALLS=5`, `RATE=1`/s.

Each script ends by emitting a label via `attacks.orchestrator.label_emitter` (category `injection`, technique `T1190`).

## Run

```bash
python -m attacks.orchestrator.run_phase --phase 3
```

Requires the lab stack up (`make up`) so the `ngn-sip_sip_lab` network and the `ngn-sip/sipp:3.7.3` image exist; both scripts exit early if either is missing.
