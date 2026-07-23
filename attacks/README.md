# Attacks

The attack execution layer: a six-phase SIP attack playbook plus shared orchestration code. Each script drives a labeled attack against the local lab (Kamailio / Asterisk / rtpengine) and writes a ground-truth row to `ngn_sip.attack_labels`, so the synthetic dataset is reproducibly labeled.

## Phases

| Dir | Phase | Focus |
|---|---|---|
| `01_recon/` | 1 | SIP listener enumeration (sipvicious / sippts svmap, OPTIONS scan) |
| `02_credentials/` | 2 | SIP digest auth brute-force / weak-credential abuse (sippts svcrack) |
| `03_injection/` | 3 | Malformed / smap-style INVITE traffic (SIPp) |
| `04_dos/` | 4 | SIP REGISTER flood (SIPp) |
| `05_media/` | 5 | RTP injection into the media path (Scapy) |
| `06_tollfraud/` | 6 | Premium-prefix dialplan abuse (SIPp) |

Each phase directory holds its own `README.md` documenting the exact scripts, tools, MITRE techniques, and expected detections.

## Orchestrator

`orchestrator/` provides the phase runner and the ground-truth label emitter:

- `run_phase.py` (`python -m attacks.orchestrator.run_phase --phase N`) executes every `*.sh` in `0N_*/` in name order, injecting `TARGET_HOST` / `TARGET_PORT` / `OUTPUT_DIR` and writing a combined per-phase run log. Use `--dry-run` to list scripts without executing.
- `label_emitter.py` writes one `attack_labels` row per attack invocation to ClickHouse.
- `attack_matrix.sh` is the shell-side attack matrix helper.

See `orchestrator/README.md` for the full env-var contract and outputs.

## Run

```bash
make up                                              # core SIP stack
python -m attacks.orchestrator.run_phase --phase 1   # ...through --phase 6
```
