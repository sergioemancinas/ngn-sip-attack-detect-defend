# attacks/orchestrator

Phase-based runner + ground-truth label emitter for the synthetic tier of the project's three-tier evaluation.

## Install (uv-managed)

```bash
cd attacks/orchestrator
uv sync
```

## Run a phase

```bash
# from repo root
python -m attacks.orchestrator.run_phase --phase 1
python -m attacks.orchestrator.run_phase --phase 2 --target-host 127.0.0.1 --target-port 5060
python -m attacks.orchestrator.run_phase --phase 1 --dry-run
```

## Env-var contract

| Var | Default | Purpose |
|---|---|---|
| `TARGET_HOST` | `127.0.0.1` | Kamailio listener |
| `TARGET_PORT` | `5060` | SIP UDP/TCP port |
| `OUTPUT_DIR` | `./data/pcaps` | Per-phase PCAP and run-log destination |
| `CLICKHOUSE_HOST` | `127.0.0.1` | ClickHouse HTTP endpoint host |
| `CLICKHOUSE_PORT` | `8123` | ClickHouse HTTP endpoint port |
| `CLICKHOUSE_USER` | `ngn` | ClickHouse user with INSERT on `ngn_sip.attack_labels` |
| `CLICKHOUSE_PASSWORD` | (required) | Sourced from `.env`; never hardcoded |
| `ATTACK_NETWORK` | `ngn-sip_sip_lab` | Docker network for sibling attack containers |

## Outputs

- One `attack_labels` row per attack script invocation, written via the ClickHouse HTTP interface.
- One combined run log per phase under `${OUTPUT_DIR}/run_phase_<n>_<utc>.log`.
- PCAPs (when tool wrappers are uncommented): `${OUTPUT_DIR}/0X_<phase>/<ts>_<attack>.pcap`.
