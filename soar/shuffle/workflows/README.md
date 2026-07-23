# Shuffle Workflows

Stage 3 SOAR workflows for the NGN SIP detect-defend lab.

## Workflows

| File | Purpose |
|---|---|
| `sip_response_orchestration.json` | **Stage 3** graded orchestration (ClickHouse enrichment, graded ban via kamcmd-relay, `soar_cases` evidence rows) |

`sip_response_orchestration.json` is a **real, importable Shuffle 2.2.0 workflow**
exported from a live instance and slimmed for review (base64 images and
instance-only bookkeeping stripped). It uses only stock Shuffle apps:

- **Shuffle Tools 1.2.0** (`execute_python`) for input validation and the graded
  decision
- **http 1.4.0** (`POST`) for the ClickHouse queries, the kamcmd-relay ban call,
  and the notify stub

## Provisioning (recommended: automated)

```bash
make shuffle-provision            # or: ./scripts/provision_shuffle.sh
```

`scripts/provision_shuffle.sh` imports/updates this workflow over the Shuffle
REST API, starts the webhook trigger, captures the **generated** webhook URL
(`/api/v1/hooks/webhook_<trigger-id>`, where the id is minted per install and
never hardcoded), and rewrites `siem/wazuh/integrations/wazuh_shuffle_integration.xml`
to point Wazuh at it. Re-runs are idempotent. `DRY_RUN=1` previews.

Manual import through the UI (**Workflows -> Import**) also works; then activate
the webhook trigger and copy its URL into the Wazuh integration XML yourself.

## Node graph

```
webhook (wazuh_sip_alert)
  -> parse_alert        Shuffle Tools execute_python: extract srcip/rule_id/rule_level
  |                     from the Wazuh shuffle.py payload; bare-IP-literal gate
  |                     (also the SQL-injection guard for the queries below)
  -> dedup_check        http POST -> ClickHouse: recent soar_cases for src_ip
  |                     within $soar_dedup_window_seconds
  -> enrich_ml          http POST -> ClickHouse: latest ml_scores
  |                     (predicted_class, proba) for src_ip, 1 h window
  -> enrich_llm         http POST -> ClickHouse: latest llm_verdicts
  |                     (verdict, confidence) for src_ip, 1 h window
  -> enrich_suricata    http POST -> ClickHouse: suricata_alerts count +
  |                     top signature for src_ip, 15 min window
  -> decide             Shuffle Tools execute_python: graded-response policy
       -> [should_ban == true]  ban_via_relay -> record_case_ban
       -> [should_ban == false] record_case_noban
       -> [notify == true]      notify_ops
```

Aggregate ClickHouse queries (`argMax`/`count`, `FORMAT JSONEachRow`) always
return exactly one row, so downstream references stay resolvable when a source
has no data (empty enrichment degrades to the `log_only` branch, never crashes).

## Graded-response policy (`decide` node)

Implements the table in `docs/09_soar_runbook.md`:

| `graded_action` | Condition |
|---|---|
| `dedup_suppressed` | non-suppressed case for src_ip within `$soar_dedup_window_seconds` |
| `ban` | Wazuh level >= 10 AND corroborated: Stage 2 `malicious` (conf >= 0.6) or `suspicious` (conf >= 0.8), OR ML proba >= `$ml_attack_score_high` with an attack label, OR proba >= `$attack_score_ban_threshold`, OR level >= 12 |
| `rate_limit_notify` | Stage 2 `suspicious`/`needs_review`, or mid-range proba (`low` <= proba < `ban`) |
| `log_only` | Below `$attack_score_low_threshold` with no Stage 2 corroboration (FP candidate) |

Every execution writes one `ngn_sip.soar_cases` row (ban path and no-ban path
alike); the ban itself is additionally audited by kamcmd-relay into
`ngn_sip.ban_audit`. The never-ban allowlist (protected stack containers,
loopback, etc.) is enforced by kamcmd-relay itself (`soar/kamcmd-relay`), so a
spoofed protected source can never reach `ban_table` regardless of what the
workflow decides. `kamailio-autoban` remains the deterministic backstop:
Stage 1/2 verdicts inform the SOAR tier, they never disable the backstop.

## Workflow variables

Set as **workflow variables** inside the workflow (referenced as `$name`).
`scripts/provision_shuffle.sh` overwrites them from `.env` on every run; the
shipped file only contains placeholders.

| Variable | Purpose | Default |
|---|---|---|
| `clickhouse_http_url` | ClickHouse HTTP API on `sip_lab` | `http://clickhouse:8123` |
| `clickhouse_user` / `clickhouse_password` | ClickHouse credentials | from `.env` |
| `kamcmd_relay_url` | Ban enforcement endpoint | `http://kamcmd-relay:8099/kamcmd-block` |
| `kamcmd_relay_token` | Bearer token for kamcmd-relay (`KAMCMD_BLOCK_RELAY_TOKEN`) | from `.env` |
| `soar_dedup_window_seconds` | Dedup window per src_ip | `300` |
| `attack_score_ban_threshold` | ML proba at/above -> ban | `0.85` |
| `attack_score_low_threshold` | Below this -> no containment | `0.55` |
| `ml_attack_score_high` | High-confidence ML corroboration | `0.90` |
| `notify_webhook_url` | Ops webhook (`disabled` = no-op) | `disabled` |

## Prerequisites

- `make soar-up` (Shuffle + kamcmd-relay on `sip_lab`)
- `ngn_sip.soar_cases` table (`infra/clickhouse/init/10_soar_cases.sql`; created
  automatically on a fresh ClickHouse volume, and `scripts/provision_shuffle.sh`
  also ensures it on existing volumes)
- Wazuh integration installed: `siem/wazuh/integrations/install_integrations.sh`

## Smoke test (manual)

Send a synthetic POST to the webhook with a Wazuh `shuffle.py`-shaped body
(`all_fields.rule.level` 10+, `all_fields.data.srcip` a non-protected external
test IP, plus recent `ml_scores`/`llm_verdicts` fixture rows if you want the
corroborated ban branch). Confirm:

1. The execution finishes and each node reports SUCCESS/SKIPPED as expected
   (`GET /api/v1/workflows/<id>/executions`).
2. A row appears in `ngn_sip.soar_cases` with the graded action and the
   enrichment snapshot.
3. For the `ban` branch, `ngn_sip.ban_audit` gains a `SOAR graded ban` row and
   `kamcmd htable.dump ban_table` on Kamailio shows the source.
