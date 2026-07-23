# Operations Deep Dive: Wazuh, Vector, ClickHouse, Shuffle

Operational notes for the four data-plane and SOC tools in this stack. Every
item is a concrete failure mode I hit and fixed while bringing the stack up from
clean, not a textbook summary: why the configs look the way they do, and where
the sharp edges are.

---

## Wazuh (SIEM: manager, indexer, dashboard)

**Architecture.** Three services: the **manager** (analysisd + logcollector +
the API), the **indexer** (an OpenSearch fork that stores alerts), and the
**dashboard** (an OpenSearch-Dashboards fork). Log flow: a `<localfile>` in
`ossec.conf` → logcollector → analysisd runs decoders then rules → alerts to
`alerts.json` and to the indexer.

**Advanced mechanics and gotchas learned here:**

1. **`ossec.conf` lives in the container's writable layer, and that is
   deliberate.** I do not bind-mount it, because the pinned 4.14.5 default
   config and the agent `client.keys` also live under `/var/ossec/etc` and a
   bind mount would clobber them. Consequence: a fresh or `--force-recreate`d
   manager starts from the stock config and loses every project `<localfile>`
   and `<integration>`. Fix: an **append-only, idempotent entrypoint script**
   (`siem/wazuh/bootstrap/register_localfiles.sh`) mounted at
   `/entrypoint-scripts/*.sh`. The stock image's `/etc/cont-init.d/2-manager`
   runs every script there *before* `wazuh-control start`, so the manager comes
   up fully configured with no manual step and no restart.

2. **Decoders and rules must sit on the non-recursive load path.** The default
   ruleset scans `etc/decoders` and `etc/rules` **non-recursively**. Files
   dropped in an `etc/rules/local/` subdir are silently never loaded. Mount at
   the top level (`/wazuh-config-mount/etc/rules`), which is why `sip_rules.xml`
   and `ml_rules.xml` sit there directly.

3. **The JSON decoder renders numbers to fixed 6-decimal strings.** A rule that
   matches `ml.proba` must account for this: `0.939` in the log decodes as the
   string `"0.939000"`. That is why rule 100151 gates with the regex
   `^(0\.9[0-9]*|1(\.0+)?)$` (matches `0.900000`..`0.999999` and `1.000000`) to
   mean "proba >= 0.90". Verify any field rule with `wazuh-logtest` against a
   crafted event before trusting it.

4. **The API enforces a password policy the compose default must satisfy.** The
   manager's `create_user.py` rejects a weak API password with
   `Error 5007 - Insecure user password`, and the container then exits. The
   default must contain upper, lower, digit, and symbol (hence
   `ChangeMeLocal1!`, not `change-me-local-only`).

5. **The indexer OOMs quietly if the container limit is too tight.** A 1 GiB JVM
   heap needs ~3 GiB container memory (heap + off-heap + Lucene mmap). At
   `mem_limit: 1536m` it was OOM-killed (exit 137) mid-index-build even with the
   VM otherwise idle. It requires `vm.max_map_count=262144` on the host/VM.

6. **Indexer OIDC config is not file-driven; it is pushed with
   `securityadmin.sh`.** The security plugin stores config in the
   `.opendistro_security` index, so mounting `config.yml` is not enough. Push
   only the `config` and `rolesmapping` objects, never `internal_users`, or you
   race the entrypoint's password-hash templating (`scripts/apply_wazuh_sso.sh`).

7. **`docker exec sh -s <<EOF` silently no-ops.** Without `-i`, `docker exec`
   does not attach stdin, so a heredoc piped to `sh -s` runs an empty script,
   exits 0, and registers nothing. Use `docker exec <ctr> sh -c '<script>'`.

---

## Vector (log/event shipper)

**Architecture.** `sources` (file tails) → `transforms` (VRL remap) → `sinks`
(ClickHouse HTTP). Config in `observability/vector/vector.yaml`.

**Advanced mechanics and gotchas learned here:**

1. **VRL is strictly typed about fallibility, in both directions.** A fallible
   expression assigned without handling errors is `error[E103]: unhandled
   fallible assignment`; an unnecessary `?? default` on an infallible expression
   is `error[E651]: unnecessary error coalescing`. `vector validate` catches
   both and the container refuses to start, so a config typo takes the pipeline
   down rather than degrading. Always `vector validate --no-environment` before
   recreating.

2. **ClickHouse's `DateTime64` JSONEachRow parser rejects RFC3339.** Vector's
   default timestamp serializes with `T`/`Z` (`2026-...T...Z`), which the parser
   rejects with a 400, and Vector then *silently drops* the row. Emit the time
   column as a ClickHouse-native string in the transform:
   `format_timestamp!(ts, format: "%Y-%m-%d %H:%M:%S%.3f")`.

3. **No buffer config means silent loss under backpressure.** By default the
   in-memory sink buffer fills and discards when ClickHouse is slow. Configure
   **disk buffers** (`type: disk, when_full: block`): `block` applies
   backpressure to the (checkpointed) file sources instead of dropping, so
   nothing is lost while ClickHouse recovers. Verified by stopping ClickHouse
   for 47s under load: events spooled to disk, zero discards, drained on
   recovery.

4. **A disk buffer needs a writable, persistent `data_dir` - awkward under a
   read-only rootfs.** The container runs `read_only: true`, `cap_drop: ALL`,
   uid 65534, and the image ships `/var/lib/vector` as root-owned. A tmpfs
   defeats the point (buffers evaporate on restart). Solution: a named volume
   plus a one-shot `vector-init` container that `chown`s it to 65534 before
   Vector starts.

5. **Make drops observable.** Add an `internal_metrics` source and a
   `prometheus_exporter` sink, then scrape it. `vector_component_discarded_events_total`
   and `vector_buffer_*` turn silent loss into a dashboard signal.

---

## ClickHouse (OLAP evidence store)

**Architecture.** Columnar OLAP DB. Two client interfaces: **HTTP on 8123**
(what Vector and the dashboard use) and the **native TCP protocol on 9000**
(what `clickhouse-client` and the ML native driver use). Schema is applied from
`infra/clickhouse/init/` by the entrypoint on first boot.

**Advanced mechanics and gotchas learned here:**

1. **Native 9000 is reachable container-to-container even when not
   host-published.** I publish only 8123 to the host; services on the shared
   network still reach `clickhouse:9000` internally. The ML scorer uses the
   native driver over 9000; Vector uses HTTP over 8123.

2. **Column types bite on insert and query.** `ban_audit.src_ip` and
   `ml_scores.src_ip` are `String`, not `IPv6`. Inserting with `toIPv6('...')`
   fails (`NO_COMMON_TYPE: no supertype for String, IPv6`) and, over the HTTP
   path, *silently* (error goes to stderr). Likewise `wazuh_alerts.rule_id` is
   `UInt32`, so `toUInt32OrZero(rule_id)` errors (`ILLEGAL_TYPE_OF_ARGUMENT` -
   the `*OrZero` functions require a String). Check `system.columns` before
   writing queries.

3. **TTL is the capacity control.** High-volume tables (`sip_events`,
   `suricata_alerts`, `wazuh_alerts`, `raw_logs`, `ml_scores`) carry
   `TTL <time> + INTERVAL N DAY`, so a sustained flood cannot grow the store
   without bound. This directly addresses the disk-exhaustion failure the live
   exposure hit.

4. **Materialized views do the feature engineering.** `mv_sip_features_5min`
   aggregates `sip_events` per source-IP per 5-minute window into
   `sip_features_5min`, which is what the Stage-1 model reads. If `sip_events`
   is empty the whole ML path is starved, so the Vector → `sip_events` transform
   is load-bearing.

5. **Ship all table DDL in the init dir.** Tables created out-of-band at runtime
   (`ml_scores`, `ban_audit`, `soar_cases`) must also have `CREATE TABLE IF NOT
   EXISTS` files in `infra/clickhouse/init/`, or a fresh boot lacks them and the
   dashboard panels error until a producer happens to create them.

---

## Shuffle (SOAR)

**Architecture.** Four services: `frontend`, `backend` (REST API on 5001,
webhooks), `orborus` (the worker/container orchestrator, authenticates to the
backend with an API key), and its own `opensearch`. Workflows are triggered by
webhooks and run app actions.

**Advanced mechanics and gotchas learned here (from driving the 2.2.0 API):**

1. **Bearer API keys must be >= 36 characters.** Shuffle 2.2.0 stores a shorter
   key but rejects it for Bearer auth, so provisioning silently falls back to
   session login. Set a >=36-char `SHUFFLE_DEFAULT_APIKEY` before first boot.

2. **First-boot auth registration lags container health by up to ~2 minutes.**
   The admin user and default API key are not ready when the container reports
   healthy, so a one-shot auth probe 403s. Provisioning must **retry** the auth
   check until ready (`scripts/provision_shuffle.sh` polls before proceeding).

3. **Webhook URLs are generated, not chosen.** Shuffle mints the trigger UUID;
   you cannot configure a custom path. The correct flow: create the workflow,
   start the webhook (`POST /api/v1/hooks/new` with a client-supplied UUID),
   read the id back from the saved workflow, then write
   `http://shuffle-backend:5001/api/v1/hooks/webhook_<id>` into the Wazuh
   integration. This is why the hook URL is provisioned by script, not hardcoded.

4. **App IDs are instance-local.** "Shuffle Tools" and "HTTP" have different app
   IDs on every install, so a portable workflow must resolve them **by name**
   against the live API, not embed an ID.

5. **Workflow schema:** actions carry `app_name`/`app_id`/`app_version`/`name`/
   `parameters[{name,value}]`; branches use `{source_id, destination_id,
   conditions:[{source,condition,destination}]}` with literal condition strings
   like `"larger than"`; an `execute_python` action returns
   `{"success":true,"message":<parsed JSON of stdout>}`, enabling
   `$node.message.field` references downstream.

6. **OIDC is API-settable but uses implicit flow.** `POST /api/v1/orgs/<id>`
   with `{"editing":"sso_config", ...}` persists the OIDC config - the `editing`
   flag is mandatory or the backend silently drops the payload. With a client
   secret set, Shuffle uses OAuth **implicit flow** (`response_type=id_token`),
   which Keycloak rejects until the client has `implicitFlowEnabled=true`.

---

## The one lesson across all four

Every tool here has a failure mode that is **silent**: Vector drops on
backpressure, ClickHouse rejects a bad insert to stderr, Wazuh's heredoc
registration no-ops, Shuffle falls back to session auth. None of them crash
loudly. The defensible pattern, applied throughout this stack, is to make the
silent path observable (metrics, audit rows, `make e2e` assertions) rather than
trust that "healthy" means "working."
