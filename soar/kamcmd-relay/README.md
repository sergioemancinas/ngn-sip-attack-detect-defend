# kamcmd-relay

HTTP ban-enforcement endpoint for the Stage-3 SOAR workflow. It sits behind
`${KAMCMD_BLOCK_RELAY_URL}` in `soar/shuffle/workflows/sip_response_orchestration.json`:
when the graded decision hits the `ban` branch, Shuffle POSTs here and the relay
pushes the source into Kamailio's `ban_table`, where `DROP_IF_BANNED`
(`infra/kamailio/modules/ban.cfg`) drops its traffic at the edge.

Shuffle workers can't run `docker exec`, so the relay does it for them, using the
exact mechanism the deployed `kamailio-autoban` sidecar uses:

```
docker exec <kamailio> /usr/sbin/kamcmd htable.sets ban_table <ip> 1
```

issued over a read-only `docker.sock` mount (no host root). `htable.sets` is
idempotent and refreshes the `autoexpire=3600` TTL, so SOAR bans and autoban bans
converge on the same table with the same decay.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/kamcmd-block` | `Authorization: Bearer ${RELAY_TOKEN}` | Ban (`command=add`, default) or unban (`command=delete`) |
| `GET` | `/healthz` | none | Liveness for the compose healthcheck |

## Request contract

Two body shapes are accepted: the workflow/`kamcmd_block.sh` contract, and a flat
form for manual ops.

```json
{"command": "add", "parameters": {"alert": {"data": {"srcip": "203.0.113.7"}}}}
{"src_ip": "203.0.113.7", "rule_id": 100102, "reason": "SOAR graded ban", "ttl_seconds": 3600}
```

`command=delete` unbans (`htable.delete`). `ttl_seconds` (1..86400) is honored
best-effort via `htable.setex`; if the Kamailio build rejects it, the entry keeps
the table-level `autoexpire` and the response reports the effective TTL.

Responses: `200` applied, `400` invalid input, `401` bad token, `403` protected
source, `502` kamcmd failure.

## Safeguards

SIP-over-UDP source addresses are spoofable (RFC 3261 §26), so an attacker could
forge an internal IP to make the response pipeline ban it (blocklist poisoning).
The relay therefore refuses to ban:

1. Anything that isn't a bare IP literal (regex gate, then strict `ipaddress` parse).
2. The never-ban allowlist: `NEVER_BAN_IPS`, the live IPs of `PROTECTED_CONTAINERS` (resolved via the Docker API, refreshed every 30 s), and its own container IPs.
3. Loopback, link-local, multicast, unspecified, and reserved ranges.
4. RFC1918/ULA private space, refused **by default**. Set `RELAY_ALLOW_PRIVATE=1` for the lab, where attacker containers live on the `172.x` bridge.

Auth is a shared bearer secret (`RELAY_TOKEN`, constant-time compare); the relay
refuses to start without one.

## Audit trail

Every outcome writes a row to `ngn_sip.ban_audit` over ClickHouse HTTP (the same
table autoban uses), as `FORMAT JSONEachRow` data (never string-interpolated SQL).
Actions: `ban` / `ban_failed`, `unban` / `unban_failed`, `skip_protected`,
`reject_invalid`, `reject_unauthorized`. Audit failures are logged but never block
enforcement.

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8099` | Listen port |
| `RELAY_TOKEN` | (required) | Bearer secret, from `KAMCMD_BLOCK_RELAY_TOKEN` in `.env` |
| `KAMAILIO_CTR` | `ngn-sip-kamailio-1` | Target container |
| `HTABLE_NAME` | `ban_table` | Ban htable |
| `DOCKER_SOCK` | `/var/run/docker.sock` | Docker Engine API socket (read-only mount) |
| `CLICKHOUSE_URL` | `http://clickhouse:8123` | Audit endpoint |
| `NEVER_BAN_IPS` | `127.0.0.1 ::1` | Static never-ban list |
| `PROTECTED_CONTAINERS` | autoban's list | Containers whose IPs are never bannable |
| `RELAY_ALLOW_PRIVATE` | `0` | `1` = allow banning RFC1918 sources (lab mode) |
| `DEFAULT_TTL_SECONDS` / `MAX_TTL_SECONDS` | `3600` / `86400` | TTL default and upper bound |

## Smoke test

```bash
curl -s http://kamcmd-relay:8099/healthz

curl -s -X POST http://kamcmd-relay:8099/kamcmd-block \
  -H "Authorization: Bearer $KAMCMD_BLOCK_RELAY_TOKEN" \
  -d '{"command":"add","parameters":{"alert":{"data":{"srcip":"198.51.100.9"}}}}'

docker exec ngn-sip-kamailio-1 kamcmd htable.dump ban_table   # verify
```

Use `command:"delete"` to unban.

## The three response paths

`kamailio-autoban` (polls ClickHouse every 5 s) is the deterministic backstop;
**kamcmd-relay** (this service) is the orchestrated SOAR arm; `kamcmd_block.sh`
is the reference Wazuh-native path (not wired). All converge on `ban_table` +
the allowlist + `DROP_IF_BANNED`. Do not disable autoban when running SOAR. See
[`../../docs/09_soar_runbook.md`](../../docs/09_soar_runbook.md).
