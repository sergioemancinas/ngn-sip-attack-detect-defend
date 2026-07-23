# SBC Hardening Runbook

Operational procedure for enabling, testing, and rolling back the Kamailio SBC hardening
controls. Audience: the operator preparing the edge for internet exposure on the campus VM.

The preventive controls (TLS, digest auth, edge request filtering) ship **gated off** so the
default lab runtime stays un-hardened and the C3 detection experiment (signature vs
correlation vs ML on identical traffic) is preserved. This runbook is the procedure to turn
them on for an exposed deployment. The always-on controls (PIKE, autoban) are documented here
too because exposure readiness depends on confirming they still behave under load.

Ground rules:

- Enable one control at a time, in a maintenance window.
- Validate config before every restart: `docker compose exec kamailio kamailio -c -f /etc/kamailio/kamailio.cfg`.
- Run the baseline SIP health check (below) before and after every change. A control is
  "done" only when SIP still completes and the intended block fires.
- Keep `DEV_BIND_IP=127.0.0.1`; only `SIP_BIND_IP` faces the internet.

## Default posture

| Control | Type | Gate | Default | Implemented in |
|---|---|---|---|---|
| SIP over TLS (5061) | Preventive (transport) | `TLS_ENABLE` | OFF | `infra/kamailio/modules/tls.cfg` |
| Digest auth (REGISTER) | Preventive (auth) | `AUTH_ENABLE` | OFF | `infra/kamailio/modules/auth.cfg` + `route(SBC_AUTH)` in `kamailio.cfg` |
| Edge request filtering | Preventive (filter) | `SECFILTER_ENFORCE` | OFF | `infra/kamailio/modules/secfilter.cfg` + enforcement block in `kamailio.cfg` |
| Topology hiding | Preventive (recon) | `TOPOH_ENABLE` | OFF | `infra/kamailio/modules/topoh.cfg` |
| PIKE rate limiting | Detection (rate) | none (always on) | ON, detection-only | `infra/kamailio/modules/pike.cfg` + `pike_check_req()` in `kamailio.cfg` |
| Autoban active response | Response (containment) | none (sidecar) | ON | `siem/wazuh/active-response/autoban_loop.sh` + `ban.cfg` / `htable.cfg` |

The repo gate names are `TLS_ENABLE`, `AUTH_ENABLE`, and `SECFILTER_ENFORCE` (matching the
existing `TOPOH_ENABLE` and `HEP_CAPTURE_ENABLE` convention), not `ENABLE_*`.

## How the gates work

Each gated module is wrapped in `#!ifdef <GATE>` so the body compiles only when the matching
`#!define` is present. To turn a control on, add the define near the top of
`infra/kamailio/kamailio.cfg` (after the `#!KAMAILIO` line and global parameters, before the
include block), for example:

```
#!define TLS_ENABLE
```

Then validate and restart:

```bash
docker compose exec kamailio kamailio -c -f /etc/kamailio/kamailio.cfg   # must print no errors
docker compose restart kamailio
```

With no define present, `kamailio -c` is clean and the runtime is identical to today.

## Baseline SIP health check

Run this before and after every change. It is the regression gate.

```bash
make smoke
```

This drives an authenticated SIPp REGISTER for two endpoints and a UAC to UAS INVITE through
`kamailio:5060` (`scripts/smoke_sip_call.sh`). Pass condition: the run prints
the smoke call completes and SIPp reports 0 failed calls. If smoke fails after a change,
roll that control back before continuing.

## Control 1: SIP over TLS (5061)

**What it does.** Adds a TLS/SIPS listener on 5061/tcp so signaling between an external client
and the SBC is encrypted and the server is authenticated by certificate. This addresses
passive interception and transport downgrade against the client-to-edge leg (RFC 3261
Sec 26.2.1 Transport and Network Layer Security, Sec 26.2.2 SIPS URI Scheme). The
edge-to-Asterisk leg stays on the internal `sip_lab` network. UDP/TCP 5060 are not removed;
TLS is additive.

**Prerequisites.**

1. Provision a key pair (lab self-signed shown; use step-ca for anything real):

```bash
mkdir -p infra/tls
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout infra/tls/kamailio.key -out infra/tls/kamailio.crt \
  -subj "/CN=ngn-sip-lab"
```

`infra/tls/*` is gitignored and `*.key` is gitignored; never commit private keys.

2. Mount the certs and publish 5061 in `docker-compose.yml` (kamailio service):

```yaml
    volumes:
      - ./infra/tls:/etc/kamailio/tls:ro
    ports:
      - "${SIP_BIND_IP:-127.0.0.1}:5061:5061/tcp"   # uncomment the existing line
```

`tls.cfg` reads the cert at `/etc/kamailio/tls/kamailio.crt` and key at
`/etc/kamailio/tls/kamailio.key`. `tls.cfg` is included before the auth/database modules so
`tls.so` initialises OpenSSL first.

**Enable.** Add `#!define TLS_ENABLE` to `kamailio.cfg`, validate with `kamailio -c`, restart.

**Test (SIP still works).**

```bash
# 1. TLS listener is up and the handshake completes with the expected cert:
openssl s_client -connect <vm-host>:5061 -servername ngn-sip-lab </dev/null
# 2. Plain SIP path is unaffected (TLS is additive on a separate port):
make smoke
```

Pass condition: `s_client` prints the certificate and `Verify return code` without a handshake
error, and `make smoke` still completes. Optionally drive a TLS REGISTER with a TLS-capable
client (SIPp `-t l1 -p 5061`, or `sipsak --tls`) and confirm a 200.

**Rollback.** Remove `#!define TLS_ENABLE`, `kamailio -c`, restart. Re-comment the 5061 publish
line. No state to clean up; 5060 was never touched.

## Control 2: Digest authentication on REGISTER

**What it does.** Challenges REGISTER at the edge with HTTP Digest (RFC 3261 Sec 22.4,
Sec 26.2.3) so unauthenticated registrations are rejected with 401 before `t_relay`, instead
of being proxied to Asterisk. This is the preventive control against registration hijacking
and credential abuse (RFC 3261 Sec 26.1.1) that an exposed SBC should provide. INVITE auth is
left optional in `route(SBC_AUTH)`.

**Prerequisites.** A credentials source consistent with Asterisk's pjsip endpoints. `auth.cfg`
binds `auth_db` to `postgres://ngn@postgres:5432/ngn_sip` with `calculate_ha1=1` and a plaintext
`password` column, and loads `db_postgres.so` (required driver) before `auth_db.so`. The
`subscriber` table must contain the SIPp smoke users (`infra/sipp/data/ua1000.csv`,
`ua1001.csv`) with passwords matching `pjsip.conf`, or smoke will 401. For a credential-free
lab check you can instead load the static-AoR `auth` path noted in `auth.cfg`.

**Enable.** Add `#!define AUTH_ENABLE` to `kamailio.cfg`, validate, restart. The same flag gates
both the module load and the `route(SBC_AUTH)` call in `request_route` (after `sanity_check`,
before relay).

**Test (SIP still works).**

```bash
# 1. Credentialled clients still register and call (creds provisioned in subscriber):
make smoke
# 2. Unauthenticated REGISTER is now challenged, not proxied:
#    send a REGISTER with no Authorization and confirm a 401 from Kamailio.
# 3. Brute force is rejected at the edge and raises the burst rule:
TARGET_HOST=kamailio attacks/02_credentials/sippts_svcrack.sh   # expect 401s, Wazuh rule 100102
```

Pass condition: `make smoke` still completes (credentialled), an uncredentialled REGISTER gets
401, and repeated failures raise Wazuh rule 100102 / 100106.

**Rollback.** Remove `#!define AUTH_ENABLE`, validate, restart. Authentication reverts to being
delegated to Asterisk. If a misconfigured credentials source is rejecting legitimate REGISTER,
rolling back the define restores service immediately.

## Control 3: Edge request filtering (scanner UA, malformed SIP)

**What it does.** When `SECFILTER_ENFORCE` is set, the SBC drops requests whose User-Agent
matches a known SIP attack-tool family with `403 Forbidden` at the edge, before relay
(reconnaissance / scanning, MITRE T1595.001). Malformed SIP that fails `sanity_check` is
already dropped in all modes (the request_route exits before this gate). In both states the
`NGN-SEC` detection event is still emitted first, so detection and telemetry are unchanged;
the flag only adds the inline block. No extra module is loaded (enforcement reuses
textops/pv/htable), so toggling the flag cannot fail module loading at startup.

**Enable.** Add `#!define SECFILTER_ENFORCE` to `kamailio.cfg`, validate, restart.

**Test (SIP still works).**

```bash
# 1. Legitimate traffic (SIPp default UA, not a blacklisted family) is unaffected:
make smoke
# 2. A scanner-UA probe is now blocked at the edge with 403:
TARGET_HOST=kamailio attacks/01_recon/sipvicious_svmap.sh    # UA matches family -> 403
# 3. The detection event still fires regardless of the flag:
#    confirm Wazuh rule 100107 (scanner UA) still alerts.
```

Pass condition: `make smoke` still completes, the scanner-UA probe receives 403 and is not
relayed to Asterisk, and rule 100107 still alerts. Ensure no legitimate test tooling uses a
blacklisted UA (the family list includes `sippts`, `sipsak`, `sipvicious`, `friendly-scanner`,
and others; see the regex in `kamailio.cfg`).

**Rollback.** Remove `#!define SECFILTER_ENFORCE`, validate, restart. The edge reverts to
detection-only: scanner UAs are logged via `NGN-SEC` and proxied, matching the measurement
default.

## Control 4: PIKE rate limiting (always on, detection-only)

**What it does.** `pike` tracks per-source SIP request rate. A source exceeding
`reqs_density_per_unit` (30) within `sampling_time_unit` (2s) is flagged for `remove_latency`
(120s). In `request_route`, a flagged source emits a single `pike: PIKE BLOCKING ip <src>` plus
an `NGN-SEC ... reason="pike_flood"` event per source per dedup window. This is the rate-based
flood signal that catches volumetric abuse even when the UA is spoofed (MITRE T1499; the SIP
overload problem characterised in RFC 5390). It is **detection-only**: the request still flows
so all three C3 arms see identical traffic. Inline dropping is the autoban / ban_table job.

**Tunables.** `infra/kamailio/modules/pike.cfg`: `sampling_time_unit`, `reqs_density_per_unit`,
`remove_latency`. Raise the density if a legitimate burst (mass softphone reconnect) trips it.

**Test.**

```bash
attacks/04_dos/sipp_register_flood.sh     # 50 REGISTER/s by default; exceeds the PIKE rate
```

Pass condition: Kamailio logs `pike: PIKE BLOCKING ip ...` and Wazuh rule 100103 fires
(decoder `kamailio-pike`). Because PIKE is detection-only, legitimate calls are not dropped by
it; `make smoke` continues to pass during and after the flood.

**Rollback / tuning.** PIKE does not block inline, so there is nothing to "disable" for safety.
To quiet it, raise the thresholds in `pike.cfg` and restart, or comment the `pike_check_req()`
block in `request_route`. Do not remove the htable definitions used by autoban.

## Control 5: Autoban active response (always on)

**What it does.** The `kamailio-autoban` sidecar (`autoban_loop.sh`) polls ClickHouse for
sources of high-severity SIP detections (`rule_level >= 10`, SIDs 100100 to 100199) and bans
each at the edge with `kamcmd htable.sets ban_table <ip> 1` (1h autoexpire). `route(DROP_IF_BANNED)`
then drops all further traffic from that source (MITRE T1499 containment; rule 100131 on the
drop). A never-ban allowlist (protected stack container IPs plus `NEVER_BAN_IPS`) is mirrored
into `ban_allowlist` so a spoofed internal source cannot be banned (RFC 3261 Sec 26
anti-spoofing). Every ban, skip, and reject is written to `ngn_sip.ban_audit`.

**Test.**

```bash
# Trigger a high-severity detection, then confirm the source lands in the ban table:
TARGET_HOST=kamailio attacks/01_recon/sipvicious_svmap.sh         # raises rule 100107 (level 10)
docker compose exec kamailio kamcmd htable.dump ban_table         # attacker IP appears within POLL_SECONDS
docker compose exec kamailio kamcmd htable.dump ban_allowlist     # protected stack IPs present
```

Pass condition: the attacker source appears in `ban_table`, a `ban` row is written to
`ngn_sip.ban_audit`, and subsequent traffic from it is dropped (rule 100131). Protected stack
IPs appear in `ban_allowlist` and are never banned.

**Rollback / pause.**

```bash
docker stop kamailio-autoban                                      # pause containment (clean measurement)
docker compose exec kamailio kamcmd htable.delete ban_table <ip>  # unban a single source
```

`kamcmd_block.sh` is the alternative native-Wazuh-AR actuator and is reference-only unless
explicitly wired into an `<active-response>` block; keep exactly one path live.

## Verification quick reference

| Check | Command |
|---|---|
| SIP call path | `make smoke` |
| Config syntax | `docker compose exec kamailio kamailio -c -f /etc/kamailio/kamailio.cfg` |
| TLS listener | `openssl s_client -connect <host>:5061` |
| Ban / allowlist state | `kamcmd htable.dump ban_table` / `kamcmd htable.dump ban_allowlist` |
| Rule decode | `wazuh-logtest` against captured Kamailio `NGN-SEC` log fixtures |

## Enable order for full exposure

Follow this activation order: bind split, RTP range reconcile, then optional
`SECFILTER_ENFORCE` and TLS. Provision TLS and turn on
`TLS_ENABLE` before requesting 5061 from the campus firewall owner.
