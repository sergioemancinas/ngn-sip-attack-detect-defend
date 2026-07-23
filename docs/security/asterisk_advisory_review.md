# Asterisk Advisory Review


## Verdict

The Asterisk image is not exposed to the host and is built from Asterisk `20.19.0`, which is newer than the patched versions for the recent Asterisk advisories reviewed below. The container also now runs as the `asterisk` user by default, and the embedded Asterisk HTTP server reports disabled at runtime.

## Reviewed Advisories

| Advisory | CVE | Upstream affected range relevant to Asterisk 20 | Patched version | Status |
|---|---|---:|---:|---|
| GHSA-64qc-9x89-rx5j, malformed SIP `Authorization` header crash | CVE-2025-57767 | `<= 20.15.1` | `20.15.2` | Mitigated by `20.19.0` |
| GHSA-85x7-54wr-vh42, XML parser XXE/XInclude risk | CVE-2026-23739 | `<= 20.18.1` | `20.18.2` | Mitigated by `20.19.0` |
| GHSA-v6hp-wh3r-cwxh, `/httpstatus` reflected XSS | CVE-2026-23738 | `<= 20.18.1` | `20.18.2` | Mitigated by `20.19.0`; HTTP server disabled locally |
| GHSA-xpc6-x892-v83c, `ast_coredumper` temporary-file privilege escalation | CVE-2026-23740 | `<= 20.18.1` | `20.18.2` | Mitigated by `20.19.0`; container runs non-root |
| GHSA-rvch-3jmx-3jf3, `ast_coredumper` sourced config privilege escalation | CVE-2026-23741 | `<= 20.18.1` | `20.18.2` | Mitigated by `20.19.0`; `/etc/asterisk` bind is read-only |

## Local Validation

Commands run:

```sh
docker compose exec -T asterisk sh -c 'id; command -v asterisk; ps -o user,group,pid,comm,args -p 1'
docker compose exec -T asterisk asterisk -rx 'core show version'
docker compose exec -T asterisk asterisk -rx 'http show status'
docker scout cves --only-severity critical,high --only-fixed local://ngn-sip/asterisk:20.19.0
make smoke
```

Observed:

- Asterisk runs as `uid=999(asterisk)` / `gid=999(asterisk)`.
- PID 1 command is `/usr/sbin/asterisk -f -U asterisk -G asterisk -vvv`.
- Runtime version is `Asterisk 20.19.0`.
- HTTP status reports `Server Disabled`.
- Docker Scout reports no fixable critical/high vulnerabilities for `ngn-sip/asterisk:20.19.0`.
- Aikido MCP, Docker Scout, and Trivy report no issues for the Asterisk Dockerfile, config, and Compose service after changing the Dockerfile to literal digest-pinned `FROM` lines and `USER asterisk`.
- `make smoke` still completes the REGISTER and INVITE flow after the hardening.

## Local Exposure Boundary

Asterisk has no host-published ports. It listens only on the Docker bridge network for Kamailio. Public SIP exposure is deferred to the university VM phase and must be handled with the VM hardening checklist in `docs/05_kubernetes_migration.md`.
