# Docker Image Security Review


## Scope

Images reviewed:

- `pgvector/pgvector:0.8.0-pg16`
- `ngn-sip/pgvector:0.8.0-pg16`
- `ngn-sip/asterisk:20.19.0`
- `ngn-sip/kamailio:5.8.8`
- `ngn-sip/rtpengine:10.5.3.5`
- `ngn-sip/sipp:3.7.3`

## Docker Scout Status

Docker Scout CLI is installed locally and should be used as the image security gate:

```sh
docker scout cves --only-severity critical,high local://ngn-sip/pgvector:0.8.0-pg16
```

Run:

```sh
make scan-containers
make scan-containers-fixable
```

Both targets use Docker Scout with `--exit-code --only-severity critical,high`.

## High Priority Findings

### 1. Replace Prebuilt `pgvector/pgvector:0.8.0-pg16`

The registry image was created on 2025-08-15 and had many runtime package updates available in the local Docker CLI check. Security-sensitive upgrades included:

- `libssl3` and `openssl`
- `libc6` and `libc-bin`
- `libxml2` and `libxslt1.1`
- PAM packages
- Kerberos packages
- `libpq5`
- `postgresql-16` from `16.10` to `16.13`

Action taken:

- Replaced the registry image with `ngn-sip/pgvector:0.8.0-pg16`.
- Built pgvector from the official `pgvector/pgvector` GitHub tag `v0.8.0`.
- Pinned and verified commit `2627c5ff775ae6d7aef0c430121ccf857842d2f2` during Docker build.
- Based the image on Docker Official `postgres:16-alpine` / `16.13-alpine3.23` manifest digest `sha256:4e6e670bb069649261c9c18031f0aded7bb249a5b6664ddec29c013a89310d50`.
- Added `apk upgrade --no-cache` to the build and purged build dependencies after pgvector installation.
- Replaced the official entrypoint's `gosu` privilege drop with `su-exec` and removed `/usr/local/bin/gosu` to eliminate Scout's Go stdlib findings from that binary.
- Install `su-exec` via `apk add --no-cache su-exec` so the binary lives at `/sbin/su-exec`. The original `postgres:16-alpine` ships `/usr/local/bin/su-exec` as a symlink pointing to `gosu`; removing `gosu` left that symlink dangling and the entrypoint failed with `exec: su-exec: not found` (exit 127). The dangling symlink is now also removed in the build.

Validation:

- PostgreSQL binary reports `PostgreSQL 16.13 on aarch64-unknown-linux-musl`.
- pgvector control file reports `default_version = '0.8.0'`; `pg_extension.extversion` is `0.8.0`.
- `pg_database.datcollate` is `en_US.utf8`.
- `gosu` is absent; the real `su-exec` is at `/sbin/su-exec` and is invoked by the patched entrypoint.

### 2. Keep Existing Custom Service Images Current

The Asterisk, Kamailio, rtpengine, and SIPp images had no pending Debian package upgrades in the local Docker CLI check.

Action taken:

- `make build` now runs `docker compose build --pull`.
- `make up` now builds with `--pull` before starting the stack.
- Asterisk now uses literal digest-pinned Debian `FROM` lines and an explicit `USER asterisk` in the final image. Aikido MCP no longer reports Dockerfile issues for the Asterisk surface.
- rtpengine now creates and runs as a dedicated non-root `rtpengine` system user. Aikido MCP no longer reports the Dockerfile default-root finding for the rtpengine surface.

### 3. Move Kamailio To Upstream-Fixed 5.8.8 Package

`CVE-2026-39863` is fixed upstream in Kamailio 5.8.8. The live Kamailio 5.8 APT repository has a Bookworm build for `5.8.8+bpo12`, so the image now installs the pinned package version from `https://deb.kamailio.org/kamailio58 bookworm main`.

Action taken:

- Updated `infra/kamailio/Dockerfile` from `5.8.6+bpo12` to `5.8.8+bpo12`.
- Switched the package source from the archived `kamailio-5.8.6` repo to the live `kamailio58` repo.
- Verified the repository key fingerprint during build: `E79ACECB87D8DCD23A20AD2FFB40D3E6508EA4C8`.

Validation:

- `docker compose build --pull kamailio` completed successfully and installed `kamailio_5.8.8+bpo12`.
- `docker scout cves --only-severity critical,high --only-fixed local://ngn-sip/kamailio:5.8.8` remains clean.
- Full Docker Scout critical/high still reports `CVE-2026-39863` against `kamailio 5.8.8+bpo12` with `Fixed version: not fixed`. Treat this as a scanner metadata/namespace residual for now because upstream and NVD identify 5.8.8 as fixed.

## Docker Scout Results

All five service images were rescanned with Docker Scout after the rebuild and recreate cycle. None have any fixable critical or high CVEs (`docker scout cves --only-severity critical,high --only-fixed` returns clean for every image, and `make scan-containers-fixable` passes the gate).

Full-severity counts:

| Image                                   | C | H | M | L  | Notes                                                                                  |
|-----------------------------------------|---|---|---|----|----------------------------------------------------------------------------------------|
| `ngn-sip/pgvector:0.8.0-pg16`       | 0 | 0 | 2 | 0  | Mediums: `CVE-2026-22185` (openldap), `CVE-2025-60876` (busybox), both `not fixed` upstream in alpine 3.23. |
| `ngn-sip/asterisk:20.19.0`          | 0 | 0 | 3 | 35 | All `not fixed` upstream in Debian bookworm.                                           |
| `ngn-sip/kamailio:5.8.8`            | 1 | 2 | 6 | 56 | Rebuilt with Kamailio `5.8.8+bpo12`. C: `CVE-2026-6100` (python3.11). H: `CVE-2026-39863` (Scout still reports despite upstream 5.8.8 fix), `CVE-2026-27135` (nghttp2). |
| `ngn-sip/rtpengine:10.5.3.5`        | 3 | 7 | 14| 97 | Critical/high cluster on `mbedtls` and `nghttp2`. Not fixed in Debian Bookworm packages. Image now runs as non-root; rebuild/rescan pending after Docker Desktop is available. |
| `ngn-sip/sipp:3.7.3`                | 0 | 0 | 2 | 41 | All `not fixed` upstream.                                                              |

The recent Asterisk advisories are reviewed separately in `docs/security/asterisk_advisory_review.md`. The image is Asterisk `20.19.0`, newer than the affected Asterisk 20 ranges reviewed there.

Container state after the previous rebuild and recreate. Re-run this after the 2026-04-28 rtpengine non-root and metrics-listener changes:

- `ngn-sip-postgres-1` -> `ngn-sip/pgvector:0.8.0-pg16`
- `ngn-sip-asterisk-1` -> `ngn-sip/asterisk:20.19.0`
- `ngn-sip-kamailio-1` -> `ngn-sip/kamailio:5.8.8`
- `ngn-sip-rtpengine-1` -> `ngn-sip/rtpengine:10.5.3.5`

## Follow-Up

- Track upstream Debian/Alpine fixes for the listed `not fixed` CVEs and rebuild when patched packages land. Rerun `make scan-containers-fixable` on each rebuild; treat any new fixable C/H finding as a release blocker.
- Kamailio `CVE-2026-39863`: upstream fix applied via `5.8.8+bpo12`, but Docker Scout still flags the package as `not fixed`. Keep this as a documented scanner residual until Scout/Debian metadata catches up or a better package namespace is available.
- rtpengine mbedtls cluster: Mbed TLS 3.6.6/4.1.0 fixes the 2026 advisory set, but Debian Bookworm and Trixie packages remain vulnerable. The current exposure appears to come through Debian's `libwebsockets17` dependency rather than direct rtpengine DTLS linkage, so a clean fix is not a simple rtpengine source rebuild against a new mbedtls tarball; it would require rebuilding/replacing the dependent library stack and verifying ABI/runtime behavior.
- Sipwise rtpengine: the latest visible mr10.5 line is `mr10.5.9` with `ngcp-rtpengine-daemon_10.5.9.1+0~mr10.5.9.1_amd64.deb`, but that repository is Bullseye-oriented and predates the 2026 mbedtls fixes. Do not swap to it without a dedicated compatibility test.
- nghttp2 `CVE-2026-27135`: Debian Bookworm and Trixie remain vulnerable; Forky/Sid have `1.68.1-1` fixed. Do not move these images off Debian 12 only for this CVE.
- SIPp smoke (`make smoke`) passes after moving SIPp authentication credentials to the `-au` and `-ap` CLI flags and keeping `[authentication]` plain inside the XML scenarios.

## External Image Review

Upstream images pulled in for the observability, SIEM, and ML stacks. Project-built images have a stricter gate (`make scan-containers-fixable` must show 0); upstream images carry residual fixable C/H counts that are tracked here and re-evaluated on each pin bump.

| Image | Critical | High | Notes |
|---|---|---|---|
| `clickhouse/clickhouse-server:24.3.18.7-alpine` | 1 | 11 | musl 1.2.5-r9 cluster, fixed in 1.2.5-r11 (alpine 3.21 image lag). Track for next 24.3 LTS patch. |
| `timberio/vector:0.41.1-alpine` | 1 | 12 | Same musl cluster; will clear on the next Vector alpine rebase. |
| `grafana/grafana:11.3.1` | 7 | 39 | Wider OS surface (alpine + Go vendored deps). Bumping to 11.4.x in a hardening pass; track grafana release notes for the next LTS minor. |
| `prom/prometheus:v3.0.1` | n/a | n/a | Added to `SCAN_IMAGES_EXTERNAL`; scan pending because Docker Desktop was unavailable in the current session. Run and append counts here. |
| `wazuh/wazuh-manager:4.10.3` | 9 | 92 | Wazuh's reference image is a wide Amazon Linux/EL stack; many CVEs are accepted upstream as tracked-not-blocked. Document the residuals; cross-check against Wazuh's own advisory channel before non-loopback exposure. |
| `wazuh/wazuh-indexer:4.10.3` | n/a | n/a | Scout cache contention timed out; rerun. |
| `wazuh/wazuh-dashboard:4.10.3` | n/a | n/a | Pending - run on a hardening pass. |
| `ollama/ollama:0.21.2` | n/a | n/a | Pending - schedule alongside Stage 2 LLM activation. |

### Decisions

- Project-built images stay under the strict `make scan-containers-fixable` gate (0 fixable C/H must be true at all times).
- External images run through `make scan-containers-external-fixable` (Docker Scout) and `make scan-containers-external-trivy` (when trivy is installed) on a separate, advisory-only gate. They feed this document and must be reviewed before release.
- Every new Compose/k3s image must be added to `SCAN_IMAGES` or `SCAN_IMAGES_EXTERNAL`. Do not leave an image out of the inventory to avoid a noisy scan.
- All external services are loopback-bound (`DEV_BIND_IP=127.0.0.1`) so the residuals are not internet-exposed in local development. The campus VM deploy must rotate every default password and re-run a fresh scan against the version pinned at the time.
- Aikido (SAST/SCA/secrets/IaC, run from the maintainer's Aikido workspace), the Gitleaks workflow, GitHub secret scanning, and Dependabot cover new code in `attacks/orchestrator/`, `siem/wazuh/`, and `infra/clickhouse/init/`.

### Follow-up tasks

- Re-run `wazuh-indexer:4.10.3` Scout scan once Docker Desktop's scout cache clears (cache contention error today).
- Pull and scan `prom/prometheus:v3.0.1`, `wazuh/wazuh-dashboard:4.10.3`, `ollama/ollama:0.21.2` via `make scan-containers-external-fixable` and append rows above.
- Bump ClickHouse and Vector to next alpine 3.21 fix-release (musl 1.2.5-r11) the moment the upstream image rebuilds land - both should clear automatically.
- Track Grafana 11.x security-fix releases; bump on each minor.
- The stack now runs Wazuh 4.14.5 (see `wazuh_4.14_tls_setup.md`); re-scan the 4.14 images and refresh the residual rows above.
