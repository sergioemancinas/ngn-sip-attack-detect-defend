# Docker Scout triage pipeline

This pipeline separates the VM scan from the Mac triage step.

- `scripts/scout_scan.sh` runs on the VM that has Docker and the built images.
- `scripts/scout_triage.sh` runs on the Mac, copies the latest VM report with `scp`, then writes `docs/security/scout_triage_<date>.md`.
- `scripts/scout_cron.sh` wraps the VM scan for weekly cron use.

No Docker Hub login is required. The scripts do not read Docker Hub credentials, do not run `docker login`, and do not store secrets. SSH access for `scp` uses the operator's existing SSH setup.

## What the VM scan writes

`scripts/scout_scan.sh` installs the Docker Scout CLI plugin only if `docker scout version` is missing. The installer path is pinned by `SCOUT_VERSION` and defaults to `v1.20.4`. It downloads the matching GitHub release asset and verifies it against the release checksum file before installing to `~/.docker/cli-plugins/docker-scout`.

The scan writes a dated directory:

```bash
~/scout-reports/YYYY-MM-DD/
```

For each image it writes:

- `cves_<image>.json`: raw `docker scout cves --format json` output.
- `critical_high_<image>.md`: `docker scout cves --format markdown --only-severity critical,high` output.
- `scout_<image>.log`: command log for that image.
- `MANIFEST.tsv`: machine-readable status, counts, and report filenames.
- `SUMMARY.txt`: human-readable critical/high counts per image.

Project-built `ngn-sip/*` images are scanned through `local://` to match the existing Makefile gate. Wazuh images use their image references, matching the existing external-image convention.

The default image set is:

- `ngn-sip/kamailio`
- `ngn-sip/asterisk`
- `ngn-sip/rtpengine`
- `ngn-sip/pgvector`
- `ngn-sip/sipp`
- `ngn-sip/attacker`
- `wazuh/wazuh-manager`
- `wazuh/wazuh-indexer`
- `wazuh/wazuh-dashboard`

The script discovers local tags for these repositories first. If the attacker image uses a nonstandard tag and is not discoverable, set `SCOUT_ATTACKER_IMAGE=ngn-sip/attacker:<tag>` or pass the full image list with `SCOUT_IMAGES`.

## On-demand run

On the VM:

```bash
cd /path/to/ngn-sip-attack-detect-defend
./scripts/scout_scan.sh
```

On the Mac:

```bash
cd /path/to/ngn-sip-attack-detect-defend
SCOUT_VM=user@vm ./scripts/scout_triage.sh
```

To triage a specific VM date:

```bash
SCOUT_VM=user@vm SCOUT_REPORT_DATE=2026-05-31 ./scripts/scout_triage.sh
```

To triage an already copied local report directory:

```bash
SCOUT_REPORT_SOURCE=/tmp/ngn-sip-scout-reports/2026-05-31 ./scripts/scout_triage.sh
```

## Weekly cron

Install this on the VM crontab when the VM path is final:

```cron
0 6 * * 1 cd /path/to/ngn-sip-attack-detect-defend && /usr/bin/env bash ./scripts/scout_cron.sh
```

This runs every Monday at 06:00 in the VM's local timezone. It writes the dated scan report under `~/scout-reports/YYYY-MM-DD/` and a dated cron log under `~/scout-reports/logs/`.

## Triage generation

By default, `scripts/scout_triage.sh` uses `scripts/scout_triage_summarizer.py`. That path is deterministic and ranks by:

1. Missing or failed scan rows.
2. Fixable critical/high findings.
3. Accepted residual critical/high findings.
4. Clean images.

An optional LLM command can replace the deterministic summarizer:

```bash
SCOUT_VM=user@vm SCOUT_TRIAGE_LLM_CMD='your-command-here' ./scripts/scout_triage.sh
```

The command receives a prompt on stdin and must write Markdown to stdout. It also receives these environment variables:

- `SCOUT_REPORT_DIR`
- `SCOUT_TRIAGE_OUTPUT`
- `SCOUT_TRIAGE_DATE`

No model command is hardcoded in the repository.

## Fixable versus accepted

Fixable means Scout reports a fixed version for a critical or high finding. Treat fixable critical/high findings as action items:

- bump the affected image or package on the same supported line where possible
- rebuild project images
- rerun the VM scan
- regenerate the triage report

Accepted means Scout reports critical/high findings but no fixed version is available in the copied JSON. Accepted residuals are not ignored. They stay in the triage report with exposure controls and must be rechecked after base-image, distro, or vendor-image updates.

For this lab, accepted residuals require these controls:

- keep dashboards and SIEM services on loopback or private ingress only
- keep SIP service images on the zero-fixable critical/high gate
- keep Wazuh manager, indexer, and dashboard on one compatible release
- rotate lab defaults before any VM exposure beyond the trusted lab network
