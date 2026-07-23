# Container Security Automation


## Goal

Automate vulnerability and malware controls for the local stack:

- Keep image CVE gating deterministic in CI/local.
- Keep source/dependency/secrets/IaC scanning in Aikido.
- Keep endpoint/runtime detection in the Wazuh + Shuffle layer.

## Security Gate Stack

1. **Aikido workflow (`.github/workflows/aikido.yml`)**  
   Gates PRs/releases for SAST, dependency, secrets, and IaC findings.

2. **Container CVE workflow (`.github/workflows/container-security.yml`)**  
   Builds the five service images and runs Trivy with:
   - severities: `critical,high`
   - policy: `--ignore-unfixed` (equivalent to a "fixable-only" gate)
   - fail behavior: `--exit-code 1`

3. **Local image gate (`Makefile`)**  
   - `make scan-containers-fixable` (Docker Scout)
   - `make scan-containers-trivy` (Trivy)

Both local targets are expected to stay green before merge.

## All-Image Docker Scout Policy

Every image introduced by a Compose file or later k3s manifest must be represented in the scan inventory:

- Project-built images go in `SCAN_IMAGES`.
- Upstream/vendor images go in `SCAN_IMAGES_EXTERNAL`.

Milestone sign-off requires a Docker Scout pass across both inventories:

```sh
make scan-containers-fixable
make scan-containers-external-fixable
```

Mitigation policy:

- Mitigate every fixable vulnerability when a patched package, pinned base image, or safer source build exists.
- Treat fixable critical/high findings as release blockers.
- Track lower-severity and upstream-unfixed findings in `docs/security/docker_image_review.md` with the affected package, current exposure, compensating control, and next recheck point.
- Do not hide residuals by omitting an image from the scan inventory.

## Required Checks On `main`

Set the following required checks on the default branch:

- `CI / lint-and-smoke`
- `ShellCheck / shellcheck`
- `Aikido Security Gate / Aikido SAST / SCA / Secrets / IaC`
- `Container Vulnerability Gate / Trivy fixable C/H gate`

Use:

```sh
./scripts/set_required_checks.sh <owner/repo> main
```

## Safe Chain Placement

Safe Chain is best used as **dependency-install protection** (developer laptops and CI), not as a container image CVE scanner.

- Local install (already supported by Aikido Safe Chain):
  - `curl -fsSL https://github.com/AikidoSec/safe-chain/releases/latest/download/install-safe-chain.sh | sh`
- CI install pattern when package managers are used:
  - `curl -fsSL https://github.com/AikidoSec/safe-chain/releases/latest/download/install-safe-chain.sh | sh -s -- --ci`

In this repository today, Safe Chain is most relevant for workflow steps that run `npm`, `pip`, or similar package manager commands (for example, installing tooling in CI).

## Wazuh / Shuffle Boundary

- **Wazuh**: host/container runtime telemetry, detection, and alerting.
- **Shuffle**: response orchestration and playbook automation.

These are runtime controls and remain out of the local build/PR gate by design. They should consume signals produced by runtime systems, while PR/build gates (Aikido + Trivy/Scout) stop known-bad code/images before deployment.
