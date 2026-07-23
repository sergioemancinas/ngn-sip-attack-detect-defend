# Security Policy

This is a research and lab project: a reproducible SIP attack-detect-defend
testbed built for an MSc lab course and an accompanying paper. It is not a
production system and ships no production deployment.

## Reporting a vulnerability

If you find a security issue in this repository (for example: a real credential
committed by mistake, a container escape in the provided Compose files, or a
flaw in the CI/CD configuration), please report it privately:

Please open a GitHub security advisory ("Report a vulnerability" on the
repository's Security tab). Include reproduction steps and the affected file or service. You can
expect an acknowledgement within a week. There is no bug bounty.

## Supported versions

Only the latest commit on `main` is supported. Older commits, tags, and
branches receive no fixes.

## Scope notes

Some weaknesses are part of the testbed's design, not vulnerabilities:

- Intentionally weak demo SIP credentials (e.g. extensions `1000`/`1001` with
  passwords `1000pass`/`1001pass`) exist so the attack scripts have something
  to brute-force. They are lab fixtures.
- Attack scripts under `attacks/` are offensive by design and must only be run
  against the lab stack itself.
- Placeholder values in `.env.example` are not secrets; real deployments must
  set their own values and keep management ports on loopback as documented.

Reports about these design decisions will be closed as expected behavior.
Anything that lets the lab affect systems outside the lab is in scope.

## Before exposing this stack to an untrusted network

This testbed is lab-secure, not internet-secure. If you intend to run it
anywhere reachable, follow the hardening checklist in
[`docs/INTERNET_EXPOSURE.md`](docs/INTERNET_EXPOSURE.md) first: rotate every
placeholder secret, keep management planes private, set `RELAY_ALLOW_PRIVATE=0`,
and harden Keycloak and the SIP edge.
