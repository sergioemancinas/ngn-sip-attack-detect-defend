# Contributing

Thanks for your interest. This is a reproducible SIP attack-detect-defend
research testbed: a lab for studying honest detection/response evaluation, not
a production security product. Contributions that improve reproducibility,
detection engineering, evaluation rigor, or documentation are welcome.

## A few things to know first

The reported metrics are all pinned to committed run artifacts (a metrics JSON
or a reproducible run), so if you change a number, point to where it comes from.

Every credential in the repo is a lab placeholder (`change-me-local-only`, the
demo SIP passwords), and the stack is loopback-bound by design, so don't commit
real secrets and check `SECURITY.md` before proposing anything network-facing.

Changes should survive a clean `make clean && make up-all` on a fresh machine,
so pin any new dependencies and image tags.

## Local setup

Requires Docker (Engine 26+) with ~18 GiB available to the VM (the Wazuh indexer
alone needs ~3 GiB). On macOS, Colima is the tested runtime.

```bash
cp .env.example .env            # local-only placeholder defaults
make up-all                     # base + IDS + Keycloak + Wazuh + Homer + observability
make wazuh-sso-apply            # indexer OIDC
make ml-up && make ml-pull      # ML ring + models (~4.7 GB)
make soar-up                    # Shuffle + kamcmd-relay
bash scripts/setup_keycloak_sso_clients.sh   # SSO clients
bash scripts/provision_shuffle.sh            # import the SOAR workflow
```

Verify the full pipeline end-to-end:

```bash
make e2e        # drives labeled attack traffic and asserts every ring
```

## Making changes

1. Branch from `main`.
2. Keep commits focused; write why, not just what.
3. Run the relevant checks locally: `make e2e`, `cd ml && python -m pytest`,
   `shellcheck` on any changed scripts, and `docker compose -f <file> config` on
   any changed compose file.
4. Open a PR using the template. CI (lint, shellcheck, container security, ML
   tests) must pass.

## Reporting security issues

Do **not** open a public issue for a vulnerability. Follow `SECURITY.md`.
