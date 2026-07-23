#!/usr/bin/env bash
#
# One-shot, idempotent post-up configuration. Run after `make up-all` (and,
# for the full pipeline, after `make ml-up && make ml-pull` and `make soar-up`).
# Folds every manual post-step into one health-gated, re-runnable command:
#
#   1. Wazuh indexer OIDC (securityadmin push)
#   2. Wazuh <localfile> registration for the SIP-correlation and ML logs
#      (skipped when the manager already self-registered them)
#   3. Keycloak SSO client provisioning
#   4. Shuffle workflow + webhook provisioning and the Wazuh->Shuffle wiring
#      (only when the SOAR stack is up)
#
# Safe to re-run: each step is idempotent and skips work already done.
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
PROJ="${COMPOSE_PROJECT_NAME:-ngn-sip}"
[ -f .env ] || { echo "no .env (cp .env.example .env first)"; exit 1; }

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
have() { docker ps --format '{{.Names}}' | grep -q "^$1$"; }
health() { docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$1" 2>/dev/null || echo missing; }
wait_healthy() {
  local c="$1" t="${2:-180}" e=0
  until [ "$(health "$c")" = healthy ]; do
    [ "$e" -ge "$t" ] && { echo "  timeout waiting for $c (status: $(health "$c"))"; return 1; }
    sleep 5; e=$((e+5))
  done
}

step "Waiting for Wazuh indexer + manager to be healthy"
wait_healthy "${PROJ}-wazuh-indexer-1" || exit 1
wait_healthy "${PROJ}-wazuh-manager-1" || exit 1
echo "  ready."

step "1/4 Wazuh indexer OIDC (idempotent securityadmin push)"
./scripts/apply_wazuh_sso.sh || echo "  (wazuh-sso-apply failed; continuing)"

step "2/4 Wazuh <localfile> registration (skip if already present)"
MGR="${PROJ}-wazuh-manager-1"
# grep -c prints "0" AND exits 1 when absent, so `|| echo 0` would append a
# second line ("0\n0") and break a string compare. Use -q and branch on the
# exit code instead, so the fallback actually runs when a localfile is missing.
if docker exec "$MGR" grep -qF 'ngnsec/kamailio-sec.log' /var/ossec/etc/ossec.conf 2>/dev/null; then
  echo "  SIP-correlation localfile already registered."
else
  bash siem/wazuh/setup_kamailio_localfile.sh || echo "  (SIP localfile step failed; continuing)"
fi
if docker exec "$MGR" grep -qF 'ml/stage1.json' /var/ossec/etc/ossec.conf 2>/dev/null; then
  echo "  ML localfile already registered."
else
  bash ml/deploy/setup_stage1_localfile.sh || echo "  (ML localfile step failed; continuing)"
fi

step "3/4 Keycloak SSO clients (idempotent)"
if wait_healthy "${PROJ}-keycloak-1" 60; then
  bash scripts/setup_keycloak_sso_clients.sh >/dev/null 2>&1 && echo "  SSO clients provisioned." || echo "  (SSO client provisioning failed; continuing)"
else echo "  Keycloak not up; skip SSO client provisioning."; fi

step "4/4 Shuffle SOAR provisioning"
if have shuffle-backend; then
  bash scripts/provision_shuffle.sh && \
    { echo "  installing Wazuh->Shuffle integration..."; $(command -v gmake >/dev/null && echo gmake || echo make) wazuh-integrate; } \
    || echo "  (Shuffle provisioning failed; re-run 'make bootstrap' once shuffle-backend is healthy)"
else
  echo "  SOAR stack not up. Run 'make soar-up' then 'make bootstrap' again to wire it."
fi

printf '\n\033[32mBootstrap complete.\033[0m Verify with: make e2e\n'
