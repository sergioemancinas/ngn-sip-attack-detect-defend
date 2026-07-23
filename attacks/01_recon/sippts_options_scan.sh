#!/usr/bin/env bash
# Recon: SIP OPTIONS sweep via sippts.
# MITRE: T1595 (Active Scanning) generic enumeration of an SIP listener.
# OWASP: A05 Security Misconfiguration.
# Detection: Suricata SIP rule on OPTIONS volume from a single source; Wazuh sid 100107 if UA matches.
# FP scenarios: normal monitoring keep-alives (every UA pings periodically); rate-of-distinct-To-uri
#   should be the discriminator, not raw OPTIONS count.
# Author: ngn-sip-detect-defend - Date: 2026-04-25

set -euo pipefail

TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-5060}"
OUTPUT_DIR="${OUTPUT_DIR:-./data/pcaps}"
NETWORK="${ATTACK_NETWORK:-ngn-sip_sip_lab}"
mkdir -p "${OUTPUT_DIR}/01_recon"

echo "==> sippts scan OPTIONS ${TARGET_HOST}:${TARGET_PORT} (label only - tool wrapper TBD)"
# docker run --rm --network "${NETWORK}" pepelux/sippts:latest scan -i "${TARGET_HOST}" -p "${TARGET_PORT}" -m OPTIONS

python3 -m attacks.orchestrator.label_emitter \
  "${TARGET_HOST}" \
  "sippts_options" \
  "T1595" \
  "recon" \
  "stub - upgrade once docker-compose.attack.yml provisions sippts"
