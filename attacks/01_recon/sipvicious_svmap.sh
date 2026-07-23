#!/usr/bin/env bash
# Recon: SIPVicious svmap-style scan against the local Kamailio target.
# MITRE: T1595.001 (Active Scanning: Scanning IP Blocks)
# OWASP: A05 Security Misconfiguration (exposes server reachability + UA banner)
# Detection: Wazuh sid 100107 (scanner UA), Suricata sip-custom rule for friendly-scanner UA.
# FP scenarios: legitimate ops tools (sipsak, internal monitoring) - exclude lab subnets in tuning.
# Author: ngn-sip-detect-defend - Date: 2026-04-25

set -euo pipefail

TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-5060}"
OUTPUT_DIR="${OUTPUT_DIR:-./data/pcaps}"
NETWORK="${ATTACK_NETWORK:-ngn-sip_sip_lab}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
PCAP_DIR="${OUTPUT_DIR}/01_recon"
mkdir -p "${PCAP_DIR}"

echo "==> sipvicious svmap ${TARGET_HOST}:${TARGET_PORT} (label only - tool wrapper TBD)"
# Tool invocation placeholder. Once docker-compose.attack.yml ships sippts/sipvicious
# (finalisation), uncomment one of:
#   docker run --rm --network "${NETWORK}" pepelux/sippts:latest svmap -i "${TARGET_HOST}" -p "${TARGET_PORT}"
#   docker run --rm --network "${NETWORK}" enablesecurity/sipvicious svmap "${TARGET_HOST}:${TARGET_PORT}"
# For now we emit the ground-truth label so the orchestrator phase logs are coherent and the
# detection rules under siem/wazuh/rules can be exercised against a hand-crafted PCAP.

python -m attacks.orchestrator.label_emitter \
  "${TARGET_HOST}" \
  "sipvicious_svmap" \
  "T1595.001" \
  "recon" \
  "stub - upgrade once docker-compose.attack.yml provisions sippts"
