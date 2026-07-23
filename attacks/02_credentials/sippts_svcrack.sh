#!/usr/bin/env bash
# Credentials: SIP digest brute force against extension 1000 via sippts svcrack.
# MITRE: T1110.001 (Brute Force: Password Guessing)
# OWASP: A07 Identification and Authentication Failures.
# Detection: Wazuh sid 100102 (auth-fail burst), 100105 (Asterisk PJSIP burst); Suricata custom rule.
# FP scenarios: corporate NAT egressing many UAs from one IP; tune frequency/timeframe per env.
# Wordlist: short.txt (30 well-known weak SIP creds). Replace with full rockyou for evaluation.
# Author: ngn-sip-detect-defend - Date: 2026-04-25

set -euo pipefail

TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-5060}"
OUTPUT_DIR="${OUTPUT_DIR:-./data/pcaps}"
NETWORK="${ATTACK_NETWORK:-ngn-sip_sip_lab}"
EXTENSION="${EXTENSION:-1000}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLIST="${WORDLIST:-${SCRIPT_DIR}/wordlists/short.txt}"
mkdir -p "${OUTPUT_DIR}/02_credentials"

if [ ! -f "${WORDLIST}" ]; then
  echo "wordlist not found: ${WORDLIST}" >&2
  exit 1
fi

echo "==> sippts svcrack ${TARGET_HOST}:${TARGET_PORT} ext=${EXTENSION} wordlist=${WORDLIST} (label only - tool wrapper TBD)"
# docker run --rm --network "${NETWORK}" -v "${WORDLIST}:/wordlist:ro" pepelux/sippts:latest \
#   svcrack -i "${TARGET_HOST}" -p "${TARGET_PORT}" -e "${EXTENSION}" -w /wordlist

python -m attacks.orchestrator.label_emitter \
  "${TARGET_HOST}" \
  "sippts_svcrack" \
  "T1110.001" \
  "credentials" \
  "stub - extension=${EXTENSION}, wordlist=$(basename "${WORDLIST}")"
