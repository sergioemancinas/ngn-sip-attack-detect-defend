#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_ROOT="${SCOUT_REPORT_ROOT:-${HOME}/scout-reports}"
REPORT_DATE="${SCOUT_REPORT_DATE:-$(date +%F)}"
LOG_DIR="${SCOUT_CRON_LOG_DIR:-${REPORT_ROOT}/logs}"
LOG_FILE="${LOG_DIR}/scout_cron_${REPORT_DATE}.log"

mkdir -p "$LOG_DIR"

{
  echo "Scout cron start: $(date -Is)"
  echo "Report date: ${REPORT_DATE}"
  SCOUT_REPORT_DATE="$REPORT_DATE" SCOUT_REPORT_ROOT="$REPORT_ROOT" "${SCRIPT_DIR}/scout_scan.sh"
  echo "Scout cron finish: $(date -Is)"
} >>"$LOG_FILE" 2>&1
