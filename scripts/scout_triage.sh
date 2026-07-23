#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOCAL_ROOT="${SCOUT_LOCAL_ROOT:-/tmp/ngn-sip-scout-reports}"
REMOTE_ROOT="${SCOUT_REMOTE_ROOT:-~/scout-reports}"
TRIAGE_CMD="${SCOUT_TRIAGE_LLM_CMD:-${SCOUT_TRIAGE_CMD:-}}"

usage() {
  cat <<'EOF'
Usage:
  SCOUT_VM=user@vm ./scripts/scout_triage.sh
  SCOUT_VM=user@vm SCOUT_REPORT_DATE=2026-05-31 ./scripts/scout_triage.sh
  SCOUT_REPORT_SOURCE=/tmp/ngn-sip-scout-reports/2026-05-31 ./scripts/scout_triage.sh

Environment:
  SCOUT_VM                 SSH target for the VM that ran scout_scan.sh.
  SCOUT_REPORT_DATE        Optional date directory to copy. Defaults to latest remote report.
  SCOUT_REMOTE_ROOT        Remote report root. Default: ~/scout-reports.
  SCOUT_LOCAL_ROOT         Local copy root. Default: /tmp/ngn-sip-scout-reports.
  SCOUT_TRIAGE_LLM_CMD     Optional command that reads a prompt on stdin and writes Markdown to stdout.
  SCOUT_TRIAGE_CMD         Alias for SCOUT_TRIAGE_LLM_CMD.
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required." >&2
    exit 1
  fi
}

copy_report_from_vm() {
  local remote_path local_path

  mkdir -p "$LOCAL_ROOT"

  if [ -n "${SCOUT_REPORT_SOURCE:-}" ]; then
    local_path="${SCOUT_REPORT_SOURCE}"
    if [ ! -d "$local_path" ]; then
      echo "SCOUT_REPORT_SOURCE does not exist or is not a directory: $local_path" >&2
      exit 1
    fi
    printf '%s\n' "$local_path"
    return 0
  fi

  if [ -z "${SCOUT_VM:-}" ]; then
    usage >&2
    exit 2
  fi

  require_command ssh
  require_command scp

  if [ -n "${SCOUT_REPORT_DATE:-}" ]; then
    remote_path="${REMOTE_ROOT%/}/${SCOUT_REPORT_DATE}"
  else
    remote_path="$(
      ssh "$SCOUT_VM" "set -e; ls -1dt ${REMOTE_ROOT%/}/* 2>/dev/null | head -n 1"
    )"
  fi

  if [ -z "$remote_path" ]; then
    echo "No remote Scout reports found under ${REMOTE_ROOT} on ${SCOUT_VM}." >&2
    exit 1
  fi

  scp -q -r "${SCOUT_VM}:${remote_path}" "$LOCAL_ROOT/"
  local_path="${LOCAL_ROOT}/$(basename "$remote_path")"
  printf '%s\n' "$local_path"
}

build_llm_prompt() {
  local report_dir="$1"
  local output_path="$2"
  local report_date="$3"

  cat <<EOF
Generate a Docker Scout triage report in Markdown.

Report date: ${report_date}
Input directory: ${report_dir}
Output path: ${output_path}

Match the local precedent in docs/security/scout_triage_2026-04-28.md:
- title
- source and severity filter
- per-image verdict table
- bump candidates
- accepted residuals
- mitigation-required controls
- VM-readiness checklist
- test plan after each bump

Rank by scan gaps first, then fixable critical/high findings, then accepted residual critical/high findings.
Use only the copied Scout inputs. Do not require Docker Hub login or any secrets.

SUMMARY.txt:
EOF

  if [ -f "${report_dir}/SUMMARY.txt" ]; then
    sed -n '1,220p' "${report_dir}/SUMMARY.txt"
  else
    echo "SUMMARY.txt missing."
  fi

  echo
  echo "MANIFEST.tsv:"
  if [ -f "${report_dir}/MANIFEST.tsv" ]; then
    sed -n '1,220p' "${report_dir}/MANIFEST.tsv"
  else
    echo "MANIFEST.tsv missing."
  fi
}

run_triage() {
  local report_dir="$1"
  local output_path="$2"
  local report_date="$3"
  local tmp_output prompt_file

  tmp_output="$(mktemp)"
  prompt_file="$(mktemp)"
  cleanup() {
    rm -f "$tmp_output" "$prompt_file"
  }
  trap cleanup RETURN

  if [ -n "$TRIAGE_CMD" ]; then
    build_llm_prompt "$report_dir" "$output_path" "$report_date" >"$prompt_file"
    SCOUT_REPORT_DIR="$report_dir" \
      SCOUT_TRIAGE_OUTPUT="$output_path" \
      SCOUT_TRIAGE_DATE="$report_date" \
      sh -c "$TRIAGE_CMD" <"$prompt_file" >"$tmp_output"
  else
    require_command python3
    python3 "${SCRIPT_DIR}/scout_triage_summarizer.py" "$report_dir" "$tmp_output" "$report_date"
  fi

  if [ ! -s "$tmp_output" ]; then
    echo "Triage output was empty." >&2
    exit 1
  fi

  mv "$tmp_output" "$output_path"
  rm -f "$prompt_file"
  trap - RETURN
}

main() {
  local report_dir report_date output_path

  if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
  fi

  report_dir="$(copy_report_from_vm)"
  report_date="${SCOUT_REPORT_DATE:-$(basename "$report_dir")}"
  output_path="${REPO_ROOT}/docs/security/scout_triage_${report_date}.md"

  run_triage "$report_dir" "$output_path" "$report_date"

  echo "Wrote ${output_path}"
}

main "$@"
