#!/usr/bin/env bash
set -euo pipefail

SIGMA_CLI_VERSION="3.0.2"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${SIGMA_VENV_DIR:-${TMPDIR:-/tmp}/ngn-sip-sigma-cli-${SIGMA_CLI_VERSION}}"

cd "$(dirname "$0")/../.."

if [ ! -x "${VENV_DIR}/bin/sigma" ] || ! "${VENV_DIR}/bin/python" -m pip show sigma-cli 2>/dev/null | grep -q "^Version: ${SIGMA_CLI_VERSION}$"; then
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
  "${VENV_DIR}/bin/python" -m pip install --upgrade pip
  "${VENV_DIR}/bin/python" -m pip install "sigma-cli==${SIGMA_CLI_VERSION}"
fi

"${VENV_DIR}/bin/sigma" check --fail-on-error --pass-on-issues siem/sigma/rules
