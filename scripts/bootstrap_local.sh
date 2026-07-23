#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

if [[ ! -f .env ]]; then
  cp .env.example .env
fi

docker compose up -d --build postgres asterisk kamailio rtpengine
docker compose ps
