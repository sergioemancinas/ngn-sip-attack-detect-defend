#!/usr/bin/env bash
set -euo pipefail

command -v docker >/dev/null
docker compose version >/dev/null
command -v git >/dev/null

echo "Dev machine prerequisites available."
