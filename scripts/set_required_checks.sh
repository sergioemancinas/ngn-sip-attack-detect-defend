#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <owner/repo> [branch]"
  echo "Example: $0 sergioemancinas/ngn-sip-detect-defend main"
}

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required." >&2
  exit 1
fi

if [ "${1:-}" = "" ]; then
  usage
  exit 1
fi

repo_full="$1"
branch="${2:-main}"
owner="${repo_full%%/*}"
repo="${repo_full##*/}"

checks='[
  "CI / lint-and-smoke",
  "ShellCheck / shellcheck",
  "Container Vulnerability Gate / Trivy fixable C/H gate"
]'

patch_payload="$(mktemp)"
put_payload="$(mktemp)"
cleanup() {
  rm -f "${patch_payload}" "${put_payload}"
}
trap cleanup EXIT

cat >"${patch_payload}" <<EOF
{
  "strict": true,
  "contexts": ${checks}
}
EOF

cat >"${put_payload}" <<EOF
{
  "required_status_checks": {
    "strict": true,
    "contexts": ${checks}
  },
  "enforce_admins": true,
  "required_pull_request_reviews": null,
  "restrictions": null
}
EOF

echo "Applying required status checks to ${owner}/${repo} (${branch})..."

if gh api \
  --method PATCH \
  -H "Accept: application/vnd.github+json" \
  "/repos/${owner}/${repo}/branches/${branch}/protection/required_status_checks" \
  --input "${patch_payload}" >/dev/null 2>&1; then
  echo "Updated existing branch protection required status checks."
  exit 0
fi

gh api \
  --method PUT \
  -H "Accept: application/vnd.github+json" \
  "/repos/${owner}/${repo}/branches/${branch}/protection" \
  --input "${put_payload}" >/dev/null

echo "Created branch protection with required status checks."
