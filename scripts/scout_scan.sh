#!/usr/bin/env bash
set -euo pipefail

SCOUT_VERSION="${SCOUT_VERSION:-v1.20.4}"
REPORT_DATE="${SCOUT_REPORT_DATE:-$(date +%F)}"
REPORT_ROOT="${SCOUT_REPORT_ROOT:-${HOME}/scout-reports}"
REPORT_DIR="${REPORT_ROOT}/${REPORT_DATE}"
SCOUT_INSTALL_DIR="${SCOUT_INSTALL_DIR:-${HOME}/.docker/cli-plugins}"

EXPECTED_REPOS=(
  "ngn-sip/kamailio"
  "ngn-sip/asterisk"
  "ngn-sip/rtpengine"
  "ngn-sip/pgvector"
  "ngn-sip/sipp"
  "ngn-sip/attacker"
  "wazuh/wazuh-manager"
  "wazuh/wazuh-indexer"
  "wazuh/wazuh-dashboard"
)

fallback_image_for_repo() {
  case "$1" in
    ngn-sip/kamailio) echo "ngn-sip/kamailio:5.8.8" ;;
    ngn-sip/asterisk) echo "ngn-sip/asterisk:20.19.0" ;;
    ngn-sip/rtpengine) echo "ngn-sip/rtpengine:10.5.3.5" ;;
    ngn-sip/pgvector) echo "ngn-sip/pgvector:0.8.0-pg16" ;;
    ngn-sip/sipp) echo "ngn-sip/sipp:3.7.3" ;;
    ngn-sip/attacker) echo "${SCOUT_ATTACKER_IMAGE:-}" ;;
    wazuh/wazuh-manager) echo "wazuh/wazuh-manager:4.14.5" ;;
    wazuh/wazuh-indexer) echo "wazuh/wazuh-indexer:4.14.5" ;;
    wazuh/wazuh-dashboard) echo "wazuh/wazuh-dashboard:4.14.5" ;;
    *) echo "" ;;
  esac
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required." >&2
    exit 1
  fi
}

download_file() {
  local url="$1"
  local output="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$output"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$output" "$url"
  else
    echo "curl or wget is required to install Docker Scout." >&2
    exit 1
  fi
}

sha256_file() {
  local path="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  else
    echo "sha256sum or shasum is required to verify Docker Scout." >&2
    exit 1
  fi
}

normal_os() {
  local os
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$os" in
    linux) echo "linux" ;;
    *)
      echo "Unsupported OS for VM Scout installation: $os" >&2
      exit 1
      ;;
  esac
}

normal_arch() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64 | amd64) echo "amd64" ;;
    aarch64 | arm64) echo "arm64" ;;
    *)
      echo "Unsupported architecture for Docker Scout installation: $arch" >&2
      exit 1
      ;;
  esac
}

install_scout_if_missing() {
  if docker scout version >/dev/null 2>&1; then
    return 0
  fi

  local os arch version_no_v release_url checksum_name tmp_dir checksums asset_name asset_path expected actual binary_path
  os="$(normal_os)"
  arch="$(normal_arch)"
  version_no_v="${SCOUT_VERSION#v}"
  release_url="https://github.com/docker/scout-cli/releases/download/${SCOUT_VERSION}"
  checksum_name="docker-scout_${version_no_v}_checksums.txt"
  tmp_dir="$(mktemp -d)"

  cleanup_install() {
    rm -rf "$tmp_dir"
  }
  trap cleanup_install RETURN

  checksums="${tmp_dir}/${checksum_name}"
  download_file "${release_url}/${checksum_name}" "$checksums"

  asset_name="$(
    awk -v os="$os" -v arch="$arch" '
      {
        for (i = 1; i <= NF; i++) {
          if ($i ~ ("^docker-scout_.*_" os "_" arch "\\.tar\\.gz$")) {
            print $i
            exit
          }
        }
      }
    ' "$checksums"
  )"

  if [ -z "$asset_name" ]; then
    echo "No Docker Scout release asset found for ${os}/${arch} in ${checksum_name}." >&2
    exit 1
  fi

  asset_path="${tmp_dir}/${asset_name}"
  download_file "${release_url}/${asset_name}" "$asset_path"

  expected="$(
    awk -v asset="$asset_name" '
      {
        for (i = 1; i <= NF; i++) {
          if ($i == asset) {
            print $1
            exit
          }
        }
      }
    ' "$checksums"
  )"
  actual="$(sha256_file "$asset_path")"

  if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    echo "Docker Scout checksum verification failed for ${asset_name}." >&2
    exit 1
  fi

  tar -xzf "$asset_path" -C "$tmp_dir"
  binary_path="$(find "$tmp_dir" -type f -name docker-scout | head -n 1)"
  if [ -z "$binary_path" ]; then
    echo "Docker Scout binary not found in ${asset_name}." >&2
    exit 1
  fi
  mkdir -p "$SCOUT_INSTALL_DIR"
  install -m 0755 "$binary_path" "${SCOUT_INSTALL_DIR}/docker-scout"

  docker scout version >/dev/null
  cleanup_install
  trap - RETURN
}

safe_name() {
  printf '%s' "$1" | tr '/:@' '____' | tr -c 'A-Za-z0-9._-' '_'
}

scout_ref_for_image() {
  case "$1" in
    ngn-sip/*) echo "local://$1" ;;
    *) echo "$1" ;;
  esac
}

collect_images() {
  local repo fallback found image

  if [ -n "${SCOUT_IMAGES:-}" ]; then
    printf '%s\n' $SCOUT_IMAGES
    return 0
  fi

  for repo in "${EXPECTED_REPOS[@]}"; do
    found="$(
      docker image ls --format '{{.Repository}}:{{.Tag}}' "$repo" 2>/dev/null \
        | awk '$0 !~ /:<none>$/ {print}' \
        | sort -u
    )"

    if [ -n "$found" ]; then
      while IFS= read -r image; do
        [ -n "$image" ] && printf '%s\n' "$image"
      done <<EOF
$found
EOF
      continue
    fi

    fallback="$(fallback_image_for_repo "$repo")"
    if [ -n "$fallback" ]; then
      printf '%s\n' "$fallback"
    else
      printf 'MISSING:%s\n' "$repo"
    fi
  done
}

count_json_findings() {
  local json_file="$1"

  python3 - "$json_file" <<'PY'
import json
import sys

path = sys.argv[1]

with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)

severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unspecified": 0}
not_fixed = {"", "not fixed", "none", "null", "n/a", "na", "won't fix", "wont fix"}


def text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def get_first(mapping, keys):
    for key in keys:
        if key in mapping:
            value = mapping[key]
            if isinstance(value, dict):
                nested = get_first(value, keys)
                if nested:
                    return nested
            value_text = text(value)
            if value_text:
                return value_text
    return ""


def get_cve_id(mapping):
    value = get_first(mapping, ["cve", "CVE", "cveID", "cve_id", "id", "ID"])
    if value.upper().startswith("CVE-"):
        return value.upper()
    vuln = mapping.get("vulnerability")
    if isinstance(vuln, dict):
        return get_cve_id(vuln)
    if text(vuln).upper().startswith("CVE-"):
        return text(vuln).upper()
    return value


def get_severity(mapping):
    value = get_first(mapping, ["severity", "Severity"])
    return value.lower()


def fixed_values(node):
    values = []
    if isinstance(node, dict):
        for key, value in node.items():
            key_l = key.lower()
            if "fixed" in key_l or "fixversion" in key_l or "fix_version" in key_l or key_l == "fix":
                if isinstance(value, list):
                    values.extend(text(item) for item in value)
                else:
                    values.append(text(value))
            elif isinstance(value, (dict, list)):
                values.extend(fixed_values(value))
    elif isinstance(node, list):
        for item in node:
            values.extend(fixed_values(item))
    return values


def has_fix(mapping):
    for value in fixed_values(mapping):
        if value.lower().strip() not in not_fixed:
            return True
    return False


def package_name(mapping):
    return get_first(mapping, ["package", "packageName", "package_name", "name", "pkgName", "pkg_name"])


findings = []


def walk(node):
    if isinstance(node, dict):
        cve_id = get_cve_id(node)
        severity = get_severity(node)
        if cve_id.upper().startswith("CVE-") and severity in severity_rank:
            findings.append(
                {
                    "id": cve_id.upper(),
                    "severity": severity,
                    "fixable": has_fix(node),
                    "package": package_name(node),
                }
            )
            return
        for value in node.values():
            walk(value)
    elif isinstance(node, list):
        for item in node:
            walk(item)


walk(data)

critical = sum(1 for item in findings if item["severity"] == "critical")
high = sum(1 for item in findings if item["severity"] == "high")
fixable = sum(1 for item in findings if item["severity"] in {"critical", "high"} and item["fixable"])

top = "-"
if findings:
    ranked = sorted(
        findings,
        key=lambda item: (
            severity_rank.get(item["severity"], -1),
            1 if item["fixable"] else 0,
            item["id"],
        ),
        reverse=True,
    )
    top_item = ranked[0]
    top = f'{top_item["id"]} ({top_item["severity"].upper()})'

print(f"{critical}\t{high}\t{fixable}\t{top}")
PY
}

write_summary_header() {
  local scout_version
  scout_version="$(docker scout version 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]*$//')"

  {
    echo "Docker Scout scan summary - ${REPORT_DATE}"
    echo
    echo "Report directory: ${REPORT_DIR}"
    echo "Scout version: ${scout_version}"
    echo "No Docker Hub login is required or used by this script."
    echo
    echo "| Image | Status | Critical | High | Fixable C/H | Top finding |"
    echo "|---|---|---:|---:|---:|---|"
  } >"${REPORT_DIR}/SUMMARY.txt"

  {
    printf 'image\tscout_ref\tjson_report\tmarkdown_report\tstatus\tcritical\thigh\tfixable_critical_high\ttop_finding\n'
  } >"${REPORT_DIR}/MANIFEST.tsv"
}

scan_image() {
  local image="$1"
  local ref safe json_report markdown_report log_report counts critical high fixable top status

  if [[ "$image" == MISSING:* ]]; then
    image="${image#MISSING:}"
    status="missing"
    printf '| `%s` | %s | 0 | 0 | 0 | - |\n' "$image" "$status" >>"${REPORT_DIR}/SUMMARY.txt"
    printf '%s\t%s\t%s\t%s\t%s\t0\t0\t0\t-\n' "$image" "-" "-" "-" "$status" >>"${REPORT_DIR}/MANIFEST.tsv"
    return 0
  fi

  ref="$(scout_ref_for_image "$image")"
  safe="$(safe_name "$image")"
  json_report="${REPORT_DIR}/cves_${safe}.json"
  markdown_report="${REPORT_DIR}/critical_high_${safe}.md"
  log_report="${REPORT_DIR}/scout_${safe}.log"
  status="ok"

  echo "Scanning ${image}..."

  if ! docker scout cves --format json --output "${json_report}.tmp" "$ref" >"${log_report}" 2>&1; then
    status="json-failed"
    mv "${json_report}.tmp" "$json_report" 2>/dev/null || true
  else
    mv "${json_report}.tmp" "$json_report"
  fi

  if [ "$status" = "ok" ]; then
    if ! docker scout cves --format markdown --only-severity critical,high --output "${markdown_report}.tmp" "$ref" >>"${log_report}" 2>&1; then
      status="markdown-failed"
      mv "${markdown_report}.tmp" "$markdown_report" 2>/dev/null || true
    else
      mv "${markdown_report}.tmp" "$markdown_report"
    fi
  fi

  if [ "$status" = "ok" ]; then
    counts="$(count_json_findings "$json_report")"
    critical="$(printf '%s' "$counts" | awk -F '\t' '{print $1}')"
    high="$(printf '%s' "$counts" | awk -F '\t' '{print $2}')"
    fixable="$(printf '%s' "$counts" | awk -F '\t' '{print $3}')"
    top="$(printf '%s' "$counts" | awk -F '\t' '{print $4}')"
  else
    critical="0"
    high="0"
    fixable="0"
    top="-"
  fi

  printf '| `%s` | %s | %s | %s | %s | %s |\n' "$image" "$status" "$critical" "$high" "$fixable" "$top" >>"${REPORT_DIR}/SUMMARY.txt"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$image" "$ref" "$(basename "$json_report")" "$(basename "$markdown_report")" \
    "$status" "$critical" "$high" "$fixable" "$top" >>"${REPORT_DIR}/MANIFEST.tsv"
}

main() {
  local image total_critical total_high total_fixable failures

  require_command docker
  require_command awk
  require_command python3
  require_command tar

  install_scout_if_missing

  mkdir -p "$REPORT_DIR"
  write_summary_header

  while IFS= read -r image; do
    [ -z "$image" ] && continue
    scan_image "$image"
  done < <(collect_images)

  total_critical="$(awk -F '\t' 'NR > 1 {sum += $6} END {print sum + 0}' "${REPORT_DIR}/MANIFEST.tsv")"
  total_high="$(awk -F '\t' 'NR > 1 {sum += $7} END {print sum + 0}' "${REPORT_DIR}/MANIFEST.tsv")"
  total_fixable="$(awk -F '\t' 'NR > 1 {sum += $8} END {print sum + 0}' "${REPORT_DIR}/MANIFEST.tsv")"
  failures="$(awk -F '\t' 'NR > 1 && $5 != "ok" {count += 1} END {print count + 0}' "${REPORT_DIR}/MANIFEST.tsv")"

  {
    echo
    echo "Totals: critical=${total_critical} high=${total_high} fixable_critical_high=${total_fixable}"
    echo "Non-ok rows: ${failures}"
  } >>"${REPORT_DIR}/SUMMARY.txt"

  echo "Wrote Docker Scout reports to ${REPORT_DIR}"
  echo "Critical=${total_critical} High=${total_high} Fixable C/H=${total_fixable} Non-ok=${failures}"

  if [ "$failures" -gt 0 ]; then
    exit 1
  fi
}

main "$@"
