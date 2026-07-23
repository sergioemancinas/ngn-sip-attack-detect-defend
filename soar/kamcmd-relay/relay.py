#!/usr/bin/env python3
"""kamcmd-relay: HTTP ban enforcement endpoint for the Shuffle SOAR workflow.

This is the missing executor behind ${KAMCMD_BLOCK_RELAY_URL} in
soar/shuffle/workflows/sip_response_orchestration.json. Shuffle workers on the
sip_lab network cannot run `docker exec`, so this sidecar exposes the
kamcmd_block.sh JSON contract over HTTP and enforces bans with the IDENTICAL
mechanism the deployed kamailio-autoban sidecar uses
(siem/wazuh/active-response/autoban_loop.sh):

    docker exec <kamailio> /usr/sbin/kamcmd htable.sets ban_table <ip> 1

executed here via the Docker Engine API over the read-only docker.sock mount
(exec create/start/inspect) - same privilege model as autoban (socket only, no
host root). htable.sets is idempotent and refreshes ban_table's
autoexpire=3600 TTL (infra/kamailio/modules/htable.cfg); DROP_IF_BANNED
(infra/kamailio/modules/ban.cfg) then drops the source at the edge.

Safeguards (parity with autoban_loop.sh / kamcmd_block.sh):
  * bare-IP-literal validation ^[0-9A-Fa-f.:]+$ before anything reaches kamcmd
  * never-ban allowlist: NEVER_BAN_IPS + live IPs of PROTECTED_CONTAINERS
    (docker inspect) + this relay's own IPs. SIP-over-UDP sources are
    spoofable (RFC 3261 sec 26), so a forged internal address must never be
    bannable (blocklist poisoning -> self-DoS).
  * RFC1918/loopback/link-local/multicast/reserved refused by default.
    RELAY_ALLOW_PRIVATE=1 relaxes ONLY the RFC1918 part (lab attackers live on
    the 172.x sip_lab bridge - same posture as autoban's Wazuh-alert path);
    loopback/multicast/etc. and the allowlist are always enforced.
  * shared-secret auth: Authorization: Bearer ${RELAY_TOKEN} (constant-time
    compare). Fails closed if RELAY_TOKEN is unset.

Every request outcome is audited to ngn_sip.ban_audit over ClickHouse HTTP
(same columns as infra/clickhouse/init/09_ban_audit.sql), so the SOAR ban path
and the autoban path share one evidence trail.

Endpoints:
  POST /kamcmd-block   ban/unban (see README.md for the JSON contract)
  GET  /healthz        liveness (no auth)

Stdlib only (http.server, http.client over AF_UNIX, urllib). No dependencies.
"""

import http.client
import http.server
import hmac
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.request

# --------------------------------------------------------------------------
# Configuration (env)
# --------------------------------------------------------------------------
PORT = int(os.environ.get("PORT", "8099"))
RELAY_TOKEN = os.environ.get("RELAY_TOKEN", "")
KAMAILIO_CTR = os.environ.get("KAMAILIO_CTR", "ngn-sip-kamailio-1")
KAMCMD_PATH = os.environ.get("KAMCMD_PATH", "/usr/sbin/kamcmd")
HTABLE_NAME = os.environ.get("HTABLE_NAME", "ban_table")
DOCKER_SOCK = os.environ.get("DOCKER_SOCK", "/var/run/docker.sock")
CLICKHOUSE_URL = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123").rstrip("/")
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "ngn")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")
# Space- or comma-separated static never-ban list (parity with autoban_loop.sh).
NEVER_BAN_IPS = set(
    os.environ.get("NEVER_BAN_IPS", "127.0.0.1 ::1").replace(",", " ").split()
)
# Same default protected set as autoban_loop.sh / kamcmd_block.sh.
PROTECTED_CONTAINERS = os.environ.get(
    "PROTECTED_CONTAINERS",
    "ngn-sip-asterisk-1 ngn-sip-kamailio-1 ngn-sip-rtpengine-1 "
    "ngn-sip-prometheus-1 ngn-sip-vector-1 ngn-sip-clickhouse-1 "
    "ngn-sip-kamailio-sec-relay-1 ngn-sip-postgres-1",
).split()
ALLOW_PRIVATE = os.environ.get("RELAY_ALLOW_PRIVATE", "0") == "1"
# ban_table autoexpire in infra/kamailio/modules/htable.cfg; audited as the
# effective TTL when the caller does not request one.
DEFAULT_TTL_SECONDS = int(os.environ.get("DEFAULT_TTL_SECONDS", "3600"))
MAX_TTL_SECONDS = int(os.environ.get("MAX_TTL_SECONDS", "86400"))
MAX_BODY_BYTES = 65536
PROTECTED_CACHE_SECONDS = 30
DOCKER_TIMEOUT = 10
AUDIT_TIMEOUT = 5

# Parity with autoban_loop.sh valid_ip() / kamcmd_block.sh: bare IP literal only.
IP_LITERAL = re.compile(r"^[0-9A-Fa-f.:]+$")


def log(level, msg, **fields):
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "level": level,
        "component": "kamcmd-relay",
        "msg": msg,
    }
    rec.update(fields)
    print(json.dumps(rec, separators=(",", ":")), flush=True)


# --------------------------------------------------------------------------
# Docker Engine API over the unix socket (stdlib http.client)
# --------------------------------------------------------------------------
class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, sock_path, timeout=DOCKER_TIMEOUT):
        super().__init__("localhost", timeout=timeout)
        self._sock_path = sock_path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._sock_path)
        self.sock = s


def docker_request(method, path, payload=None):
    """Single request against the Docker Engine API. Returns (status, body-bytes)."""
    conn = UnixHTTPConnection(DOCKER_SOCK)
    try:
        body = None
        headers = {"Host": "docker"}
        if payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def docker_exec(container, cmd):
    """Equivalent of `docker exec <container> <cmd...>`. Returns (exit_code, output).

    exit_code is None when the exec could not even be created/started.
    """
    try:
        status, body = docker_request(
            "POST",
            f"/containers/{container}/exec",
            {"AttachStdout": True, "AttachStderr": True, "Cmd": cmd},
        )
        if status != 201:
            log("error", "docker exec create failed", container=container,
                status=status, detail=body.decode(errors="replace")[:200])
            return None, ""
        exec_id = json.loads(body)["Id"]
        status, out = docker_request(
            "POST", f"/exec/{exec_id}/start", {"Detach": False, "Tty": False}
        )
        if status != 200:
            log("error", "docker exec start failed", container=container, status=status)
            return None, ""
        status, meta = docker_request("GET", f"/exec/{exec_id}/json")
        exit_code = json.loads(meta).get("ExitCode") if status == 200 else None
        # Output is a multiplexed raw stream; we only ever log a snippet.
        return exit_code, out.decode(errors="replace")
    except (OSError, ValueError, KeyError, http.client.HTTPException) as exc:
        log("error", "docker api error", container=container, error=str(exc))
        return None, ""


def kamcmd(*args):
    """Identical invocation to autoban_loop.sh:
    docker exec $KAMAILIO /usr/sbin/kamcmd <args...>"""
    return docker_exec(KAMAILIO_CTR, [KAMCMD_PATH, *args])


def container_ips(name):
    ips = set()
    try:
        status, body = docker_request("GET", f"/containers/{name}/json")
        if status == 200:
            nets = json.loads(body).get("NetworkSettings", {}).get("Networks", {})
            for net in nets.values():
                ip = net.get("IPAddress") or ""
                if ip:
                    ips.add(ip)
                ip6 = net.get("GlobalIPv6Address") or ""
                if ip6:
                    ips.add(ip6)
    except (OSError, ValueError, http.client.HTTPException):
        pass
    return ips


def own_ips():
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except OSError:
        pass
    return ips


# --------------------------------------------------------------------------
# Never-ban allowlist (parity with autoban_loop.sh refresh_allowlist)
# --------------------------------------------------------------------------
_allowlist_lock = threading.Lock()
_allowlist_cache = {"ts": 0.0, "ips": set()}


def protected_ips():
    """NEVER_BAN_IPS + live protected container IPs + this relay's own IPs."""
    now = time.monotonic()
    with _allowlist_lock:
        if now - _allowlist_cache["ts"] < PROTECTED_CACHE_SECONDS:
            return _allowlist_cache["ips"]
    acc = set(NEVER_BAN_IPS) | own_ips()
    for ctr in PROTECTED_CONTAINERS:
        acc |= container_ips(ctr)
    with _allowlist_lock:
        _allowlist_cache["ts"] = now
        _allowlist_cache["ips"] = acc
    return acc


# --------------------------------------------------------------------------
# ClickHouse audit trail (columns per infra/clickhouse/init/09_ban_audit.sql)
# --------------------------------------------------------------------------
BAN_AUDIT_DDL = (
    "CREATE TABLE IF NOT EXISTS ngn_sip.ban_audit ("
    "event_time DateTime64(3) DEFAULT now64(3), src_ip String, "
    "action LowCardinality(String), reason String, min_level UInt16, "
    "ttl_seconds UInt32) ENGINE = MergeTree ORDER BY event_time"
)


def ch_post(query_body):
    req = urllib.request.Request(
        CLICKHOUSE_URL + "/?database=ngn_sip",
        data=query_body.encode(),
        headers={
            "Content-Type": "text/plain",
            "X-ClickHouse-User": CLICKHOUSE_USER,
            "X-ClickHouse-Key": CLICKHOUSE_PASSWORD,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=AUDIT_TIMEOUT) as resp:
        return resp.status


def sanitize_ip_field(value):
    """Same neutralisation as autoban_loop.sh audit(): keep IP-literal chars only."""
    return re.sub(r"[^0-9A-Fa-f.:_-]", "", str(value))[:64]


def audit(action, src_ip, reason, min_level=0, ttl_seconds=None):
    """Write one ban_audit evidence row. Failure is logged, never raised:
    an audit outage must not turn into an enforcement outage (autoban parity:
    its ch() also swallows errors). Injection-safe: row travels as
    JSONEachRow data, never interpolated into SQL."""
    row = {
        "src_ip": sanitize_ip_field(src_ip),
        "action": action,
        "reason": str(reason)[:500],
        "min_level": int(min_level) if str(min_level).isdigit() else 0,
        "ttl_seconds": int(ttl_seconds if ttl_seconds is not None else DEFAULT_TTL_SECONDS),
    }
    query = (
        "INSERT INTO ngn_sip.ban_audit "
        "(src_ip, action, reason, min_level, ttl_seconds) FORMAT JSONEachRow\n"
        + json.dumps(row)
    )
    try:
        ch_post(query)
        return True
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log("error", "ban_audit insert failed", action=action,
            src_ip=row["src_ip"], error=str(exc))
        return False


def audit_init():
    """Best-effort CREATE TABLE IF NOT EXISTS at startup (autoban parity)."""
    for attempt in range(30):
        try:
            ch_post(BAN_AUDIT_DDL)
            log("info", "ban_audit table ensured")
            return
        except (urllib.error.URLError, OSError) as exc:
            if attempt == 0:
                log("warn", "clickhouse not reachable yet, retrying", error=str(exc))
            time.sleep(5)
    log("error", "giving up on ban_audit DDL; audit inserts will retry per-request")


# --------------------------------------------------------------------------
# Request validation
# --------------------------------------------------------------------------
def parse_ip(raw):
    """Return an ipaddress object for a bare IP literal, else None.

    IPv4-mapped IPv6 (::ffff:a.b.c.d) is unmapped to the embedded IPv4, matching
    ml/stage2/worker.py and observability/hep-bridge/bridge.py. Without this a
    real external attacker whose address reaches the relay in mapped form parses
    as is_reserved and is silently skipped instead of banned.
    """
    if not isinstance(raw, str) or not raw or not IP_LITERAL.fullmatch(raw):
        return None
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def refusal_reason(ip_obj):
    """Why this IP must not be banned, or None if bannable.

    Always refused: allowlist (protected stack / NEVER_BAN_IPS / self),
    loopback, link-local, multicast, unspecified, reserved.
    Refused unless RELAY_ALLOW_PRIVATE=1: RFC1918 / ULA private space.
    """
    literal = str(ip_obj)
    if literal in NEVER_BAN_IPS or literal in protected_ips():
        return "in never-ban allowlist (protected stack source)"
    if ip_obj.is_loopback:
        return "loopback address"
    if ip_obj.is_link_local:
        return "link-local address"
    if ip_obj.is_multicast:
        return "multicast address"
    if ip_obj.is_unspecified:
        return "unspecified address"
    if ip_obj.is_reserved:
        return "reserved address"
    # not is_global covers RFC1918/ULA plus CGN (100.64/10) and the RFC5737
    # documentation ranges - none of which should be bannable in the default
    # (internet-facing) posture. RELAY_ALLOW_PRIVATE=1 relaxes only this check
    # (lab mode: attackers live on the 172.x sip_lab bridge, same posture as
    # autoban's Wazuh-alert path); everything above stays enforced.
    if not ip_obj.is_global and not ALLOW_PRIVATE:
        return "non-global address (private/CGN/documentation) and RELAY_ALLOW_PRIVATE=0"
    return None


def extract_request(body):
    """Accept both contracts:
    A) flat: {src_ip, rule_id?, rule_level?, reason?, ttl_seconds?, token?}
    B) kamcmd_block.sh / workflow: {command, parameters.alert.data.srcip, token?}
    Returns dict(command, src_ip_raw, rule_id, rule_level, reason, ttl, token).
    """
    src = body.get("src_ip") or body.get("srcip")
    if not src:
        src = (
            body.get("parameters", {})
            .get("alert", {})
            .get("data", {})
            .get("srcip")
            if isinstance(body.get("parameters"), dict)
            else None
        )
    ttl = body.get("ttl_seconds")
    try:
        ttl = int(ttl) if ttl is not None else None
    except (TypeError, ValueError):
        ttl = -1  # flagged invalid downstream
    return {
        "command": str(body.get("command", "add")).lower(),
        "src_ip_raw": src,
        "rule_id": body.get("rule_id", ""),
        "rule_level": body.get("rule_level", 0),
        "reason": str(body.get("reason", ""))[:200],
        "ttl": ttl,
        "token": body.get("token", ""),
    }


# --------------------------------------------------------------------------
# Enforcement
# --------------------------------------------------------------------------
def enforce_ban(ip_literal, ttl):
    """Replicates autoban_loop.sh exactly:
    kamcmd htable.sets ban_table <ip> 1  (idempotent; refreshes autoexpire TTL)
    then best-effort per-item TTL via htable.setex when the caller asked for a
    non-default ttl_seconds. Returns (ok, effective_ttl)."""
    code, out = kamcmd("htable.sets", HTABLE_NAME, ip_literal, "1")
    if code != 0:
        log("error", "kamcmd htable.sets failed", src_ip=ip_literal,
            exit_code=code, output=out[:200])
        return False, ttl or DEFAULT_TTL_SECONDS
    effective = DEFAULT_TTL_SECONDS
    if ttl and ttl != DEFAULT_TTL_SECONDS:
        code2, out2 = kamcmd("htable.setex", HTABLE_NAME, ip_literal, str(ttl))
        if code2 == 0:
            effective = ttl
        else:
            log("warn", "htable.setex not honored; falling back to table autoexpire",
                src_ip=ip_literal, requested_ttl=ttl, autoexpire=DEFAULT_TTL_SECONDS)
    return True, effective


def enforce_unban(ip_literal):
    """kamcmd htable.delete ban_table <ip> (kamcmd_block.sh delete contract)."""
    code, _ = kamcmd("htable.delete", HTABLE_NAME, ip_literal)
    # htable.delete on a missing key returns non-zero on some builds; treat
    # "container reachable, command ran" (code is not None) as success like
    # kamcmd_block.sh does (`|| true`).
    return code is not None


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "kamcmd-relay"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # route access logs through structured log
        pass

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self, _body_token=None):
        # Header-only: the Authorization header is the sole accepted credential.
        # A token in the JSON body is more likely to be captured in proxy/access
        # logs, so it is intentionally not honored (the Shuffle workflow presents
        # the Bearer header). _body_token is kept for signature compatibility.
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return False
        presented = header[len("Bearer "):].strip()
        if not RELAY_TOKEN or not presented:
            return False
        return hmac.compare_digest(presented, RELAY_TOKEN)

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, {"status": "ok", "component": "kamcmd-relay"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/kamcmd-block":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send(413 if length > MAX_BODY_BYTES else 400,
                       {"error": "missing or oversized body"})
            return
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise ValueError("body is not a JSON object")
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"error": "invalid JSON"})
            return

        req = extract_request(body)
        src_display = req["src_ip_raw"] if isinstance(req["src_ip_raw"], str) else ""

        # 1. Auth (fail closed). Unauthorized attempts are logged to stdout only,
        # NOT written to ClickHouse: an unauthenticated caller must not be able to
        # drive a DB insert per request (audit-write amplification / DoS). The
        # structured stderr/stdout log still leaves evidence, captured by the log
        # pipeline, without giving an anonymous peer a write primitive.
        if not self._authorized(req["token"]):
            log("warn", "unauthorized request", src_ip=sanitize_ip_field(src_display),
                peer=self.client_address[0])
            self._send(401, {"error": "unauthorized"})
            return

        # 2. IP literal validation (parity with kamcmd_block.sh / autoban).
        ip_obj = parse_ip(src_display)
        if ip_obj is None:
            log("warn", "rejected non-IP literal", value=sanitize_ip_field(src_display))
            audit("reject_invalid", src_display, "not a bare IP literal",
                  req["rule_level"])
            self._send(400, {"error": "src_ip is not a bare IP literal"})
            return
        ip_literal = str(ip_obj)

        # 3. TTL validation.
        ttl = req["ttl"]
        if ttl is not None and (ttl < 1 or ttl > MAX_TTL_SECONDS):
            audit("reject_invalid", ip_literal,
                  f"ttl_seconds out of range 1..{MAX_TTL_SECONDS}", req["rule_level"])
            self._send(400, {"error": f"ttl_seconds must be 1..{MAX_TTL_SECONDS}"})
            return

        reason = req["reason"] or "SOAR graded ban via Shuffle workflow"
        if req["rule_id"]:
            reason = f"{reason} (wazuh rule_id={sanitize_ip_field(req['rule_id'])})"

        # 4. Unban path (kamcmd_block.sh delete contract; no allowlist gate).
        if req["command"] == "delete":
            ok = enforce_unban(ip_literal)
            action = "unban" if ok else "unban_failed"
            log("info" if ok else "error", action, src_ip=ip_literal)
            audit(action, ip_literal, reason, req["rule_level"], 0)
            self._send(200 if ok else 502,
                       {"action": action, "src_ip": ip_literal})
            return

        # 5. Never-ban safeguards (spoofing guard, RFC 3261 sec 26).
        refusal = refusal_reason(ip_obj)
        if refusal:
            log("warn", "skipped protected source", src_ip=ip_literal, reason=refusal)
            audit("skip_protected", ip_literal, refusal, req["rule_level"],
                  ttl or DEFAULT_TTL_SECONDS)
            self._send(403, {"action": "skip_protected", "src_ip": ip_literal,
                             "reason": refusal})
            return

        # 6. Enforce at the SBC (identical mechanism to autoban_loop.sh).
        ok, effective_ttl = enforce_ban(ip_literal, ttl)
        if ok:
            log("info", "BANNED", src_ip=ip_literal, ttl_seconds=effective_ttl,
                reason=reason)
            audited = audit("ban", ip_literal, reason, req["rule_level"], effective_ttl)
            self._send(200, {"action": "ban", "src_ip": ip_literal,
                             "htable": HTABLE_NAME, "ttl_seconds": effective_ttl,
                             "audited": audited})
        else:
            audit("ban_failed", ip_literal, "kamcmd error", req["rule_level"],
                  ttl or DEFAULT_TTL_SECONDS)
            self._send(502, {"action": "ban_failed", "src_ip": ip_literal,
                             "error": "kamcmd htable.sets failed"})


def main():
    if not RELAY_TOKEN:
        log("fatal", "RELAY_TOKEN is not set; refusing to start (fail closed)")
        sys.exit(1)
    if RELAY_TOKEN.startswith("change-me"):
        log("warn", "RELAY_TOKEN looks like a placeholder; rotate it in .env")
    if ALLOW_PRIVATE:
        log("warn", "RELAY_ALLOW_PRIVATE=1: RFC1918 sources are bannable "
            "(lab mode, parity with autoban's Wazuh path); allowlist still enforced")
    threading.Thread(target=audit_init, daemon=True).start()
    # Warm the allowlist cache so the first request does not pay the inspect cost.
    threading.Thread(target=protected_ips, daemon=True).start()
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log("info", "kamcmd-relay listening", port=PORT, kamailio=KAMAILIO_CTR,
        htable=HTABLE_NAME, clickhouse=CLICKHOUSE_URL, allow_private=ALLOW_PRIVATE)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
