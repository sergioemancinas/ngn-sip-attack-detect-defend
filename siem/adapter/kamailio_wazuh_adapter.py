#!/usr/bin/env python3
"""
Kamailio -> Wazuh event adapter (NGN SIP attack-detect-defend).

Problem it solves: the Wazuh SIP ruleset (100100..100134) chains off a base
rule that matches a Kamailio "NGN-SEC" log line:

    NGN-SEC <event_type> src=<ip> ua="<ua>" reason="<reason>"

Kamailio only emits a few of those reason strings, so most rules never see a
matching line and stay dead (measured: 4 of 35 fired under live exposure).
This adapter reads the authoritative detections already in ClickHouse
(sip_events, suricata_alerts) and emits the full NGN-SEC vocabulary in the
exact format the Wazuh kamailio decoder parses, so the correlation rules fire
on real traffic and feed the autoban.

Design notes:
  - Output is a kamailio-style syslog line so program_name resolves to
    "kamailio" and the existing decoder/rules apply unchanged. The line is
    written to ADAPTER_LOG, which Wazuh reads via a <localfile> (syslog).
  - Per-source, per-condition rate caps (MAX_PER_SRC) let Wazuh frequency
    rules trip (e.g. 100102 needs 5 auth failures / 60s) without recreating a
    log flood. This mirrors the Suricata threshold fix.
  - A watermark file makes polling idempotent across restarts.
  - No third-party dependencies (urllib + ClickHouse HTTP).
"""

import os
import sys
import json
import time
import socket
import urllib.parse
import urllib.request
from datetime import datetime, timezone

CH_URL = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123")
CH_USER = os.environ.get("CLICKHOUSE_USER", "ngn")
CH_PASS = os.environ.get("CLICKHOUSE_PASSWORD", "")
ADAPTER_LOG = os.environ.get("ADAPTER_LOG", "/out/ngnsec/kamailio-ngnsec.log")
WATERMARK = os.environ.get("ADAPTER_WATERMARK", "/tmp/kw_adapter.watermark")
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "30"))
LOOKBACK_SECONDS = int(os.environ.get("LOOKBACK_SECONDS", "120"))
MAX_PER_SRC = int(os.environ.get("MAX_PER_SRC", "12"))       # cap lines/src/condition/poll
EXTERNAL_ONLY = os.environ.get("EXTERNAL_ONLY", "1") == "1"  # skip RFC1918 sources
HOSTNAME = socket.gethostname()

PREMIUM = r"(?:1900|1809|1268|1976|976|979)"  # premium-rate prefixes (rules 100118/100119)


def ch_query(sql):
    """Run a ClickHouse query over HTTP, return list of tab-split rows."""
    data = sql.encode()
    req = urllib.request.Request(
        CH_URL + "/?" + urllib.parse.urlencode({"user": CH_USER, "password": CH_PASS}),
        data=data,
        headers={"Content-Type": "text/plain"},
    )
    with urllib.request.urlopen(req, timeout=25) as r:
        text = r.read().decode(errors="replace")
    return [line.split("\t") for line in text.splitlines() if line]


def read_watermark():
    try:
        return open(WATERMARK).read().strip()
    except Exception:
        return None


def write_watermark(ts):
    try:
        with open(WATERMARK, "w") as f:
            f.write(ts)
    except Exception as e:
        log_stderr(f"watermark write failed: {e}")


def log_stderr(msg):
    sys.stderr.write(f"{datetime.now().isoformat()} kw-adapter {msg}\n")
    sys.stderr.flush()


def emit(fh, event_type, src_ip, ua, reason):
    """Write one NGN-SEC line in kamailio syslog format the decoder expects."""
    ua = (ua or "").replace('"', "").replace("\n", " ")[:128]
    reason = (reason or "").replace('"', "").replace("\n", " ")[:128]
    stamp = datetime.now().strftime("%b %d %H:%M:%S")
    fh.write(
        f'{stamp} {HOSTNAME} kamailio[1]: NOTICE: ngn_sec: '
        f'NGN-SEC {event_type} src={src_ip} ua="{ua}" reason="{reason}"\n'
    )


# Each entry: (event_type, reason_expr, WHERE clause on sip_events).
# reason_expr is a ClickHouse expression producing the reason string.
# NOTE: auth failures are handled separately (auth_failures query) because the
# 401/403 response row carries the server address, not the attacker. The real
# source is on the REGISTER request, joined by call_id over the poll window.
SIP_MAP = [
    # REGISTER / INVITE volume -> frequency flood rules 100108 / 100111
    ("REGISTER", "'register'", "method = 'REGISTER'"),
    ("INVITE", "'invite'", "method = 'INVITE'"),
    # Toll fraud: INVITE to premium-rate destination -> 100118 / 100119
    ("INVITE", "concat('dst=', to_uri)",
     f"method = 'INVITE' AND match(to_uri, '{PREMIUM}[0-9]{{4,}}')"),
    # OPTIONS scan / keepalive -> 100125 / 100126 / 100127
    ("OPTIONS", "'keepalive'", "method = 'OPTIONS'"),
    ("SUBSCRIBE", "'subscribe'", "method = 'SUBSCRIBE'"),
    ("NOTIFY", "'notify'", "method = 'NOTIFY'"),
]

# Suricata signature id -> (event_type, reason) for malformed-header rules.
SURICATA_MAP = {
    "1000006": ("INVITE", "malformed_via"),   # -> rule 100113
    "1000007": ("INVITE", "malformed_cseq"),  # -> rule 100114
}

RFC1918 = ("10.", "172.", "192.168.", "127.")


def external(ip):
    if not EXTERNAL_ONLY:
        return True
    return not any(ip.startswith(p) for p in RFC1918)


def poll(fh, since_expr):
    n = 0
    # sip_events driven conditions
    for event_type, reason_expr, where in SIP_MAP:
        sql = (
            f"SELECT replaceOne(toString(src_ip),'::ffff:','') ip, "
            f"any(user_agent), {reason_expr} reason "
            f"FROM ngn_sip.sip_events "
            f"WHERE {where} AND event_time > {since_expr} "
            f"GROUP BY ip, reason "
            f"ORDER BY count() DESC LIMIT {MAX_PER_SRC} BY ip FORMAT TabSeparated"
        )
        try:
            for row in ch_query(sql):
                ip = row[0]
                ua = row[1] if len(row) > 1 else ""
                reason = row[2] if len(row) > 2 else event_type.lower()
                if ip and external(ip):
                    emit(fh, event_type, ip, ua, reason)
                    n += 1
        except Exception as e:
            log_stderr(f"sip query failed ({event_type}): {e}")
    # Note on credential attacks: 401/403 response rows carry the server address
    # (0.0.0.0), not the attacker, and do not share call_id with the REGISTER in
    # this schema, so auth failures cannot be attributed to a source here. The
    # credential signal is instead the REGISTER volume and REGISTER+scanner-UA
    # rules (100108/100109), which key on the real request source above.
    # suricata malformed-header signals
    sig_in = ",".join(f"'{s}'" for s in SURICATA_MAP)
    sql = (
        f"SELECT toString(sig_id), replaceOne(toString(src_ip),'::ffff:','') ip "
        f"FROM ngn_sip.suricata_alerts "
        f"WHERE toString(sig_id) IN ({sig_in}) AND event_time > {since_expr} "
        f"GROUP BY sig_id, ip LIMIT {MAX_PER_SRC} BY ip FORMAT TabSeparated"
    )
    try:
        for row in ch_query(sql):
            sig, ip = row[0], row[1]
            if ip and external(ip) and sig in SURICATA_MAP:
                et, reason = SURICATA_MAP[sig]
                emit(fh, et, ip, "", reason)
                n += 1
    except Exception as e:
        log_stderr(f"suricata query failed: {e}")
    return n


def main():
    os.makedirs(os.path.dirname(ADAPTER_LOG), exist_ok=True)
    log_stderr(f"started CH={CH_URL} out={ADAPTER_LOG} poll={POLL_SECONDS}s "
               f"lookback={LOOKBACK_SECONDS}s cap={MAX_PER_SRC} external_only={EXTERNAL_ONLY}")
    while True:
        wm = read_watermark()
        since_expr = f"'{wm}'" if wm else f"now() - INTERVAL {LOOKBACK_SECONDS} SECOND"
        try:
            with open(ADAPTER_LOG, "a") as fh:
                emitted = poll(fh, since_expr)
            # advance watermark to the latest event we could have seen
            mx = ch_query("SELECT toString(max(event_time)) FROM ngn_sip.sip_events FORMAT TabSeparated")
            if mx and mx[0] and mx[0][0]:
                write_watermark(mx[0][0])
            if emitted:
                log_stderr(f"emitted {emitted} NGN-SEC lines")
        except Exception as e:
            log_stderr(f"poll error: {e}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
