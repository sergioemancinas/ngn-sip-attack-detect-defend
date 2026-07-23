"""Demo runner: triggers ONE fixed, bounded SIP demo burst on POST /run.

Security model: this is the only service with the Docker socket. It NEVER takes
any command/argument from the request body, it runs a hardcoded, bounded demo
(short SIP recon scan + a small extension probe against the lab edge). It is on
the internal sip_lab network only (not host-published); the Keycloak-gated
dashboard is the only intended caller. Single-run lock + cooldown prevent abuse.
"""
import json
import os
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

NET = os.environ.get("DEMO_NET", "ngn-sip_sip_lab")
IMAGE = os.environ.get("DEMO_IMAGE", "ngn-sip/attacker:v1")
TARGET = os.environ.get("DEMO_TARGET", "kamailio")
COOLDOWN = int(os.environ.get("DEMO_COOLDOWN", "45"))
PER_CMD_TIMEOUT = int(os.environ.get("DEMO_CMD_TIMEOUT", "40"))

_state_lock = threading.Lock()
_running = False
_last_run = 0.0
_last_result = "never run"

# Fixed, bounded demo: recon scan (OPTIONS) + extension probe (REGISTER/INVITE ->
# 401/404 responses). Hardcoded args; nothing from the request is interpolated.
DEMO_CMDS = [
    ["docker", "run", "--rm", "--network", NET, IMAGE,
     "scan", "-i", TARGET, "-r", "5060", "-p", "udp"],
    ["docker", "run", "--rm", "--network", NET, IMAGE,
     "exten", "-i", TARGET, "-r", "5060", "-p", "udp", "-e", "100-130"],
]


def _run_demo(run_id: str) -> None:
    global _running, _last_run, _last_result
    ok = 0
    for cmd in DEMO_CMDS:
        try:
            subprocess.run(cmd, timeout=PER_CMD_TIMEOUT, capture_output=True)
            ok += 1
        except Exception:
            pass
    with _state_lock:
        _running = False
        _last_run = time.time()
        _last_result = f"run {run_id} finished ({ok}/{len(DEMO_CMDS)} steps)"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):  # quiet
        pass

    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            with _state_lock:
                self._send(200, {"status": "ok", "running": _running, "last_result": _last_result})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        global _running
        if self.path != "/run":
            self._send(404, {"error": "not found"})
            return
        now = time.time()
        with _state_lock:
            if _running:
                self._send(429, {"status": "busy", "detail": "a demo run is already in progress"})
                return
            wait = COOLDOWN - (now - _last_run)
            if _last_run and wait > 0:
                self._send(429, {"status": "cooldown", "detail": f"wait {int(wait)}s before another run"})
                return
            _running = True
            run_id = uuid.uuid4().hex[:12]
        threading.Thread(target=_run_demo, args=(run_id,), daemon=True).start()
        self._send(202, {"run_id": run_id, "status": "started",
                         "detail": "bounded SIP recon scan + extension probe launched against the lab edge"})


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8088), Handler).serve_forever()
