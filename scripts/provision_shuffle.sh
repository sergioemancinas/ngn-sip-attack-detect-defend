#!/usr/bin/env bash
# Provision the Stage-3 SOAR workflow into the running Shuffle instance over its
# REST API — replaces every manual UI step:
#
#   1. Authenticate: Bearer ${SHUFFLE_DEFAULT_APIKEY} when it is a valid key
#      (Shuffle 2.2.0 REJECTS keys shorter than 36 chars), else fall back to a
#      session login with ${SHUFFLE_DEFAULT_USERNAME}/${SHUFFLE_DEFAULT_PASSWORD}.
#   2. Verify the org and the onprem runner environment exist.
#   3. Resolve the "Shuffle Tools" and "http" app ids BY NAME (app ids are
#      instance-local; the shipped workflow JSON is rewritten to match).
#   4. Create-or-update the workflow from
#      soar/shuffle/workflows/sip_response_orchestration.json (matched by name;
#      re-runs update in place). Workflow variables (ClickHouse creds, relay
#      token, thresholds) are overwritten from .env on every run.
#   5. Start the webhook trigger (POST /api/v1/hooks/new) and READ BACK the
#      generated webhook URL /api/v1/hooks/webhook_<trigger-id>. The trigger id
#      is minted per install (fresh UUID on first create, reused afterwards) —
#      never a hardcoded path.
#   6. Rewrite <hook_url> in siem/wazuh/integrations/wazuh_shuffle_integration.xml
#      to the captured URL, so siem/wazuh/integrations/install_integrations.sh
#      wires Wazuh to the real endpoint.
#   7. Best-effort: ensure ngn_sip.soar_cases exists in ClickHouse
#      (infra/clickhouse/init/10_soar_cases.sql) for pre-existing volumes.
#
# Optional: --sso additionally configures Shuffle OpenID Connect against the
# lab Keycloak realm via POST /api/v1/orgs/<id> with {"editing": "sso_config"}
# (this IS API-drivable in 2.2.0; only SSO_REDIRECT_URL is env-driven).
#
# Usage:
#   ./scripts/provision_shuffle.sh            # provision workflow + webhook + wazuh XML
#   ./scripts/provision_shuffle.sh --sso      # ... and configure Keycloak OIDC
#   DRY_RUN=1 ./scripts/provision_shuffle.sh  # read-only preview (also --dry-run)
#
# Env (defaults match .env / docker-compose conventions):
#   SHUFFLE_API_URL            default http://127.0.0.1:5001 (host-side API)
#   SHUFFLE_INTERNAL_URL       default http://shuffle-backend:5001 (what Wazuh uses)
#   SHUFFLE_DEFAULT_APIKEY / SHUFFLE_DEFAULT_USERNAME / SHUFFLE_DEFAULT_PASSWORD
#   KAMCMD_BLOCK_RELAY_URL / KAMCMD_BLOCK_RELAY_TOKEN
#   CLICKHOUSE_HTTP_URL (workflow-side, default http://clickhouse:8123)
#   CLICKHOUSE_HOST_HTTP_URL (host-side DDL, default http://127.0.0.1:8123)
#   CLICKHOUSE_USER / CLICKHOUSE_PASSWORD
#   SOAR_DEDUP_WINDOW_SECONDS / ATTACK_SCORE_BAN_THRESHOLD /
#   ATTACK_SCORE_LOW_THRESHOLD / ML_ATTACK_SCORE_HIGH / NOTIFY_WEBHOOK_URL
#   KEYCLOAK_REALM / KEYCLOAK_PUBLIC_URL / KEYCLOAK_INTERNAL_URL
#   SHUFFLE_OIDC_CLIENT_ID / SHUFFLE_OIDC_CLIENT_SECRET   (for --sso)
#
# Idempotency: safe to re-run; the workflow is updated in place, the running
# webhook is left running, the XML rewrite is a no-op when already current.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW_JSON="${ROOT_DIR}/soar/shuffle/workflows/sip_response_orchestration.json"
WAZUH_XML="${ROOT_DIR}/siem/wazuh/integrations/wazuh_shuffle_integration.xml"

if [ -f "${ROOT_DIR}/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "${ROOT_DIR}/.env"
  set +a
fi

DRY_RUN="${DRY_RUN:-0}"
DO_SSO=0
for arg in "$@"; do
  case "${arg}" in
    --dry-run) DRY_RUN=1 ;;
    --sso)     DO_SSO=1 ;;
    *) echo "Unknown flag: ${arg}" >&2; exit 2 ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required." >&2
  exit 1
fi
if [ ! -f "${WORKFLOW_JSON}" ]; then
  echo "Missing workflow JSON: ${WORKFLOW_JSON}" >&2
  exit 1
fi

# All API work happens in one python3 process (stdlib only). Bash passes
# configuration through the environment; secrets never hit argv.
export PROVISION_ROOT_DIR="${ROOT_DIR}"
export PROVISION_WORKFLOW_JSON="${WORKFLOW_JSON}"
export PROVISION_WAZUH_XML="${WAZUH_XML}"
export PROVISION_DRY_RUN="${DRY_RUN}"
export PROVISION_DO_SSO="${DO_SSO}"
export SHUFFLE_API_URL="${SHUFFLE_API_URL:-http://127.0.0.1:5001}"
export SHUFFLE_INTERNAL_URL="${SHUFFLE_INTERNAL_URL:-http://shuffle-backend:5001}"
export SHUFFLE_DEFAULT_APIKEY="${SHUFFLE_DEFAULT_APIKEY:-}"
export SHUFFLE_DEFAULT_USERNAME="${SHUFFLE_DEFAULT_USERNAME:-admin}"
export SHUFFLE_DEFAULT_PASSWORD="${SHUFFLE_DEFAULT_PASSWORD:-}"
export KAMCMD_BLOCK_RELAY_URL="${KAMCMD_BLOCK_RELAY_URL:-http://kamcmd-relay:8099/kamcmd-block}"
export KAMCMD_BLOCK_RELAY_TOKEN="${KAMCMD_BLOCK_RELAY_TOKEN:-change-me-local-only}"
export CLICKHOUSE_HTTP_URL="${CLICKHOUSE_HTTP_URL:-http://clickhouse:8123}"
export CLICKHOUSE_HOST_HTTP_URL="${CLICKHOUSE_HOST_HTTP_URL:-http://127.0.0.1:8123}"
export CLICKHOUSE_USER="${CLICKHOUSE_USER:-ngn}"
export CLICKHOUSE_PASSWORD="${CLICKHOUSE_PASSWORD:-}"
export SOAR_DEDUP_WINDOW_SECONDS="${SOAR_DEDUP_WINDOW_SECONDS:-300}"
export ATTACK_SCORE_BAN_THRESHOLD="${ATTACK_SCORE_BAN_THRESHOLD:-0.85}"
export ATTACK_SCORE_LOW_THRESHOLD="${ATTACK_SCORE_LOW_THRESHOLD:-0.55}"
export ML_ATTACK_SCORE_HIGH="${ML_ATTACK_SCORE_HIGH:-0.90}"
export NOTIFY_WEBHOOK_URL="${NOTIFY_WEBHOOK_URL:-disabled}"
export KEYCLOAK_REALM="${KEYCLOAK_REALM:-ngn-sip-lab}"
export KEYCLOAK_PUBLIC_URL="${KEYCLOAK_PUBLIC_URL:-http://localhost:8080}"
export KEYCLOAK_INTERNAL_URL="${KEYCLOAK_INTERNAL_URL:-http://keycloak:8080}"
export SHUFFLE_OIDC_CLIENT_ID="${SHUFFLE_OIDC_CLIENT_ID:-shuffle}"
export SHUFFLE_OIDC_CLIENT_SECRET="${SHUFFLE_OIDC_CLIENT_SECRET:-change-me-local-only}"
export SOAR_CASES_DDL_FILE="${ROOT_DIR}/infra/clickhouse/init/10_soar_cases.sql"

python3 - <<'PYEOF'
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import uuid

API = os.environ["SHUFFLE_API_URL"].rstrip("/")
INTERNAL = os.environ["SHUFFLE_INTERNAL_URL"].rstrip("/")
DRY = os.environ["PROVISION_DRY_RUN"] == "1"
DO_SSO = os.environ["PROVISION_DO_SSO"] == "1"
WF_FILE = os.environ["PROVISION_WORKFLOW_JSON"]
XML_FILE = os.environ["PROVISION_WAZUH_XML"]

def log(msg):
    print(f"==> {msg}")

def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------- auth
_auth_headers = {}

def request(method, path, body=None, base=None, raw=False):
    url = (base or API) + path
    headers = {"Content-Type": "application/json"}
    headers.update(_auth_headers)
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
    req = urllib.request.Request(url, method=method, headers=headers, data=data)
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = resp.read()
    return payload if raw else json.loads(payload)

def wait_for_shuffle(headers, deadline=150):
    """Poll the API until it authenticates. On a fresh instance Shuffle's admin
    user + default apikey registration lags container health by up to ~2 min;
    a one-shot probe 403s and the whole run dies. Retry until ready or timeout.
    Returns True if the given headers authenticate, False otherwise."""
    global _auth_headers
    saved, _auth_headers = _auth_headers, headers
    waited = 0
    while True:
        try:
            request("GET", "/api/v1/workflows")
            return True
        except urllib.error.HTTPError as exc:
            if exc.code not in (401, 403) or waited >= deadline:
                _auth_headers = saved
                return False
        except (urllib.error.URLError, OSError):
            if waited >= deadline:
                _auth_headers = saved
                return False
        if waited == 0:
            log("waiting for Shuffle first-boot auth registration...")
        time.sleep(5)
        waited += 5

apikey = os.environ["SHUFFLE_DEFAULT_APIKEY"]
if len(apikey) >= 36:
    if wait_for_shuffle({"Authorization": f"Bearer {apikey}"}):
        log("authenticated with SHUFFLE_DEFAULT_APIKEY (Bearer)")
    else:
        log("API key rejected after retries; falling back to session login")
        _auth_headers = {}
if not _auth_headers:
    if apikey and len(apikey) < 36:
        log("NOTE: SHUFFLE_DEFAULT_APIKEY is shorter than 36 chars - Shuffle "
            "2.2.0 rejects it for Bearer auth; using session login instead. "
            "Set a >=36 char key in .env before first boot to enable key auth.")
    password = os.environ["SHUFFLE_DEFAULT_PASSWORD"]
    if not password:
        die("no usable API key and SHUFFLE_DEFAULT_PASSWORD is empty")
    try:
        res = request("POST", "/api/v1/login", {
            "username": os.environ["SHUFFLE_DEFAULT_USERNAME"],
            "password": password,
        })
    except (urllib.error.URLError, OSError) as exc:
        die(f"cannot reach Shuffle API at {API}: {exc}")
    cookies = res.get("cookies") or []
    token = next((c["value"] for c in cookies if c.get("key") == "session_token"), "")
    if not res.get("success") or not token:
        die("Shuffle login failed; check SHUFFLE_DEFAULT_USERNAME/PASSWORD")
    _auth_headers = {"Cookie": f"session_token={token}"}
    log("authenticated with session login")

# ---------------------------------------------------------------- org + env
orgs = request("GET", "/api/v1/orgs")
if not isinstance(orgs, list) or not orgs:
    die("no Shuffle org found (unexpected on a bootstrapped instance)")
org_id = orgs[0]["id"]
log(f"org: {orgs[0].get('name', '?')} ({org_id})")

envs = request("GET", "/api/v1/getenvironments")
default_env = next((e for e in envs if e.get("default")), envs[0] if envs else None)
if default_env is None:
    die("no runner environment registered (is shuffle-orborus up?)")
env_name = default_env["Name"]
if not default_env.get("running_ip") and not default_env.get("checkin"):
    log(f"WARNING: environment '{env_name}' has never checked in; "
        "executions will queue until shuffle-orborus is healthy")
log(f"runner environment: {env_name}")

# ---------------------------------------------------------------- apps by name
apps = request("GET", "/api/v1/apps")
by_name = {}
for a in apps:
    by_name.setdefault(a.get("name", ""), a)
missing = [n for n in ("Shuffle Tools", "http") if n not in by_name]
if missing:
    die(f"required Shuffle apps missing: {missing} (backend app bootstrap incomplete?)")
app_map = {n: {"id": by_name[n]["id"], "app_version": by_name[n]["app_version"]}
           for n in ("Shuffle Tools", "http")}
for n, meta in app_map.items():
    log(f"app '{n}': id {meta['id']} v{meta['app_version']}")

# ---------------------------------------------------------------- workflow
tmpl = json.load(open(WF_FILE))
wf_name = tmpl["name"]
existing = next((w for w in request("GET", "/api/v1/workflows")
                 if w.get("name") == wf_name), None)
if existing:
    # The workflow list is eventually consistent (OpenSearch); confirm the hit
    # actually resolves before updating in place (a fresh delete can linger).
    try:
        existing = request("GET", f"/api/v1/workflows/{existing['id']}")
    except urllib.error.HTTPError:
        log(f"stale listing for '{wf_name}' (deleted workflow); recreating")
        existing = None

if existing:
    wf_id = existing["id"]
    log(f"workflow exists: {wf_id} (updating in place)")
elif DRY:
    wf_id = "<would-create>"
    log(f"DRY_RUN: would create workflow '{wf_name}'")
else:
    created = request("POST", "/api/v1/workflows", {"name": wf_name})
    wf_id = created["id"]
    existing = created
    log(f"created workflow: {wf_id}")

# Overlay the shipped graph onto the server copy so server-managed defaults
# (org ids, validation bookkeeping) survive.
server_copy = existing if existing else {}
wf = dict(server_copy)
for key in ("name", "description", "start", "workflow_variables",
            "actions", "triggers", "branches"):
    wf[key] = tmpl[key]

# Instance-local rewrites: app ids/versions + runner environment.
for action in wf["actions"]:
    meta = app_map.get(action["app_name"])
    if meta:
        action["app_id"] = meta["id"]
        action["app_version"] = meta["app_version"]
    action["environment"] = env_name
for trig in wf["triggers"]:
    trig["environment"] = env_name

# Workflow variables from .env (shipped file holds placeholders only).
var_sources = {
    "clickhouse_http_url": os.environ["CLICKHOUSE_HTTP_URL"],
    "clickhouse_user": os.environ["CLICKHOUSE_USER"],
    "clickhouse_password": os.environ["CLICKHOUSE_PASSWORD"],
    "kamcmd_relay_url": os.environ["KAMCMD_BLOCK_RELAY_URL"],
    "kamcmd_relay_token": os.environ["KAMCMD_BLOCK_RELAY_TOKEN"],
    "soar_dedup_window_seconds": os.environ["SOAR_DEDUP_WINDOW_SECONDS"],
    "attack_score_ban_threshold": os.environ["ATTACK_SCORE_BAN_THRESHOLD"],
    "attack_score_low_threshold": os.environ["ATTACK_SCORE_LOW_THRESHOLD"],
    "ml_attack_score_high": os.environ["ML_ATTACK_SCORE_HIGH"],
    "notify_webhook_url": os.environ["NOTIFY_WEBHOOK_URL"] or "disabled",
}
for var in wf["workflow_variables"]:
    if var["name"] in var_sources and var_sources[var["name"]]:
        var["value"] = var_sources[var["name"]]

# Webhook trigger id: reuse the existing one (keeps the URL stable across
# re-runs); mint a fresh UUID on first create so no two installs share a
# predictable unauthenticated endpoint.
old_trigger_id = wf["triggers"][0]["id"]
server_triggers = (server_copy.get("triggers") or []) if existing else []
server_hook = next((t for t in server_triggers
                    if t.get("trigger_type") == "WEBHOOK"), None)
if server_hook:
    trigger_id = server_hook["id"]
    trigger_status = server_hook.get("status", "uninitialized")
else:
    trigger_id = str(uuid.uuid4())
    trigger_status = "uninitialized"
trig = wf["triggers"][0]
trig["id"] = trigger_id
trig["status"] = trigger_status
for p in trig["parameters"]:
    if p["name"] == "url":
        p["value"] = f"{INTERNAL}/api/v1/hooks/webhook_{trigger_id}"
    elif p["name"] == "tmp":
        p["value"] = f"webhook_{trigger_id}"
for br in wf["branches"]:
    if br["source_id"] == old_trigger_id:
        br["source_id"] = trigger_id

if DRY:
    log(f"DRY_RUN: would PUT workflow '{wf_name}' "
        f"({len(wf['actions'])} actions, trigger {trigger_id})")
else:
    request("PUT", f"/api/v1/workflows/{wf_id}", wf)
    log(f"workflow saved ({len(wf['actions'])} actions, "
        f"{len(wf['branches'])} branches)")

# ---------------------------------------------------------------- webhook
if trigger_status != "running":
    if DRY:
        log(f"DRY_RUN: would start webhook {trigger_id} via /api/v1/hooks/new")
    else:
        request("POST", "/api/v1/hooks/new", {
            "name": trig.get("label", "wazuh_sip_alert"),
            "type": "webhook",
            "id": trigger_id,
            "workflow": wf_id,
            "start": wf["start"],
            "environment": env_name,
            "auth": "",
            "custom_response": "",
        })
        log("webhook started")
else:
    log("webhook already running")

# Read the generated webhook URL back from the saved workflow - the workflow
# object is the source of truth for the trigger id Shuffle serves.
if not DRY:
    saved = request("GET", f"/api/v1/workflows/{wf_id}")
    hook = next((t for t in saved["triggers"]
                 if t.get("trigger_type") == "WEBHOOK"), None)
    if hook is None:
        die("webhook trigger vanished after save")
    if hook.get("status") != "running":
        die(f"webhook not running (status: {hook.get('status')})")
    trigger_id = hook["id"]

hook_path = f"/api/v1/hooks/webhook_{trigger_id}"
internal_url = f"{INTERNAL}{hook_path}"
log(f"webhook URL (sip_lab / Wazuh):  {internal_url}")
log(f"webhook URL (host debugging):   {API}{hook_path}")

# ---------------------------------------------------------------- wazuh XML
xml = open(XML_FILE).read()
new_xml = re.sub(r"<hook_url>[^<]*</hook_url>",
                 f"<hook_url>{internal_url}</hook_url>", xml, count=1)
if new_xml == xml:
    log("wazuh integration XML already current")
elif DRY:
    log(f"DRY_RUN: would set <hook_url> in {XML_FILE}")
else:
    open(XML_FILE, "w").write(new_xml)
    log(f"updated <hook_url> in {XML_FILE}")
    log("next: ./siem/wazuh/integrations/install_integrations.sh "
        "(pushes ossec.conf + restarts wazuh-manager)")

# ---------------------------------------------------------------- soar_cases DDL
ddl_file = os.environ["SOAR_CASES_DDL_FILE"]
ch_url = os.environ["CLICKHOUSE_HOST_HTTP_URL"].rstrip("/")
if os.path.exists(ddl_file) and not DRY:
    try:
        req = urllib.request.Request(
            ch_url + "/?database=ngn_sip",
            data=open(ddl_file, "rb").read(),
            headers={"Content-Type": "text/plain",
                     "X-ClickHouse-User": os.environ["CLICKHOUSE_USER"],
                     "X-ClickHouse-Key": os.environ["CLICKHOUSE_PASSWORD"]},
            method="POST")
        urllib.request.urlopen(req, timeout=10).read()
        log("ngn_sip.soar_cases ensured (CREATE TABLE IF NOT EXISTS)")
    except (urllib.error.URLError, OSError) as exc:
        log(f"WARNING: could not ensure ngn_sip.soar_cases ({exc}); "
            "run infra/clickhouse/init/10_soar_cases.sql manually")

# ---------------------------------------------------------------- optional SSO
if DO_SSO:
    realm = os.environ["KEYCLOAK_REALM"]
    sso = {
        "client_id": os.environ["SHUFFLE_OIDC_CLIENT_ID"],
        "client_secret": os.environ["SHUFFLE_OIDC_CLIENT_SECRET"],
        "openid_authorization": (f"{os.environ['KEYCLOAK_PUBLIC_URL']}"
                                 f"/realms/{realm}/protocol/openid-connect/auth"),
        "openid_token": (f"{os.environ['KEYCLOAK_INTERNAL_URL']}"
                         f"/realms/{realm}/protocol/openid-connect/token"),
        "SSORequired": False,
        "auto_provision": False,
        "role_required": False,
        "skip_sso_for_admins": True,
    }
    if DRY:
        log(f"DRY_RUN: would set org sso_config for realm '{realm}' "
            f"(client {sso['client_id']})")
    else:
        # The undocumented but required contract: sso_config is only applied
        # when the body carries {"editing": "sso_config"} (HandleEditOrg in
        # shuffle-shared). A plain POST returns 200 and silently ignores it.
        request("POST", f"/api/v1/orgs/{org_id}", {
            "org_id": org_id,
            "editing": "sso_config",
            "sso_config": sso,
        })
        back = request("GET", f"/api/v1/orgs/{org_id}")
        got = back.get("sso_config", {})
        if got.get("client_id") != sso["client_id"]:
            die("sso_config did not persist; check backend logs")
        log(f"OIDC configured: client '{got['client_id']}', "
            f"auth {got['openid_authorization']}")
        log("login: open the frontend and use the SSO button; set "
            "SHUFFLE_SSO_REDIRECT_URL in .env to pin the redirect_uri "
            "(Keycloak client must allow <redirect>/api/v1/login_openid)")

log("provisioning complete" + (" (dry run - nothing changed)" if DRY else ""))
PYEOF
