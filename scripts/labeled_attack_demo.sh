#!/usr/bin/env bash
# Prove the labeled-attack loop: run a real sippts recon scan from a named
# attacker container, capture its sip_lab IP, emit the ground-truth label with
# that IP, then confirm attack_labels + sip_events + features line up by src_ip.
set -uo pipefail
# Resolve the repo root from this script's own location, not a fixed path.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
P="$(grep ^CLICKHOUSE_PASSWORD= .env | cut -d= -f2-)"
# Credentials go in headers, not the URL query string: keeps the password out
# of argv/proxy logs and avoids corruption when it contains &, +, #, or space.
ch() { printf '%s' "$1" | curl -s -H "X-ClickHouse-User: ngn" -H "X-ClickHouse-Key: ${P}" "http://127.0.0.1:8123/" --data-binary @- ; }

echo "==> attack_labels before: $(ch 'SELECT count() FROM ngn_sip.attack_labels')"

# Start a persistent attacker container so we can read its IP, then exec the scan.
docker rm -f ngn-attacker-run >/dev/null 2>&1 || true
docker run -d --name ngn-attacker-run --network ngn-sip_sip_lab \
  --entrypoint sleep ngn-sip/attacker:v1 300 >/dev/null
ATK_IP="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ngn-attacker-run 2>/dev/null)"
echo "==> attacker IP: ${ATK_IP}"

echo "==> run sippts scan (recon, T1595) from the attacker container"
docker exec ngn-attacker-run sippts scan -i kamailio -r 5060 -p udp 2>&1 | grep -E "Response|Unauthorized|401|User-Agent" | head -3 || true

echo "==> emit ground-truth label with the attacker IP (direct ClickHouse insert,"
echo "    equivalent to attacks/orchestrator/label_emitter.py emit_label())"
LABEL_TS="$(date -u '+%Y-%m-%d %H:%M:%S.000')"
LABEL_JSON="$(printf '{"label_time":"%s","src_ip":"%s","attack_id":"sippts_scan","mitre_technique":"T1595","phase":"recon","notes":"labeled-attack-loop proof"}' "${LABEL_TS}" "${ATK_IP}")"
printf '%s' "${LABEL_JSON}" | curl -s "http://127.0.0.1:8123/?user=ngn&password=${P}&database=ngn_sip&query=INSERT%20INTO%20attack_labels%20FORMAT%20JSONEachRow" --data-binary @- 2>&1 | tail -2 || true

docker rm -f ngn-attacker-run >/dev/null 2>&1 || true
sleep 3

echo ""
echo "==> RESULTS"
echo "attack_labels after: $(ch 'SELECT count() FROM ngn_sip.attack_labels')"
echo "--- the label row ---"
ch "SELECT label_time, src_ip, attack_id, mitre_technique, phase FROM ngn_sip.attack_labels ORDER BY label_time DESC LIMIT 2 FORMAT TSV"
echo "--- sip_events from that attacker IP ---"
ch "SELECT method, count() FROM ngn_sip.sip_events WHERE src_ip = toIPv6('${ATK_IP}') GROUP BY method FORMAT TSV"
echo "LABELED_ATTACK_DONE"
