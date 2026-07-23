#!/usr/bin/env bash
# live demo: one command -> Attack -> Detect (3 arms) -> Defend (auto-ban).
# Run on the VM:  bash scripts/live_demo.sh
set -u
NET=ngn-sip_sip_lab; IMG=ngn-sip/attacker:v1; KAM=ngn-sip-kamailio-1; CH=ngn-sip-clickhouse-1
B=$(( (RANDOM % 40) + 210 ))   # fresh /24 each run so banned IPs don't interfere
say(){ printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }

say "1) Clearing the edge ban-table for a clean run"
docker exec $KAM /usr/sbin/kamcmd htable.dump ban_table 2>/dev/null | grep -oE '172\.18\.[0-9.]+' \
  | while read -r ip; do docker exec $KAM /usr/sbin/kamcmd htable.delete ban_table "$ip" >/dev/null 2>&1; done
echo "   done."

say "2) Launching 3 attacks from distinct source IPs (172.18.$B.1/2/3)"
for o in 1 2 3; do docker rm -f atk_$o >/dev/null 2>&1
  docker run -d --name atk_$o --network $NET --ip 172.18.$B.$o --entrypoint sleep $IMG 90 >/dev/null; done
echo "   - recon scan          (-> Suricata + Wazuh scanner rule 100107, T1595.001)"
docker exec atk_1 sh -lc "timeout 6 sippts scan  -i kamailio -r 5060 -p udp" >/dev/null 2>&1
echo "   - REGISTER flood/IOC  (-> Wazuh 100109, level 12)"
docker exec atk_2 sh -lc "timeout 6 sippts flood -i kamailio -r 5060 -p udp -m register" >/dev/null 2>&1
echo "   - spoofed-UA flood    (-> rate-based PIKE rule 100103, T1499)"
docker exec atk_3 sh -lc "timeout 6 sippts flood -i kamailio -r 5060 -p udp -m invite -ua PolycomVVX" >/dev/null 2>&1

say "3) DETECT - waiting for the pipeline (Suricata/Wazuh -> Vector -> ClickHouse)"
sleep 22
docker exec $CH sh -lc 'clickhouse-client --user ngn --password "$CLICKHOUSE_PASSWORD" -q "
  SELECT rule_id, rule_level AS lvl, any(rule_description) AS detection, srcip
  FROM ngn_sip.wazuh_alerts WHERE srcip LIKE '\''172.18.'"$B"'.%'\'' AND alert_time > now() - INTERVAL 3 MINUTE
  GROUP BY rule_id, rule_level, srcip ORDER BY rule_id FORMAT PrettyCompact"'

say "4) DEFEND - the auto-ban responder banned the attackers"
docker logs --since 60s kamailio-autoban 2>&1 | grep "172.18.$B" | sed 's/^/   /'

say "5) PROOF - re-attack from a banned IP is dropped at the edge"
docker exec atk_1 sh -lc "timeout 4 sippts scan -i kamailio -r 5060 -p udp" >/dev/null 2>&1
sleep 1
docker logs --since 6s $KAM 2>&1 | grep "172.18.$B.1" | grep -i Dropping | head -1 | sed 's/^/   /'
for o in 1 2 3; do docker rm -f atk_$o >/dev/null 2>&1; done
say "Demo complete. Show Grafana 'D7 Wazuh SIP Correlation' for the visual."
