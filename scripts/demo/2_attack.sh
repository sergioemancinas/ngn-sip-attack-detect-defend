#!/usr/bin/env bash
# Live attack -> detect -> defend, fresh random source IP each run.
# Configure the SSH target via the DEMO_SSH env var, e.g.:
#   export DEMO_SSH="ssh -i ~/.ssh/id_ed25519 user@your-lab-vm"
: "${DEMO_SSH:?Set DEMO_SSH to your lab VM SSH target, e.g. export DEMO_SSH=\"ssh user@host\"}"
$DEMO_SSH 'IP=172.18.200.$((RANDOM%70+150)); echo ">> ATTACK from $IP (SIP recon scan vs Kamailio edge)"; docker run --rm --network ngn-sip_sip_lab --ip $IP ngn-sip/attacker:v1 scan -i kamailio -r 5060 -p udp -th 10 2>&1 | tail -2; echo ">> waiting for autoban (polls every 5s)..."; sleep 9; echo ">> DETECT + DEFEND:"; docker logs --tail 20 kamailio-autoban | grep $IP || echo "(wait 5s and run again)"; echo ">> ban_table entry:"; docker exec ngn-sip-kamailio-1 kamcmd htable.dump ban_table | grep -A1 $IP'
