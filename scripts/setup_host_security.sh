#!/usr/bin/env bash
# Host-level security hardening for the campus VM. Run on the VM with sudo:
#   ! sudo bash scripts/setup_host_security.sh            # apply
#   ! sudo AUDIT_ONLY=1 bash scripts/setup_host_security.sh   # read-only baseline
#
# Conservative + idempotent. The high-value, low-risk host controls that
# complement the container-level stack (Suricata/Wazuh/autoban). Larger tools
# (Falco, CrowdSec, OpenSCAP) are in clearly-marked OPTIONAL sections at the end.
# References: Lynis (cisofy.com/lynis), Ubuntu CIS hardening, fail2ban for SIP.
set -euo pipefail
AUDIT_ONLY="${AUDIT_ONLY:-0}"
log(){ printf '\n=== %s ===\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

log "1. Lynis security audit (read-only baseline -> hardening index)"
apt-get update -qq
apt-get install -y --no-install-recommends lynis >/dev/null
lynis audit system --quick --no-colors 2>/dev/null | tee /var/log/lynis-baseline-"$(date +%F)".log | grep -iE 'Hardening index|Warning|Suggestion' | head -40 || true
echo "Full report: /var/log/lynis.log ; baseline saved under /var/log/lynis-baseline-*.log"

if [ "$AUDIT_ONLY" = 1 ]; then echo "AUDIT_ONLY set; stopping before changes."; exit 0; fi

log "2. Apply security updates (no full dist-upgrade; conservative)"
DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
apt-get -y autoremove --purge
[ -f /var/run/reboot-required ] && echo "NOTE: reboot required (kernel/libs) - schedule it."

log "3. auditd (forensic audit trail)"
apt-get install -y --no-install-recommends auditd audispd-plugins >/dev/null
systemctl enable --now auditd

log "4. fail2ban SIP jail (host-firewall backstop to the Wazuh autoban)"
# Filter: Kamailio NGN-SEC security events + dropped/banned + Asterisk auth fails.
cat > /etc/fail2ban/filter.d/ngn-sip.conf <<'FILTER'
[Definition]
failregex = NGN-SEC \S+ src=<HOST>
            Dropping (malformed|banned) SIP (request|source) (from )?<HOST>
            SecurityEvent="(InvalidPassword|ChallengeResponseFailed|InvalidAccountID|FailedACL)".*RemoteAddress="IPV4/UDP/<HOST>/
ignoreregex =
FILTER
# Jail: reads the relayed Kamailio NGN-SEC log + Asterisk security log if present.
cat > /etc/fail2ban/jail.d/ngn-sip.conf <<'JAIL'
[ngn-sip]
enabled  = true
filter   = ngn-sip
backend  = auto
maxretry = 5
findtime = 120
bantime  = 3600
action   = iptables-allports[name=ngn-sip]
logpath  = /var/lib/docker/volumes/ngn-sip_wazuh_manager_logs/_data/ngnsec/kamailio-sec.log
JAIL
systemctl restart fail2ban
fail2ban-client status ngn-sip 2>/dev/null || echo "ngn-sip jail registered (logpath populates as attacks arrive)"

log "DONE (core). ufw stays default-deny; only 22 (+5060 at SIP cut-over) should be open."
cat <<'NEXT'

OPTIONAL phase-2 (larger installs, run intentionally):

# Falco - runtime container syscall detection (eBPF), exports to Prometheus/Grafana
#   curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
#   echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list
#   apt-get update && apt-get install -y falco   # choose modern eBPF probe in the prompt

# CrowdSec - crowd-sourced IP reputation banning (stronger than fail2ban for exposure)
#   curl -s https://install.crowdsec.net | sh && apt-get install -y crowdsec crowdsec-firewall-bouncer-iptables

# OpenSCAP - formal CIS/STIG compliance scan (academic-grade benchmark)
#   apt-get install -y libopenscap8 ssg-debderived
#   oscap xccdf eval --profile cis_level1_server --report /var/log/oscap-cis.html /usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml
NEXT
