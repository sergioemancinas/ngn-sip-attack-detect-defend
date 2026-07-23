#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
VM bootstrap is intentionally not executed in the local stack.
Required posture for the VM deployment:
- UFW default deny
- expose only SIP 5060/5061 and the configured RTP range
- SSH key-only on a non-standard port
- Fail2Ban enabled
- Docker daemon configured with --iptables=false
- dashboards bound to 127.0.0.1 and reached through SSH tunnels
EOF
