#!/usr/bin/env bash
# Asterisk PBX endpoints (behind the Kamailio security edge) on the lab VM.
# Configure the SSH target via the DEMO_SSH env var, e.g.:
#   export DEMO_SSH="ssh -i ~/.ssh/id_ed25519 user@your-lab-vm"
: "${DEMO_SSH:?Set DEMO_SSH to your lab VM SSH target, e.g. export DEMO_SSH=\"ssh user@host\"}"
$DEMO_SSH 'echo ">> Asterisk PBX endpoints (behind the Kamailio security edge):"; docker exec ngn-sip-asterisk-1 asterisk -rx "pjsip show endpoints"'
