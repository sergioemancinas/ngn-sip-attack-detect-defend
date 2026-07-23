#!/usr/bin/env bash
# Stack health: list the ngn-sip containers and their status on the lab VM.
# Configure the SSH target via the DEMO_SSH env var, e.g.:
#   export DEMO_SSH="ssh -i ~/.ssh/id_ed25519 user@your-lab-vm"
: "${DEMO_SSH:?Set DEMO_SSH to your lab VM SSH target, e.g. export DEMO_SSH=\"ssh user@host\"}"
$DEMO_SSH 'docker ps --format "table {{.Names}}\t{{.Status}}" | grep ngn-sip'
