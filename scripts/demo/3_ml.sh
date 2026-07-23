#!/usr/bin/env bash
# ML verdicts: live classification summary from ClickHouse on the lab VM.
# Configure the SSH target via the DEMO_SSH env var, e.g.:
#   export DEMO_SSH="ssh -i ~/.ssh/id_ed25519 user@your-lab-vm"
: "${DEMO_SSH:?Set DEMO_SSH to your lab VM SSH target, e.g. export DEMO_SSH=\"ssh user@host\"}"
$DEMO_SSH 'docker exec ngn-sip-clickhouse-1 clickhouse-client --user ngn --password "$(grep -RhoE "CLICKHOUSE_PASSWORD=[^ ]+" ~/sip-attack-detect-defend/.env* | head -1 | cut -d= -f2)" -q "SELECT predicted_class, count() AS windows, round(avg(proba),3) AS confidence FROM ngn_sip.ml_scores GROUP BY 1 ORDER BY 2 DESC FORMAT PrettyCompact"'
