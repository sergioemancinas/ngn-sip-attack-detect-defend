#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

cleanup() {
  docker rm -f ngn-ua1000 ngn-ua1001 >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup

docker compose run -d --name ngn-ua1001 sip-tester >/dev/null
docker compose run -d --name ngn-ua1000 sip-tester >/dev/null

ua1001_ip="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ngn-ua1001)"
ua1000_ip="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ngn-ua1000)"
ua1001_user="$(awk -F';' 'NR==2 { print $1 }' infra/sipp/data/ua1001.csv)"
ua1001_pass="$(awk -F';' 'NR==2 { print $2 }' infra/sipp/data/ua1001.csv)"
ua1000_user="$(awk -F';' 'NR==2 { print $1 }' infra/sipp/data/ua1000.csv)"
ua1000_pass="$(awk -F';' 'NR==2 { print $2 }' infra/sipp/data/ua1000.csv)"

docker exec ngn-ua1001 /usr/local/bin/sipp kamailio:5060 \
  -sf /scenarios/register.xml \
  -inf /data/ua1001.csv \
  -au "${ua1001_user}" \
  -ap "${ua1001_pass}" \
  -m 1 \
  -i "${ua1001_ip}" \
  -p 5062 \
  -trace_err

docker exec ngn-ua1000 /usr/local/bin/sipp kamailio:5060 \
  -sf /scenarios/register.xml \
  -inf /data/ua1000.csv \
  -au "${ua1000_user}" \
  -ap "${ua1000_pass}" \
  -m 1 \
  -i "${ua1000_ip}" \
  -p 5061 \
  -trace_err

docker exec -d ngn-ua1001 /usr/local/bin/sipp \
  -sf /scenarios/uas_answer.xml \
  -i "${ua1001_ip}" \
  -p 5062 \
  -m 1 \
  -timeout 30 \
  -trace_err

sleep 2

docker exec ngn-ua1000 /usr/local/bin/sipp kamailio:5060 \
  -sf /scenarios/uac_call.xml \
  -inf /data/ua1000.csv \
  -au "${ua1000_user}" \
  -ap "${ua1000_pass}" \
  -m 1 \
  -i "${ua1000_ip}" \
  -p 5061 \
  -trace_err \
  -trace_stat

echo "smoke call completed."
