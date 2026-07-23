.PHONY: up down logs smoke smoke-clean e2e clean ps build check-local-exposure scan-containers scan-containers-fixable scan-containers-trivy scan-containers-external scan-containers-external-fixable scan-containers-external-trivy obs-up obs-down obs-logs obs-ps obs-smoke ids-up ids-down ids-logs ids-ps wazuh-up wazuh-down wazuh-logs wazuh-ps wazuh-integrate wazuh-integrate-dryrun wazuh-integrate-remove wazuh-sso-apply keycloak-up keycloak-down keycloak-logs keycloak-ps homer-up homer-down homer-logs homer-ps soar-up soar-down soar-logs soar-ps shuffle-provision shuffle-provision-dryrun shuffle-provision-sso ml-up ml-down ml-pull ml-export dashboard-up dashboard-down dashboard-logs dashboard-ps all-up all-down up-all down-all bootstrap docker-mem

COMPOSE ?= docker compose
SCAN_IMAGES ?= \
	ngn-sip/pgvector:0.8.0-pg16 \
	ngn-sip/asterisk:20.19.0 \
	ngn-sip/kamailio:5.8.8 \
	ngn-sip/rtpengine:10.5.3.5 \
	ngn-sip/sipp:3.7.3

# External upstream images — gated separately so we can pin policy per source.
SCAN_IMAGES_EXTERNAL ?= \
	clickhouse/clickhouse-server:24.3.18.7-alpine \
	timberio/vector:0.41.1-alpine \
	grafana/grafana:11.6.14 \
	prom/prometheus:v3.11.3 \
	postgres:15.10 \
	sipcapture/heplify-server@sha256:ab0cfcc929d0844a889ed1c16662e0a3fe120aaa974909970acd54da5a76e043 \
	sipcapture/webapp@sha256:e34fa9a3461e6cad693a2503fb569bff952f91a4fc49e8fc0f0d5cf4c10e850b \
	jasonish/suricata:7.0.10 \
	wazuh/wazuh-manager:4.14.5 \
	wazuh/wazuh-indexer:4.14.5 \
	wazuh/wazuh-dashboard:4.14.5 \
	ollama/ollama:0.22.0 \
	ghcr.io/shuffle/shuffle-frontend:v2.2.0 \
	ghcr.io/shuffle/shuffle-backend:v2.2.0 \
	ghcr.io/shuffle/shuffle-orborus:v2.2.0 \
	opensearchproject/opensearch:2.19.5

build:
	$(COMPOSE) build --pull

up:
	$(COMPOSE) build --pull postgres asterisk kamailio rtpengine
	$(COMPOSE) up -d postgres asterisk kamailio rtpengine

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=200

ps:
	$(COMPOSE) ps

smoke:
	./scripts/smoke_sip_call.sh

smoke-clean:
	@docker rm -f ngn-ua1000 ngn-ua1001 >/dev/null 2>&1 || true

e2e:
	bash scripts/e2e_verify.sh

check-local-exposure:
	@set -eu; \
	ids="$$(docker compose ps -q)"; \
	if [ -z "$$ids" ]; then \
		echo "No running Compose containers."; \
		exit 0; \
	fi; \
	bindings="$$(for id in $$ids; do docker port "$$id" 2>/dev/null || true; done)"; \
	if [ -z "$$bindings" ]; then \
		echo "No host ports published."; \
		exit 0; \
	fi; \
	printf '%s\n' "$$bindings"; \
	if printf '%s\n' "$$bindings" | grep -E ' -> (0\.0\.0\.0|\[::\]):' >/dev/null; then \
		echo "Unsafe host binding detected. Development services must bind to 127.0.0.1 only." >&2; \
		exit 1; \
	fi; \
	echo "Host port bindings are loopback-scoped."

scan-containers:
	@set -eu; \
	for image in $(SCAN_IMAGES); do \
		echo "==> Docker Scout critical/high scan: $$image"; \
		docker scout cves --exit-code --only-severity critical,high "local://$$image"; \
	done

scan-containers-fixable:
	@set -eu; \
	for image in $(SCAN_IMAGES); do \
		echo "==> Docker Scout fixable critical/high scan: $$image"; \
		docker scout cves --exit-code --only-severity critical,high --only-fixed "local://$$image"; \
	done

scan-containers-trivy:
	@set -eu; \
	command -v trivy >/dev/null 2>&1 || { echo "trivy is required. Install: https://trivy.dev/latest/getting-started/installation/" >&2; exit 1; }; \
	for image in $(SCAN_IMAGES); do \
		echo "==> Trivy fixable critical/high scan: $$image"; \
		trivy image --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 --no-progress "$$image"; \
	done

scan-containers-external:
	@set -eu; \
	for image in $(SCAN_IMAGES_EXTERNAL); do \
		echo "==> Docker Scout critical/high scan: $$image"; \
		docker scout cves --exit-code --only-severity critical,high "$$image" || true; \
	done

scan-containers-external-fixable:
	@set -eu; \
	for image in $(SCAN_IMAGES_EXTERNAL); do \
		echo "==> Docker Scout fixable critical/high scan: $$image"; \
		docker scout cves --exit-code --only-severity critical,high --only-fixed "$$image" || true; \
	done

scan-containers-external-trivy:
	@set -eu; \
	command -v trivy >/dev/null 2>&1 || { echo "trivy is required. Install: https://trivy.dev/latest/getting-started/installation/" >&2; exit 1; }; \
	for image in $(SCAN_IMAGES_EXTERNAL); do \
		echo "==> Trivy fixable critical/high scan: $$image"; \
		trivy image --severity CRITICAL,HIGH --ignore-unfixed --exit-code 0 --no-progress "$$image" || true; \
	done

# --- Optional stacks (loopback-only, all bind to DEV_BIND_IP=127.0.0.1) ---

OBS_COMPOSE := $(COMPOSE) -f docker-compose.observability.yml
IDS_COMPOSE := $(COMPOSE) -f docker-compose.ids.yml
WAZUH_COMPOSE := $(COMPOSE) -f docker-compose.wazuh.yml
KEYCLOAK_COMPOSE := $(COMPOSE) -f docker-compose.keycloak.yml
HOMER_COMPOSE := $(COMPOSE) -f docker-compose.homer.yml
SOAR_COMPOSE := $(COMPOSE) -f docker-compose.soar.yml
ML_COMPOSE := $(COMPOSE) -f docker-compose.ml.yml
DASH_COMPOSE := $(COMPOSE) -f docker-compose.dashboard.yml

# TheHive/Cortex were removed: TheHive is no longer open source (StrangeBee proprietary).
# docker-compose.thehive.yml, soar/thehive, and soar/cortex were deleted on chore/remove-thehive; no make targets.

docker-mem:
	@docker system info --format '{{.MemTotal}}' 2>/dev/null \
		| awk '{printf "Docker Desktop memory: %.2f GiB\n", $$1/1073741824}'

obs-up:
	$(OBS_COMPOSE) up -d
	@echo "ClickHouse: http://127.0.0.1:8123  | Grafana: http://127.0.0.1:3000  | Prometheus: http://127.0.0.1:9090"

obs-down:
	$(OBS_COMPOSE) down

obs-logs:
	$(OBS_COMPOSE) logs -f --tail=200

obs-ps:
	$(OBS_COMPOSE) ps

obs-smoke:
	@set -a; [ -f ./.env ] && . ./.env; set +a; \
	echo "==> ClickHouse ping"; curl -sf http://127.0.0.1:8123/ping; \
	echo "==> ngn_sip tables"; \
	curl -sf -H "X-ClickHouse-User: $${CLICKHOUSE_USER:-ngn}" -H "X-ClickHouse-Key: $${CLICKHOUSE_PASSWORD:-change-me-local-only}" "http://127.0.0.1:8123/" \
		--data-urlencode "query=SHOW TABLES FROM ngn_sip"; \
	echo "==> Grafana health"; curl -sf http://127.0.0.1:3000/api/health; \
	echo "==> Prometheus health"; curl -sf http://127.0.0.1:9090/-/healthy; \
	echo "==> Vector metrics (buffer/drop counters)"; curl -sf http://127.0.0.1:9598/metrics | grep -c '^vector_buffer_'

ids-up:
	$(IDS_COMPOSE) up -d
	@echo "Suricata EVE JSON: Docker volume ngn-sip-ids_suricata_logs:/var/log/suricata/eve.json"

ids-down:
	$(IDS_COMPOSE) down

ids-logs:
	$(IDS_COMPOSE) logs -f --tail=200

ids-ps:
	$(IDS_COMPOSE) ps

wazuh-up:
	@$(MAKE) docker-mem
	@echo "Wazuh stack needs >=12 GiB Docker memory; if the indexer OOMs, raise allocation in Docker Desktop > Settings > Resources."
	$(WAZUH_COMPOSE) up -d
	@echo "Wazuh dashboard: http://127.0.0.1:5601"

wazuh-down:
	$(WAZUH_COMPOSE) down

wazuh-logs:
	$(WAZUH_COMPOSE) logs -f --tail=200

wazuh-ps:
	$(WAZUH_COMPOSE) ps

wazuh-integrate:
	./siem/wazuh/integrations/install_integrations.sh

wazuh-integrate-dryrun:
	./siem/wazuh/integrations/install_integrations.sh --dry-run

wazuh-integrate-remove:
	./siem/wazuh/integrations/install_integrations.sh --remove

# Push the OIDC security config into the running Wazuh indexer so it validates
# Keycloak-issued JWTs. Idempotent; run once after the Wazuh stack is healthy.
wazuh-sso-apply:
	./scripts/apply_wazuh_sso.sh

keycloak-up:
	$(KEYCLOAK_COMPOSE) up -d
	@echo "Keycloak admin console: http://127.0.0.1:8080/admin"

keycloak-down:
	$(KEYCLOAK_COMPOSE) down

keycloak-logs:
	$(KEYCLOAK_COMPOSE) logs -f --tail=200

keycloak-ps:
	$(KEYCLOAK_COMPOSE) ps

homer-up:
	@$(MAKE) docker-mem
	@echo "Homer adds ~3 GiB when running with the other lab stacks; stop Wazuh/SOAR first if Docker Desktop memory is tight."
	$(HOMER_COMPOSE) up -d
	@echo "Homer UI: http://127.0.0.1:9080  | HEP UDP: 127.0.0.1:9060"

homer-down:
	$(HOMER_COMPOSE) down

homer-logs:
	$(HOMER_COMPOSE) logs -f --tail=200

homer-ps:
	$(HOMER_COMPOSE) ps

soar-up:
	@$(MAKE) docker-mem
	@echo "SOAR stack adds ~2.5 GiB on top of Wazuh; raise Docker Desktop memory if it OOMs."
	$(SOAR_COMPOSE) up -d
	@echo "Shuffle UI: http://127.0.0.1:3001  | webhook base: http://127.0.0.1:5001/api/v1/hooks/"

soar-down:
	$(SOAR_COMPOSE) down

soar-logs:
	$(SOAR_COMPOSE) logs -f --tail=200

soar-ps:
	$(SOAR_COMPOSE) ps

shuffle-provision:
	./scripts/provision_shuffle.sh
	@echo "Then: 'make wazuh-integrate' to push the rewritten hook_url into wazuh-manager."

shuffle-provision-dryrun:
	DRY_RUN=1 ./scripts/provision_shuffle.sh --sso

shuffle-provision-sso:
	./scripts/provision_shuffle.sh --sso

ml-up:
	$(ML_COMPOSE) up -d
	@echo "Ollama: http://127.0.0.1:11434  | run 'make ml-pull' to fetch the default model"

ml-down:
	$(ML_COMPOSE) down

ml-pull:
	docker exec $${COMPOSE_PROJECT_NAME:-ngn-sip}-ollama-1 ollama pull $${OLLAMA_MODEL:-qwen2.5:7b-instruct-q4_K_M}
	@echo "Pulling the RAG embedding model (Stage-2 context retrieval)..."
	docker exec $${COMPOSE_PROJECT_NAME:-ngn-sip}-ollama-1 ollama pull $${OLLAMA_EMBED_MODEL:-nomic-embed-text}

# Re-export retrained Stage-1 models into the portable *.joblib + classes.json
# the scorer loads. Run after ml/stage1/train.py; required or the scorer keeps
# serving the previous model. See ml/deploy/README.md.
ml-export:
	python3 ml/deploy/models/reexport.py

dashboard-up:
	$(DASH_COMPOSE) up -d --build
	@echo "Stack dashboard: http://127.0.0.1:3002 (Keycloak SSO when DASHBOARD_ALLOW_INSECURE=false)"

dashboard-down:
	$(DASH_COMPOSE) down

dashboard-logs:
	$(DASH_COMPOSE) logs -f --tail=100

dashboard-ps:
	$(DASH_COMPOSE) ps

all-up: up obs-up
	@echo "Core SIP + observability up. Run 'make wazuh-up' separately if RAM allocation allows."

# Full pipeline bring-up in dependency order. On first run this order is
# mandatory: the base stack (project ngn-sip) creates the shared sip_lab
# network and asterisk_logs volume, and ids/wazuh/homer create the
# suricata/wazuh-manager/hep-bridge log volumes - all of which the
# observability stack references as external and refuses to start without.
# Needs the full Docker memory allocation (see wazuh-up/homer-up warnings).
up-all: up ids-up keycloak-up wazuh-up homer-up obs-up
	@echo "All stacks up: base + IDS + Keycloak + Wazuh + Homer + observability."
	@echo "Then: 'make wazuh-sso-apply' (indexer OIDC), 'make ml-up && make ml-pull' (ML ring), 'make soar-up' (SOAR)."

# Idempotent post-up configuration (indexer OIDC, localfiles, SSO clients,
# Shuffle provisioning + Wazuh wiring). Run after up-all (+ ml-up/soar-up).
bootstrap:
	./scripts/bootstrap.sh

# Complete teardown of every stack, reverse dependency order. '-' prefixes keep
# going if a stack is already down. Covers the post-step stacks (dashboard,
# soar, ml) too, so nothing is left orphaned.
down-all:
	-$(DASH_COMPOSE) down
	-$(SOAR_COMPOSE) down
	-$(ML_COMPOSE) down
	-$(OBS_COMPOSE) down
	-$(HOMER_COMPOSE) down
	-$(WAZUH_COMPOSE) down
	-$(KEYCLOAK_COMPOSE) down
	-$(IDS_COMPOSE) down
	$(COMPOSE) down

# Backwards-compatible alias.
all-down: down-all

# Full reset: tear down every stack AND remove its named volumes (schema, state,
# certs, indices). The ollama_models cache is preserved by default so a reset
# does not re-pull the ~4.7 GB model; set CLEAN_MODELS=1 to wipe it too.
clean:
	-$(DASH_COMPOSE) down --volumes --remove-orphans
	-$(SOAR_COMPOSE) down --volumes --remove-orphans
	-$(ML_COMPOSE) down --remove-orphans
	-$(OBS_COMPOSE) down --volumes --remove-orphans
	-$(HOMER_COMPOSE) down --volumes --remove-orphans
	-$(WAZUH_COMPOSE) down --volumes --remove-orphans
	-$(KEYCLOAK_COMPOSE) down --volumes --remove-orphans
	-$(IDS_COMPOSE) down --volumes --remove-orphans
	$(COMPOSE) down --volumes --remove-orphans
	@[ "$${CLEAN_MODELS:-0}" = "1" ] && docker volume rm -f $${COMPOSE_PROJECT_NAME:-ngn-sip}_ollama_models 2>/dev/null || true
	@echo "Full reset complete (ollama_models preserved unless CLEAN_MODELS=1)."
