# Stage 2: LLM Triage (Ollama)

Stage 2 consumes Wazuh alerts, sends validated alert context to the local Ollama
model, validates the JSON response, and writes the verdict to
`ngn_sip.llm_verdicts`.

## Guardrails

- **Input filter:** requires a positive Wazuh `rule.id` and valid `srcip`.
- **Output validator:** accepts only JSON matching `VERDICT_SCHEMA` in
  `worker.py`.
- **Refusal handler:** converts refusals, invalid JSON, and Ollama failures into
  `needs_review` verdicts.

The existing audit schema has three guardrail columns. This worker maps them as:

- `guardrail_json_pass`: output JSON schema passed.
- `guardrail_ner_pass`: input alert structure passed.
- `guardrail_self_consist`: no refusal or execution failure was observed.

## Poll Wazuh alerts.json

```bash
cd ml/stage2
python3 -m venv .venv
. .venv/bin/activate
pip install -e .

export OLLAMA_HOST=http://127.0.0.1:11434
export OLLAMA_MODEL=qwen2.5:7b-instruct-q4_K_M
export CLICKHOUSE_HOST=localhost
export CLICKHOUSE_USER=ngn
export CLICKHOUSE_PASSWORD=change-me-local-only

python worker.py poll --alerts-file /var/ossec/logs/alerts/alerts.json
```

Use `--once` for a single polling pass.

## Webhook mode

```bash
python worker.py webhook --host 127.0.0.1 --port 8088
```

POST raw Wazuh alert JSON to the listener. The response is the same verdict row
shape written to ClickHouse.
