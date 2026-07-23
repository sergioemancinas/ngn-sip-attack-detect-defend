# LLM Triage Design (Stage 2)

Reflects the as-built worker in `ml/stage2/worker.py` (corrected to match the
implementation: no LangGraph, no rule-based fallback, 4-verdict enum, plain HTTP to Ollama).

## Goal

Take a Wazuh alert (level >= 10) plus ClickHouse context and produce a structured triage verdict written to `ngn_sip.llm_verdicts`. Stage 2 explains and prioritises; it does not block. Blocking stays with `kamailio-autoban`.

## Runtime

- Model: `qwen2.5:7b-instruct-q4_K_M` served by local Ollama (`docker-compose.ml.yml`), called over plain HTTP (`/api/chat`, `temperature 0`, `format=json`). No LangGraph.
- Host: campus VM is CPU-only (no GPU). Measured ~75 s per triage call at 8 CPUs (see the Stage 2 benchmark); production latency needs a GPU or a smaller model.
- No model-output fallback to rules: on refusal, invalid JSON, schema failure, error, or a prompt-injection flag, the worker emits a `needs_review` verdict at confidence 0 (advisory, routes to a human). It never invents a benign/malicious verdict.
- RAG: optional pgvector context retrieved with `nomic-embed-text` (768-dim, must match the ingest model); retrieval failure degrades to no-context, never blocks triage.

## Graph (small, single pass)

1. Load alert. Parse the Wazuh alert JSON (rule id, level, srcip, MITRE, decoded fields).
2. Pull context. Query ClickHouse for recent `sip_events`, `suricata_alerts`, `attack_labels`, and `ml_scores` for the same source.
3. Prompt the model. Constrained instruction asking for a single JSON object only.
4. Validate. Schema/guardrail check on the returned JSON (4-verdict enum, bounded confidence, required fields). On failure, route to `needs_review`.
5. Write. Insert one row into `ngn_sip.llm_verdicts` (verdict, confidence, reasoning, rag_context_ids, the three guardrail pass flags, model, latency_ms).

## Output schema (llm_verdicts)

| Column | Type | Notes |
|---|---|---|
| verdict | enum | one of: benign, suspicious, malicious, needs_review |
| confidence | float | 0.0 to 1.0 |
| reasoning | string | short justification, model-generated |
| rag_context_ids | array | corpus chunk ids used as context |
| guardrail_json_pass / guardrail_ner_pass / guardrail_self_consist | int | per-guardrail pass flags (input/json/refusal) |
| model | string | model id |
| latency_ms | int | wall-clock for the triage call |

## Guardrails

- Untrusted alert text is wrapped in an `untrusted_alert_data` envelope (segregation) and sanitized (control chars stripped, truncated).
- Output must be a single valid JSON object matching the schema, else `needs_review`.
- Confidence clamped to [0,1]; verdict constrained to the 4-value enum.
- Advisory-only: Stage 2 cannot override Stage 1 and cannot trigger blocking.
- **Load-bearing prompt-injection guardrail (OWASP LLM01):** if the alert text matches an injection pattern, the model verdict is discarded, the alert is forced to `needs_review`, and it cannot count as an FP reduction. Measured residual bypass rate is reported (`ml/stage2/adversarial_prompts.json`, `test_prompt_injection_corpus.py`).

## Evaluation

`ml/stage2/benchmark.py` scores a labeled benchmark for verdict accuracy, FP-reduction
precision/recall, guardrail/refusal rates, latency, and self-consistency, against trivial
baselines. See `docs/results/` for the run output.
