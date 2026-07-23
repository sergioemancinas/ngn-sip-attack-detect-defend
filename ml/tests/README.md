# ML Tests

Pytest suite for Stage 1 features, Stage 2 guardrails, C1 HEP features, evaluation harness, RAG embedding consistency, and MLflow tracking.

## Layout

| File | Covers |
|---|---|
| `test_stage1_features.py` | 22-feature `legacy_full` contract and window aggregation |
| `test_stage1_models.py` | XGBoost and Isolation Forest training smoke paths |
| `test_c1_features.py` | `request_only` (16) vs `response_enriched` (31) feature sets |
| `test_hep_bridge.py` | HEP bridge normalization and ndjson output |
| `test_eval_compare.py` | C3 three-arm comparison harness |
| `test_stage2_guardrails.py` | Prompt-injection guardrail and output gating |
| `test_prompt_injection_corpus.py` | 14-case adversarial injection corpus |
| `test_rag_embedding_consistency.py` | Unified `nomic-embed-text` ingest/query dimensions |
| `test_mlflow_track_eval.py` | MLflow run fingerprinting |

## Run

From repo root:

```bash
cd ml && python -m pytest tests/ -q
```

Or targeted:

```bash
python -m pytest ml/tests/test_c1_features.py ml/tests/test_hep_bridge.py -q
```

See `docs/C1_HEP_RESPONSE_FEATURES.md` for the C1 validation boundary and `docs/results/RESULTS_stage1_grouped.md` for evaluation protocol context.
