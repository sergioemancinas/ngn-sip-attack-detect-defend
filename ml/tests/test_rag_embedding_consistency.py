"""RAG corpus and query must share one embedding model and dimension.

Regression guard for the embedding-space mismatch (OWASP LLM08): the corpus was
embedded with a 384-dim sentence-transformers model while queries were embedded
with a chat model (qwen2.5), so pgvector comparisons were invalid. Ingest and the
Stage 2 worker must agree on both the model name and the vector dimension.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(module_name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(module_name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_ingest_and_query_embedding_model_match() -> None:
    ingest = _load("rag_ingest", "ml/rag/ingest.py")
    worker = _load("stage2_worker", "ml/stage2/worker.py")
    assert ingest.DEFAULT_OLLAMA_EMBED_MODEL == worker.DEFAULT_EMBED_MODEL


def test_ingest_and_query_embedding_dimension_match() -> None:
    ingest = _load("rag_ingest", "ml/rag/ingest.py")
    worker = _load("stage2_worker", "ml/stage2/worker.py")
    assert ingest.DEFAULT_DIMENSION == worker.DEFAULT_EMBED_DIMENSION


def test_query_embedding_model_is_not_a_chat_model() -> None:
    worker = _load("stage2_worker", "ml/stage2/worker.py")
    # A chat model embeds at hidden size, not a fixed retrieval dimension.
    assert "qwen" not in worker.DEFAULT_EMBED_MODEL.lower()
