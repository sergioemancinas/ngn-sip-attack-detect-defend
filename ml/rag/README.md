# RAG Corpus Ingestion

This scaffold ingests SIP security reference material into the existing
PostgreSQL/pgvector table `rag.document_chunks`.

## Corpus sources

Place local, approved source files under `ml/rag/corpus/`:

- MITRE ATT&CK notes or STIX exports relevant to SIP abuse paths.
- SIP RFC extracts for RFC 3261, 4566, 3550, 3711, 8224, and 8225.
- NVD VoIP CVE JSON exports.

The ingester reads `.md`, `.txt`, and `.json`, chunks the text, embeds each
chunk, and inserts it into pgvector.

## Default embedding path

Corpus and query must use the **same** embedding model, so ingestion defaults to
the model the Stage-2 worker queries with — Ollama `nomic-embed-text` (768-dim).
The ingester migrates `rag.document_chunks` to that dimension automatically (the
initial `vector(384)` schema is recreated on first ingest; the corpus is fully
regenerable).

```bash
export OLLAMA_HOST=http://127.0.0.1:11434
cd ml/rag
python3 -m venv .venv
. .venv/bin/activate
pip install "psycopg[binary]"

python ingest.py \
  --database-url postgresql://ngn:change-me-local-only@localhost:5432/ngn_sip \
  --corpus-dir corpus
```

Do **not** embed with a chat model (e.g. `qwen2.5`): it has no fixed retrieval
dimension, so pgvector comparisons would be invalid (the consistency test
enforces this). `BAAI/bge-small-en-v1.5` (384-dim) is available for offline,
standalone experiments only — it does not match the deployed Ollama worker.

## NVD VoIP CVEs

Use local NVD exports in `corpus/` for reproducible runs. For ad hoc
refreshes, `--fetch-nvd` pulls a VoIP keyword query from NVD in-memory. Set
`NVD_API_KEY` if available.
