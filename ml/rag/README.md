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

The repo schema defines `embedding vector(384)`, so the default embedding model
is `BAAI/bge-small-en-v1.5`.

```bash
cd ml/rag
python3 -m venv .venv
. .venv/bin/activate
pip install psycopg[binary] sentence-transformers

python ingest.py \
  --database-url postgresql://ngn:change-me-local-only@localhost:5432/ngn_sip \
  --corpus-dir corpus
```

## Ollama embedding option

```bash
export OLLAMA_HOST=http://127.0.0.1:11434
python ingest.py --embedding-backend ollama --ollama-embed-model qwen2.5
```

Only use an Ollama embedding model that returns the configured vector dimension.
For the current table, keep `--dimension 384` unless the pgvector schema is
migrated.

## NVD VoIP CVEs

Use local NVD exports in `corpus/` for reproducible runs. For ad hoc
refreshes, `--fetch-nvd` pulls a VoIP keyword query from NVD in-memory. Set
`NVD_API_KEY` if available.
