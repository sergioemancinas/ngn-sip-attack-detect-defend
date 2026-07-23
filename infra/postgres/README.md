# PostgreSQL

PostgreSQL 16 with the `pgvector` extension. Backs Kamailio subscriber lookups
and the Stage-2 LLM's RAG context store. Runs on the `sip_lab` network, wired by
the top-level Compose files.

## Init scripts

Applied in order on first start (`init/` is mounted into the entrypoint):

| File | Creates |
|---|---|
| `init/01_subscribers.sql` | `sip_subscribers` — extensions the SIPp UAs register/call as |
| `init/02_homer_schema.sql` | `homer` schema placeholder (the live HEP schema is seeded by the [homer](../homer/README.md) stack) |
| `init/03_pgvector.sql` | `vector` extension and `rag.document_chunks` (384-dim embeddings) for Stage-2 retrieval |

The RAG chunks are what the Stage-2 Ollama triage grounds its advisory verdicts
on; see [`ml/README.md`](../../ml/README.md).
