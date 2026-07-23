from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# psycopg is imported lazily in main() so the module (and its constants/--help) can be
# imported without the DB driver installed, e.g. by the embedding-consistency test.

DEFAULT_DATABASE_URL = "postgresql://ngn:change-me-local-only@localhost:5432/ngn_sip"
# Corpus and query MUST share one embedding model. The deployed Stage 2 worker queries
# via Ollama HTTP, so the default ingest path uses the same Ollama embedding model
# (nomic-embed-text, 768-dim) rather than a sentence-transformers model the worker cannot
# load. Keep DEFAULT_OLLAMA_EMBED_MODEL == worker.DEFAULT_EMBED_MODEL and
# DEFAULT_DIMENSION == worker.DEFAULT_EMBED_DIMENSION. OWASP LLM08.
DEFAULT_EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
DEFAULT_OLLAMA_EMBED_MODEL = "nomic-embed-text"
DEFAULT_DIMENSION = 768


class Embedder(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]:
        ...


@dataclass(frozen=True)
class Chunk:
    source: str
    text: str


class SentenceTransformerEmbedder:
    def __init__(self, model_name: str) -> None:
        from sentence_transformers import SentenceTransformer

        self.model = SentenceTransformer(model_name)

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = self.model.encode(texts, normalize_embeddings=True)
        return [vector.tolist() for vector in vectors]


class OllamaEmbedder:
    def __init__(self, model_name: str, host: str) -> None:
        self.model_name = model_name
        self.host = host.rstrip("/")

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            payload = {"model": self.model_name, "prompt": text}
            request = Request(
                f"{self.host}/api/embeddings",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request, timeout=60) as response:
                body = json.loads(response.read().decode("utf-8"))
            vectors.append([float(value) for value in body["embedding"]])
        return vectors


def clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def chunk_text(text: str, max_chars: int, overlap_chars: int) -> list[str]:
    cleaned = clean_text(text)
    if not cleaned:
        return []
    if len(cleaned) <= max_chars:
        return [cleaned]

    chunks: list[str] = []
    start = 0
    while start < len(cleaned):
        end = min(start + max_chars, len(cleaned))
        chunks.append(cleaned[start:end])
        if end == len(cleaned):
            break
        start = max(0, end - overlap_chars)
    return chunks


def read_corpus_documents(corpus_dir: Path) -> Iterable[tuple[str, str]]:
    suffixes = {".md", ".txt", ".json"}
    for path in sorted(corpus_dir.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".json":
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                pass
            else:
                text = json.dumps(parsed, sort_keys=True)
        yield str(path.relative_to(corpus_dir)), text


def build_chunks(corpus_dir: Path, max_chars: int, overlap_chars: int) -> list[Chunk]:
    chunks: list[Chunk] = []
    for source, text in read_corpus_documents(corpus_dir):
        for index, chunk in enumerate(chunk_text(text, max_chars=max_chars, overlap_chars=overlap_chars)):
            chunks.append(Chunk(source=f"{source}#chunk-{index}", text=chunk))
    return chunks


def fetch_nvd_voip_cves(api_key: str | None, results_per_page: int) -> dict[str, object]:
    query = urlencode({"keywordSearch": "VoIP SIP RTP SRTP", "resultsPerPage": results_per_page})
    request = Request(f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}")
    if api_key:
        request.add_header("apiKey", api_key)
    try:
        with urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(f"NVD CVE fetch failed: {exc}") from exc


def existing_embedding_dimension(conn: psycopg.Connection) -> int | None:
    """Return the current rag.document_chunks embedding dimension, or None if absent.

    pgvector stores the declared dimension in the column type modifier (atttypmod).
    """
    row = conn.execute(
        """
        SELECT a.atttypmod
        FROM pg_attribute a
        JOIN pg_class c ON a.attrelid = c.oid
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE n.nspname = 'rag' AND c.relname = 'document_chunks' AND a.attname = 'embedding'
        """
    ).fetchone()
    if row is None or row[0] is None or row[0] < 0:
        return None
    return int(row[0])


def ensure_schema(conn: psycopg.Connection, dimension: int) -> None:
    if dimension <= 0:
        raise ValueError("dimension must be positive")
    conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
    conn.execute("CREATE SCHEMA IF NOT EXISTS rag")
    # Migrate on an embedding-model/dimension change: a table left at a different vector
    # dimension (e.g. an earlier bge-small 384 corpus) cannot accept the new vectors, and
    # silently keeping it is what produced the original query/corpus space mismatch. The
    # corpus is fully regenerable from build_chunks, so a dimension change recreates it.
    current = existing_embedding_dimension(conn)
    if current is not None and current != dimension:
        print(f"migrating rag.document_chunks: embedding dim {current} -> {dimension} (recreating)")
        conn.execute("DROP TABLE rag.document_chunks")
    conn.execute(
        f"""
        CREATE TABLE IF NOT EXISTS rag.document_chunks (
            id BIGSERIAL PRIMARY KEY,
            source TEXT NOT NULL,
            chunk_text TEXT NOT NULL,
            embedding vector({dimension}),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    conn.commit()


def vector_literal(vector: list[float]) -> str:
    return "[" + ",".join(f"{value:.8f}" for value in vector) + "]"


def insert_chunks(
    conn: psycopg.Connection,
    chunks: list[Chunk],
    vectors: list[list[float]],
    dimension: int,
) -> int:
    if len(chunks) != len(vectors):
        raise ValueError("chunk/vector length mismatch")

    rows = []
    for chunk, vector in zip(chunks, vectors, strict=True):
        if len(vector) != dimension:
            raise ValueError(
                f"embedding dimension mismatch for {chunk.source}: expected {dimension}, got {len(vector)}"
            )
        rows.append((chunk.source, chunk.text, vector_literal(vector)))

    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO rag.document_chunks (source, chunk_text, embedding)
            VALUES (%s, %s, %s::vector)
            """,
            rows,
        )
    conn.commit()
    return len(rows)


def build_embedder(args: argparse.Namespace) -> Embedder:
    if args.embedding_backend == "sentence-transformers":
        return SentenceTransformerEmbedder(args.embedding_model)
    if args.embedding_backend == "ollama":
        return OllamaEmbedder(args.ollama_embed_model, os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434"))
    raise ValueError(f"unsupported embedding backend: {args.embedding_backend}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest SIP security RAG corpus into pgvector.")
    parser.add_argument("--corpus-dir", type=Path, default=Path(__file__).resolve().parent / "corpus")
    parser.add_argument("--database-url", default=os.getenv("POSTGRES_DSN", DEFAULT_DATABASE_URL))
    parser.add_argument("--embedding-backend", choices=["sentence-transformers", "ollama"], default="ollama")
    parser.add_argument("--embedding-model", default=DEFAULT_EMBEDDING_MODEL)
    parser.add_argument("--ollama-embed-model", default=os.getenv("OLLAMA_EMBED_MODEL", DEFAULT_OLLAMA_EMBED_MODEL))
    parser.add_argument("--dimension", type=int, default=DEFAULT_DIMENSION)
    parser.add_argument("--max-chars", type=int, default=1800)
    parser.add_argument("--overlap-chars", type=int, default=200)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--fetch-nvd", action="store_true", help="Fetch VoIP CVE JSON from NVD and ingest it in-memory.")
    parser.add_argument("--nvd-results-per-page", type=int, default=200)
    return parser.parse_args()


def main() -> None:
    import psycopg  # noqa: F401  (lazy: only needed for the actual ingest)

    args = parse_args()
    chunks = build_chunks(
        corpus_dir=args.corpus_dir,
        max_chars=args.max_chars,
        overlap_chars=args.overlap_chars,
    )
    if args.fetch_nvd:
        nvd_json = fetch_nvd_voip_cves(
            api_key=os.getenv("NVD_API_KEY"),
            results_per_page=args.nvd_results_per_page,
        )
        for index, chunk in enumerate(
            chunk_text(json.dumps(nvd_json, sort_keys=True), max_chars=args.max_chars, overlap_chars=args.overlap_chars)
        ):
            chunks.append(Chunk(source=f"nvd_voip_cves.json#chunk-{index}", text=chunk))

    if not chunks:
        raise SystemExit(f"No corpus chunks found under {args.corpus_dir}")

    embedder = build_embedder(args)
    inserted = 0
    with psycopg.connect(args.database_url) as conn:
        ensure_schema(conn, dimension=args.dimension)
        for start in range(0, len(chunks), args.batch_size):
            batch = chunks[start : start + args.batch_size]
            vectors = embedder.embed([chunk.text for chunk in batch])
            inserted += insert_chunks(conn, batch, vectors, dimension=args.dimension)

    print(f"inserted_chunks={inserted}")


if __name__ == "__main__":
    main()
