from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

STAGE_DIR = Path(__file__).resolve().parent
DEFAULT_ALERTS_FILE = Path("/var/ossec/logs/alerts/alerts.json")
DEFAULT_STATE_FILE = Path(os.getenv("STAGE2_STATE_FILE", "/tmp/ngn_sip_stage2_alerts.offset"))
DEFAULT_MODEL = "qwen2.5:7b-instruct-q4_K_M"
# RAG embedding model MUST match ml/rag/ingest.py (CANONICAL_EMBED_MODEL/DIMENSION).
# A chat model (qwen2.5) is not an embedding model: it yields a hidden-size vector
# (3584-dim) that cannot be compared against the 768-dim corpus, so retrieval failed.
# nomic-embed-text is a real 768-dim embedding model served by Ollama. OWASP LLM08.
DEFAULT_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
DEFAULT_EMBED_DIMENSION = int(os.getenv("RAG_EMBED_DIMENSION", "768"))
DEFAULT_POSTGRES_DSN = "postgresql://ngn:change-me-local-only@postgres:5432/ngn_sip"
HIGH_ATTACK_SCORE = float(os.getenv("STAGE2_HIGH_ATTACK_SCORE", "0.80"))

ALLOWED_VERDICTS = {"malicious", "suspicious", "benign", "needs_review"}
REFUSAL_PATTERNS = [
    re.compile(r"\bI\s+can(?:not|'t)\s+assist\b", re.IGNORECASE),
    re.compile(r"\bI\s+can(?:not|'t)\s+help\b", re.IGNORECASE),
    re.compile(r"\bnot\s+able\s+to\s+provide\b", re.IGNORECASE),
]
# Syntactic prompt-injection signatures (OWASP LLM01:2025). This is a detection layer,
# not a complete defense: it catches common English direct-instruction forms. Paraphrase,
# non-English, and encoded payloads can bypass it, which is why detection is paired with
# untrusted-content segregation (envelope), strict output-schema validation, and the
# load-bearing gate in triage() that forces needs_review on any match. The residual bypass
# rate is measured against ml/stage2/adversarial_prompts.json (see tests).
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|context)\b", re.IGNORECASE),
    re.compile(r"\bsystem\s+prompt\b", re.IGNORECASE),
    re.compile(r"\bdeveloper\s+message\b", re.IGNORECASE),
    re.compile(r"\bnew\s+instructions?\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"\bact\s+as\b", re.IGNORECASE),
    re.compile(r"\b(?:return|output|respond\s+with|classify\s+(?:this\s+)?as|mark\s+(?:this\s+)?as|label\s+(?:this\s+)?as)\s+(?:benign|safe|clean|not\s+malicious)\b", re.IGNORECASE),
    re.compile(r"\boverride\s+(?:the\s+)?(?:detection|verdict|classification)\b", re.IGNORECASE),
    re.compile(r"\bignore\s+the\s+(?:system|rules?|guardrails?)\b", re.IGNORECASE),
]


def detect_prompt_injection(text: str) -> bool:
    """True if any injection signature matches. Shared by the sanitizer and the corpus eval."""
    return any(pattern.search(text) for pattern in PROMPT_INJECTION_PATTERNS)
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True)
class NormalizedStage1Alert:
    alert_id: str
    src_ip: str
    detector: str
    predicted_label: str
    attack_score: float
    stage1_detection: bool
    window_start: str
    window_end: str
    source_rule_id: int
    ground_truth_label: str | None
    sanitized_payload: dict[str, Any]
    input_risk_flags: list[str]
    raw: dict[str, Any]


def build_clickhouse_client() -> Any:
    try:
        from clickhouse_driver import Client
    except ImportError as exc:
        raise RuntimeError("clickhouse-driver is required for verdict audit writes") from exc

    return Client(
        host=os.getenv("CLICKHOUSE_HOST", "clickhouse"),
        port=int(os.getenv("CLICKHOUSE_PORT", "9000")),
        user=os.getenv("CLICKHOUSE_USER", "ngn"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DATABASE", "ngn_sip"),
    )


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def alert_hash(alert: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(alert).encode("utf-8")).hexdigest()


def normalize_ip(value: Any) -> str:
    parsed = ipaddress.ip_address(str(value or "").strip())
    if getattr(parsed, "ipv4_mapped", None):
        return str(parsed.ipv4_mapped)
    return str(parsed)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return bool(value)
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def stage2_rule_ids() -> set[int]:
    """Wazuh rule ids the poll loop triages (ml_rules.xml: 100150 verdict, 100151 autoban)."""
    ids: set[int] = set()
    for part in os.getenv("STAGE2_RULE_IDS", "100150,100151").split(","):
        part = part.strip()
        if part:
            ids.add(int(part))
    return ids


def normalize_wazuh_ml_alert(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Map a Wazuh alerts.json envelope carrying a Stage 1 ML event (data.ml,
    written by ml/deploy/scorer.py and raised by rules 100150/100151) onto the
    flat alert shape validate_stage1_alert() expects. Returns None when the
    payload is not a Wazuh ML alert; values arrive as strings after Wazuh's
    JSON decoder, so downstream coercion (_as_float / int) handles them."""
    rule = payload.get("rule")
    data = payload.get("data")
    if not isinstance(rule, dict) or not isinstance(data, dict):
        return None
    ml = data.get("ml")
    if not isinstance(ml, dict):
        return None
    mapped: dict[str, Any] = {
        "src_ip": ml.get("srcip") or ml.get("src_ip"),
        "detector": "stage1_xgboost",
        "predicted_label": ml.get("predicted_class"),
        "attack_score": ml.get("proba"),
        "anomaly_score": ml.get("anomaly"),
        "model_version": ml.get("model_version"),
        "window_start": ml.get("window") or "",
        "window_end": "",
        "source_rule_id": rule.get("id"),
    }
    wazuh_alert_id = str(payload.get("id") or "").strip()
    if wazuh_alert_id:
        mapped["alert_id"] = f"wazuh:{wazuh_alert_id}"
    return mapped


def unwrap_payload(payload: dict[str, Any]) -> dict[str, Any]:
    for key in ("alert", "event", "stage1_alert"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            return unwrap_payload(nested)
    body = payload.get("body")
    if isinstance(body, str):
        try:
            nested_body = json.loads(body)
        except json.JSONDecodeError:
            return payload
        if isinstance(nested_body, dict):
            return unwrap_payload(nested_body)
    return payload


def sanitize_text(value: str, max_chars: int = 4000) -> str:
    cleaned = CONTROL_CHARS.sub(" ", value)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_chars]


def sanitize_value(value: Any, flags: set[str]) -> Any:
    if isinstance(value, str):
        sanitized = sanitize_text(value)
        if sanitized != value:
            flags.add("control_chars_or_truncation")
        if detect_prompt_injection(sanitized):
            flags.add("prompt_injection_pattern")
        return sanitized
    if isinstance(value, dict):
        return {sanitize_text(str(key), max_chars=120): sanitize_value(item, flags) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_value(item, flags) for item in value[:50]]
    return value


def sanitize_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    flags: set[str] = set()
    sanitized = sanitize_value(payload, flags)
    if not isinstance(sanitized, dict):
        sanitized = {"value": sanitized}
    return sanitized, sorted(flags)


def validate_stage1_alert(payload: dict[str, Any]) -> NormalizedStage1Alert:
    alert = unwrap_payload(payload)
    wazuh_mapped = normalize_wazuh_ml_alert(alert)
    if wazuh_mapped is not None:
        alert = wazuh_mapped
    sanitized_payload, input_risk_flags = sanitize_payload(alert)

    src_ip_value = alert.get("src_ip") or alert.get("srcip")
    try:
        src_ip = normalize_ip(src_ip_value)
    except ValueError as exc:
        raise ValueError("missing valid source IP") from exc

    predicted_label = sanitize_text(str(alert.get("predicted_label") or alert.get("prediction") or ""))
    if not predicted_label:
        raise ValueError("missing Stage 1 predicted_label")

    stage1_detection = _as_bool(alert.get("stage1_detection", predicted_label != "benign"))
    if not stage1_detection:
        raise ValueError("Stage 2 only accepts Stage 1 detections")

    source_rule_id = int(alert.get("source_rule_id") or alert.get("rule_id") or 0)
    alert_id = str(alert.get("alert_id") or f"stage1:{alert_hash(alert)[:16]}")
    return NormalizedStage1Alert(
        alert_id=alert_id,
        src_ip=src_ip,
        detector=sanitize_text(str(alert.get("detector") or "stage1")),
        predicted_label=predicted_label,
        attack_score=_as_float(alert.get("attack_score"), default=0.0),
        stage1_detection=stage1_detection,
        window_start=sanitize_text(str(alert.get("window_start") or "")),
        window_end=sanitize_text(str(alert.get("window_end") or "")),
        source_rule_id=max(0, source_rule_id),
        ground_truth_label=(
            sanitize_text(str(alert.get("ground_truth_label")))
            if alert.get("ground_truth_label") is not None
            else None
        ),
        sanitized_payload=sanitized_payload,
        input_risk_flags=input_risk_flags,
        raw=alert,
    )


def load_prompt(name: str) -> str:
    return (STAGE_DIR / "prompts" / name).read_text(encoding="utf-8")


def build_user_prompt(alert: NormalizedStage1Alert, rag_context: list[dict[str, str]]) -> str:
    template = load_prompt("triage.md")
    envelope = {
        "stage1_detection": {
            "detector": alert.detector,
            "predicted_label": alert.predicted_label,
            "attack_score": alert.attack_score,
            "src_ip": alert.src_ip,
            "window_start": alert.window_start,
            "window_end": alert.window_end,
            "advisory_only": True,
        },
        "input_risk_flags": alert.input_risk_flags,
        "untrusted_alert_data": alert.sanitized_payload,
    }
    return (
        template.replace("{{ALERT_JSON}}", json.dumps(envelope, indent=2, sort_keys=True, default=str))
        .replace("{{RAG_CONTEXT}}", json.dumps(rag_context, indent=2, sort_keys=True))
    )


def ollama_base_url() -> str:
    """Resolve and validate the Ollama base URL from operator config.

    OLLAMA_HOST is operator-set, not request data, but validate the scheme so a
    misconfiguration cannot turn the embedding/chat calls into an SSRF primitive
    (only http/https to the configured host; no file://, gopher://, etc.).
    """
    host = os.getenv("OLLAMA_HOST", "http://ollama:11434").rstrip("/")
    if not host.startswith(("http://", "https://")):
        raise RuntimeError(f"OLLAMA_HOST must be an http(s) URL, got: {host!r}")
    return host


def call_ollama(system_prompt: str, user_prompt: str, model: str, timeout_seconds: int) -> str:
    host = ollama_base_url()
    payload = {
        "model": model,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    request = Request(
        f"{host}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(f"Ollama request failed: {exc}") from exc

    message = body.get("message") if isinstance(body.get("message"), dict) else {}
    content = message.get("content") or body.get("response")
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("Ollama returned an empty response")
    return content.strip()


def call_ollama_embedding(text: str, model: str, timeout_seconds: int) -> list[float]:
    host = ollama_base_url()
    payload = {"model": model, "prompt": text}
    request = Request(
        f"{host}/api/embeddings",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(f"Ollama embedding request failed: {exc}") from exc
    embedding = body.get("embedding")
    if not isinstance(embedding, list) or not embedding:
        raise RuntimeError("Ollama returned an empty embedding")
    return [float(value) for value in embedding]


def vector_literal(vector: list[float]) -> str:
    return "[" + ",".join(f"{value:.8f}" for value in vector) + "]"


def retrieve_rag_context(
    alert: NormalizedStage1Alert,
    limit: int,
    timeout_seconds: int,
    database_url: str | None = None,
    embedding_model: str = DEFAULT_EMBED_MODEL,
) -> list[dict[str, str]]:
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError("psycopg is required for pgvector RAG retrieval") from exc

    query_text = " ".join(
        [
            alert.predicted_label,
            alert.src_ip,
            alert.detector,
            json.dumps(alert.sanitized_payload, sort_keys=True, default=str),
        ]
    )
    embedding = call_ollama_embedding(sanitize_text(query_text, max_chars=2000), embedding_model, timeout_seconds)
    # Fail loud on an embedding-space mismatch instead of issuing a pgvector query that
    # either errors or returns meaningless nearest-neighbours. Raising RuntimeError lets
    # _rag_context degrade to no-context (correct) rather than crashing triage. OWASP LLM08.
    if len(embedding) != DEFAULT_EMBED_DIMENSION:
        raise RuntimeError(
            f"RAG embedding dimension mismatch: query model '{embedding_model}' produced "
            f"{len(embedding)} dims but the corpus is {DEFAULT_EMBED_DIMENSION}-dim. "
            "Ingest and query must use the same embedding model."
        )
    dsn = database_url or os.getenv("POSTGRES_DSN", DEFAULT_POSTGRES_DSN)
    # Bound both the connect and the query: a slow/hung pgvector call must not
    # stall the triage worker indefinitely (the Ollama calls are already bounded
    # by timeout_seconds; RAG was the one unbounded network path).
    rag_conn_timeout = int(os.getenv("RAG_CONNECT_TIMEOUT_SECONDS", "5"))
    rag_stmt_timeout_ms = int(os.getenv("RAG_STATEMENT_TIMEOUT_MS", "5000"))
    with psycopg.connect(
        dsn,
        connect_timeout=rag_conn_timeout,
        options=f"-c statement_timeout={rag_stmt_timeout_ms}",
    ) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT source, chunk_text
                FROM rag.document_chunks
                WHERE embedding IS NOT NULL
                ORDER BY embedding <-> %s::vector
                LIMIT %s
                """,
                (vector_literal(embedding), int(limit)),
            )
            rows = cur.fetchall()
    return [{"id": str(source), "text": sanitize_text(str(text), max_chars=1200)} for source, text in rows]


def is_refusal(text: str) -> bool:
    return any(pattern.search(text) for pattern in REFUSAL_PATTERNS)


def extract_json_object(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise
        value = json.loads(match.group(0))
    if not isinstance(value, dict):
        raise ValueError("model output must be a JSON object")
    return value


def validate_verdict_payload(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = ["verdict", "confidence", "reasoning", "rag_context_ids"]
    for field in required:
        if field not in payload:
            errors.append(f"missing {field}")

    if payload.get("verdict") not in ALLOWED_VERDICTS:
        errors.append(f"verdict must be one of {sorted(ALLOWED_VERDICTS)}")

    confidence = payload.get("confidence")
    if not isinstance(confidence, int | float) or not 0.0 <= float(confidence) <= 1.0:
        errors.append("confidence must be a number between 0 and 1")

    reasoning = payload.get("reasoning")
    if not isinstance(reasoning, str) or not reasoning.strip():
        errors.append("reasoning must be a non-empty string")
    elif len(reasoning) > 1200:
        errors.append("reasoning must be 1200 characters or less")

    context_ids = payload.get("rag_context_ids")
    if not isinstance(context_ids, list) or any(not isinstance(item, str) for item in context_ids):
        errors.append("rag_context_ids must be an array of strings")
    return errors


def refusal_verdict(reason: str) -> dict[str, Any]:
    return {
        "verdict": "needs_review",
        "confidence": 0.0,
        "reasoning": reason,
        "rag_context_ids": [],
    }


def triage_metric_hook(
    alert: NormalizedStage1Alert,
    verdict: dict[str, Any],
    input_compromised: bool = False,
    output_gated: bool = False,
) -> dict[str, Any]:
    ground_truth = alert.ground_truth_label
    if ground_truth is None:
        return {"ground_truth_available": False}
    stage1_is_fp = alert.stage1_detection and ground_truth == "benign"
    triage_marks_benign = str(verdict.get("verdict")) == "benign"
    # A benign verdict produced from injection-flagged input must never count as a
    # legitimate FP reduction, or an attacker could manufacture the metric.
    # Output-gating blocks the same metric credit when a high-confidence Stage 1
    # detection was downgraded to benign (including undetected injection payloads).
    return {
        "ground_truth_available": True,
        "ground_truth_label": ground_truth,
        "stage1_is_false_positive": bool(stage1_is_fp),
        "triage_marks_benign": bool(triage_marks_benign),
        "input_compromised": bool(input_compromised),
        "output_gated": bool(output_gated),
        "advisory_fp_reduction_candidate": bool(
            stage1_is_fp and triage_marks_benign and not input_compromised and not output_gated
        ),
    }


def _src_ip_for_ch(src_ip: str) -> Any:
    # ngn_sip.llm_verdicts.src_ip is an IPv6 column (matches ml_scores / ban_audit, which
    # store the ::ffff: mapped form). normalize_ip() returns plain IPv4, which the
    # ClickHouse driver cannot serialize into an IPv6 column, so map it back here.
    try:
        ip = ipaddress.ip_address(src_ip)
    except ValueError:
        return src_ip
    if ip.version == 4:
        return ipaddress.IPv6Address("::ffff:" + str(ip))
    return ip


def insert_verdict(
    client: Any,
    alert: NormalizedStage1Alert,
    verdict: dict[str, Any],
    guardrail_json_pass: int,
    guardrail_input_pass: int,
    guardrail_refusal_pass: int,
    latency_ms: int,
    model: str,
) -> None:
    columns = [
        "alert_id",
        "alert_rule_id",
        "alert_hash",
        "src_ip",
        "verdict",
        "confidence",
        "reasoning",
        "rag_context_ids",
        "guardrail_json_pass",
        "guardrail_ner_pass",
        "guardrail_self_consist",
        "latency_ms",
        "model",
    ]
    row = (
        alert.alert_id,
        alert.source_rule_id,
        alert_hash(alert.raw),
        _src_ip_for_ch(alert.src_ip),
        str(verdict["verdict"]),
        float(verdict["confidence"]),
        str(verdict["reasoning"]),
        [str(item) for item in verdict.get("rag_context_ids", [])],
        int(guardrail_json_pass),
        int(guardrail_input_pass),
        int(guardrail_refusal_pass),
        int(latency_ms),
        model,
    )
    client.execute(f"INSERT INTO ngn_sip.llm_verdicts ({', '.join(columns)}) VALUES", [row])


class Stage2Worker:
    def __init__(
        self,
        model: str,
        timeout_seconds: int,
        client: Any | None = None,
        rag_retriever: Callable[[NormalizedStage1Alert], list[dict[str, str]]] | None = None,
        ollama_caller: Callable[[str, str, str, int], str] | None = None,
    ) -> None:
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.client = client if client is not None else build_clickhouse_client()
        self.system_prompt = load_prompt("system.md")
        self.rag_retriever = rag_retriever
        self.ollama_caller = ollama_caller or call_ollama

    def _rag_context(self, alert: NormalizedStage1Alert) -> list[dict[str, str]]:
        if self.rag_retriever is not None:
            return self.rag_retriever(alert)
        try:
            return retrieve_rag_context(alert, limit=4, timeout_seconds=self.timeout_seconds)
        except Exception as exc:  # advisory path: never let RAG retrieval break triage
            print(f"rag_context_unavailable error={exc}", file=sys.stderr)
            return []

    def triage(self, payload: dict[str, Any]) -> dict[str, Any]:
        started = time.monotonic()
        alert = validate_stage1_alert(payload)
        guardrail_json_pass = 0
        guardrail_input_pass = 1
        guardrail_refusal_pass = 1
        rag_context = self._rag_context(alert)

        try:
            content = self.ollama_caller(
                self.system_prompt,
                build_user_prompt(alert=alert, rag_context=rag_context),
                self.model,
                self.timeout_seconds,
            )
            if is_refusal(content):
                guardrail_refusal_pass = 0
                verdict = refusal_verdict("Model refusal detected; routing alert to manual review.")
            else:
                verdict = extract_json_object(content)
                validation_errors = validate_verdict_payload(verdict)
                if validation_errors:
                    verdict = refusal_verdict("Invalid model JSON: " + "; ".join(validation_errors))
                else:
                    guardrail_json_pass = 1
        except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
            guardrail_refusal_pass = 0
            verdict = refusal_verdict(f"Stage 2 triage failed: {exc}")

        # Load-bearing prompt-injection guardrail (OWASP LLM01:2025). Detection alone is
        # not enough: if the untrusted alert text carried an injection pattern, the model
        # verdict cannot be trusted, so we discard it and force needs_review. This stops an
        # injected "return benign" from yielding a benign verdict (and an FP-reduction credit).
        input_compromised = "prompt_injection_pattern" in alert.input_risk_flags
        if input_compromised:
            guardrail_input_pass = 0
            verdict = refusal_verdict(
                "Prompt-injection pattern in untrusted alert data; model verdict discarded, "
                "routing to manual review."
            )

        # Output sanity gate (OWASP LLM01 + LLM05): do not trust a benign downgrade on a
        # high-confidence Stage 1 detection. Catches injected "return benign" outcomes
        # even when the regex detector missed the injection text in the alert payload.
        output_gated = False
        if (
            not input_compromised
            and str(verdict.get("verdict")) == "benign"
            and alert.attack_score >= HIGH_ATTACK_SCORE
        ):
            output_gated = True
            verdict = refusal_verdict(
                f"Output-gating: Stage 1 attack_score {alert.attack_score:.2f} exceeds "
                f"threshold {HIGH_ATTACK_SCORE:.2f} but model returned benign; "
                "discarding verdict and routing to manual review."
            )

        latency_ms = int((time.monotonic() - started) * 1000)
        insert_verdict(
            client=self.client,
            alert=alert,
            verdict=verdict,
            guardrail_json_pass=guardrail_json_pass,
            guardrail_input_pass=guardrail_input_pass,
            guardrail_refusal_pass=guardrail_refusal_pass,
            latency_ms=latency_ms,
            model=self.model,
        )
        return {
            "alert_id": alert.alert_id,
            "alert_hash": alert_hash(alert.raw),
            "src_ip": alert.src_ip,
            "stage1_label": alert.predicted_label,
            "stage1_detection_preserved": True,
            "advisory_only": True,
            "input_risk_flags": alert.input_risk_flags,
            "output_gated": output_gated,
            "latency_ms": latency_ms,
            "metric_hook": triage_metric_hook(
                alert,
                verdict,
                input_compromised=input_compromised,
                output_gated=output_gated,
            ),
            **verdict,
        }


def read_new_alert_lines(alerts_file: Path, state_file: Path, from_start: bool) -> list[str]:
    if not alerts_file.exists():
        raise FileNotFoundError(alerts_file)

    offset = 0
    if state_file.exists() and not from_start:
        offset = int(state_file.read_text(encoding="utf-8").strip() or "0")
    # Wazuh rotates alerts.json (truncate + archive). A stored offset beyond the
    # current file size would seek past EOF and silently read nothing forever,
    # so restart from the top of the fresh file instead.
    if offset > alerts_file.stat().st_size:
        offset = 0

    with alerts_file.open("r", encoding="utf-8") as handle:
        handle.seek(offset)
        lines = handle.readlines()
        state_file.write_text(str(handle.tell()), encoding="utf-8")
    return [line.strip() for line in lines if line.strip()]


def run_poll(args: argparse.Namespace) -> None:
    worker = Stage2Worker(model=args.model, timeout_seconds=args.timeout_seconds)
    # Scope the poller to the Stage-1 ML rules (100150/100151). Filtering here,
    # at the ingestion boundary, means Stage 2 never spends an LLM call on an
    # alerts.json envelope it is not meant to see; triage() stays pure so it can
    # be unit-tested on any payload.
    allowed_rule_ids = stage2_rule_ids()
    while True:
        lines = read_new_alert_lines(
            alerts_file=args.alerts_file,
            state_file=args.state_file,
            from_start=args.from_start,
        )
        args.from_start = False
        for line in lines:
            # A long-running poller must survive ANY single-line failure: bad
            # JSON, a transient ClickHouse insert error, or an Ollama blip. Catch
            # broadly, record it, and continue rather than let one alert kill the
            # loop (the clickhouse_driver Client re-establishes on the next query).
            try:
                payload = json.loads(line)
                if allowed_rule_ids:
                    rule = payload.get("rule")
                    rule_id_raw = rule.get("id") if isinstance(rule, dict) else None
                    try:
                        rule_id = int(rule_id_raw)
                    except (TypeError, ValueError):
                        rule_id = None
                    if rule_id not in allowed_rule_ids:
                        continue
                print(json.dumps(worker.triage(payload), sort_keys=True))
            except Exception as exc:  # noqa: BLE001 - resilience over precision here
                print(json.dumps({"error": str(exc), "error_type": type(exc).__name__,
                                  "line_hash": hashlib.sha256(line.encode()).hexdigest()}))
        if args.once:
            break
        time.sleep(args.interval_seconds)


class WebhookHandler(BaseHTTPRequestHandler):
    server: "WebhookServer"

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = self.rfile.read(length)
            payload = json.loads(body.decode("utf-8"))
            result = self.server.worker.triage(payload)
            self.send_response(200)
        except (ValueError, json.JSONDecodeError) as exc:
            result = {"error": str(exc)}
            self.send_response(400)

        rendered = json.dumps(result, sort_keys=True).encode("utf-8")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(rendered)))
        self.end_headers()
        self.wfile.write(rendered)

    def log_message(self, format: str, *args: Any) -> None:
        return


class WebhookServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], worker: Stage2Worker) -> None:
        super().__init__(address, WebhookHandler)
        self.worker = worker


def run_webhook(args: argparse.Namespace) -> None:
    worker = Stage2Worker(model=args.model, timeout_seconds=args.timeout_seconds)
    server = WebhookServer((args.host, args.port), worker=worker)
    print(f"stage2 webhook listening on http://{args.host}:{args.port}")
    server.serve_forever()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stage 2 advisory triage worker for Stage 1 alerts.")
    parser.add_argument("--model", default=os.getenv("OLLAMA_MODEL", DEFAULT_MODEL))
    parser.add_argument("--timeout-seconds", type=int, default=int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "60")))
    subparsers = parser.add_subparsers(dest="mode", required=True)

    poll = subparsers.add_parser("poll", help="Poll Stage 1 JSON lines.")
    poll.add_argument("--alerts-file", type=Path, default=DEFAULT_ALERTS_FILE)
    poll.add_argument("--state-file", type=Path, default=DEFAULT_STATE_FILE)
    poll.add_argument("--interval-seconds", type=float, default=2.0)
    poll.add_argument("--from-start", action="store_true")
    poll.add_argument("--once", action="store_true")
    poll.set_defaults(func=run_poll)

    webhook = subparsers.add_parser("webhook", help="Receive Stage 1 alert JSON by HTTP POST.")
    webhook.add_argument("--host", default="127.0.0.1")
    webhook.add_argument("--port", type=int, default=8088)
    webhook.set_defaults(func=run_webhook)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
