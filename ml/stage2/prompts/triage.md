Triage this Wazuh SIP alert for the lab detection pipeline.

Allowed verdicts:

- malicious
- suspicious
- benign
- needs_review

Return JSON matching this shape:

{
  "verdict": "malicious|suspicious|benign|needs_review",
  "confidence": 0.0,
  "reasoning": "short evidence-based rationale",
  "rag_context_ids": ["source#chunk-0"]
}

Alert:

```json
{{ALERT_JSON}}
```

Retrieved context:

```json
{{RAG_CONTEXT}}
```
