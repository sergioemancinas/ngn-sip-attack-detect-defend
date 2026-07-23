import { Badge, severityVariant } from "@/components/ui/Badge";

const VERDICT_TAXONOMY = [
  {
    verdict: "benign",
    meaning: "Alert context appears consistent with normal or expected SIP activity.",
    action: "No block; Stage 1 and autoban remain authoritative.",
  },
  {
    verdict: "suspicious",
    meaning: "Indicators present but inconclusive; warrants analyst review.",
    action: "Advisory flag only; does not trigger ban_table changes.",
  },
  {
    verdict: "malicious",
    meaning: "Model assesses high-confidence attack pattern in alert envelope.",
    action: "Advisory enrichment for SOAR; blocking still via autoban rules.",
  },
  {
    verdict: "needs_review",
    meaning: "Prompt-injection detected, schema failure, or output-gate refusal.",
    action: "Forced safe verdict; never overrides Stage 1 to benign under high attack_score.",
  },
] as const;

export function LlmExplainer() {
  return (
    <div className="rounded-xl border border-surface-border bg-surface-raised/60 shadow-card">
      <div className="border-b border-surface-border/80 px-5 py-4">
        <h3 className="text-base font-semibold text-text-primary">How Stage 2 LLM triage works</h3>
        <p className="mt-1 text-xs text-text-muted">
          Local Ollama advisory layer (qwen2.5) that never overrides Stage 1 or autoban
        </p>
      </div>
      <div className="space-y-4 p-5 text-sm leading-relaxed text-text-secondary">
        <p>
          The Stage 2 worker polls high-severity Wazuh alerts (rule_level &gt;= 10 in the
          100100-100199 range), wraps untrusted alert fields in a structured envelope, and asks a
          local Ollama model for a strict JSON verdict. Output lands in{" "}
          <code className="rounded bg-surface px-1.5 py-0.5 font-mono text-xs text-text-primary">
            llm_verdicts
          </code>
          . Blocking remains the job of kamailio-autoban regardless of LLM output.
        </p>

        <div className="grid gap-3 md:grid-cols-2">
          <div className="rounded-lg border border-surface-border bg-surface/50 p-3 text-xs">
            <p className="font-semibold text-text-primary">Untrusted-data envelope</p>
            <p className="mt-2 text-text-muted">
              Alert text, rule descriptions, and source metadata are treated as untrusted input.
              Fields are sanitized and wrapped before prompt assembly to limit instruction injection
              from attacker-controlled SIP content.
            </p>
          </div>
          <div className="rounded-lg border border-surface-border bg-surface/50 p-3 text-xs">
            <p className="font-semibold text-text-primary">Strict JSON schema</p>
            <p className="mt-2 text-text-muted">
              Model output must parse as JSON with verdict, confidence, rationale, and recommended
              action fields. Malformed responses are rejected and logged without affecting the
              enforcement path.
            </p>
          </div>
        </div>

        <p className="font-medium text-text-primary">Defense layers</p>
        <ul className="list-inside list-disc space-y-1 text-xs text-text-muted">
          <li>Regex prompt-injection detector on input (adversarial paraphrases remain a known gap)</li>
          <li>
            Load-bearing guardrail: injection pattern forces{" "}
            <code className="font-mono">needs_review</code>, never benign
          </li>
          <li>
            Output gate: high attack_score plus benign verdict triggers refusal to manual review
          </li>
          <li>Advisory-only contract: Stage 2 cannot override Stage 1 ml_scores or autoban</li>
        </ul>

        <pre className="code-snippet">
          <code>
            <span className="cmt"># ml/stage2/worker.py - load-bearing guardrail</span>{"\n"}
            input_compromised = <span className="str">"prompt_injection_pattern"</span>{" "}
            <span className="kw">in</span> alert.input_risk_flags{"\n"}
            <span className="kw">if</span> input_compromised:{"\n"}
            {"    "}verdict = refusal_verdict(<span className="str">"Prompt-injection pattern..."</span>
            ){"\n"}
            <span className="kw">elif</span> ({"\n"}
            {"    "}verdict[<span className="str">"verdict"</span>] =={" "}
            <span className="str">"benign"</span>{"\n"}
            {"    "}<span className="kw">and</span> alert.attack_score &gt;= HIGH_ATTACK_SCORE{"\n"}
            ):{"\n"}
            {"    "}verdict = refusal_verdict(<span className="str">"Output-gating..."</span>)
          </code>
        </pre>

        <div>
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-text-muted">
            Verdict taxonomy
          </p>
          <div className="overflow-x-auto rounded-lg border border-surface-border/70">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Verdict</th>
                  <th>Meaning</th>
                  <th>Enforcement</th>
                </tr>
              </thead>
              <tbody>
                {VERDICT_TAXONOMY.map((row) => (
                  <tr key={row.verdict}>
                    <td>
                      <Badge variant={severityVariant(row.verdict)}>{row.verdict}</Badge>
                    </td>
                    <td className="text-text-muted">{row.meaning}</td>
                    <td className="text-text-muted">{row.action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="rounded-lg border border-accent-amber/30 bg-accent-amber/5 p-4 text-xs">
          <p className="font-semibold text-accent-amber">Honest limitations</p>
          <ul className="mt-2 list-inside list-disc space-y-1 text-text-muted">
            <li>Advisory only: no FP reduction credited from LLM verdicts yet at 3b on CPU</li>
            <li>Output gate keys on attack_score: partial mitigation, not complete injection defense</li>
            <li>Regex detector misses ~43% of adversarial paraphrases in red-team corpus</li>
            <li>qwen2.5:7b needs GPU; CPU VM sees ~50% timeout at 90-150 s/call</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
