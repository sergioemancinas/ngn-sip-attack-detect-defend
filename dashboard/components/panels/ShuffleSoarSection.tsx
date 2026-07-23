"use client";

import { Fragment } from "react";
import { useMetric } from "@/components/hooks/useMetric";
import { Badge, severityVariant } from "@/components/ui/Badge";
import { EmptyState, ErrorState, LoadingSpinner } from "@/components/ui/States";
import { coerceCount, formatInteger } from "@/lib/chart-utils";
import { parseSoarCaseRecent, type SoarCaseRecentRow } from "@/types/layout";
import { cn } from "@/lib/utils";

type StepTone = "amber" | "accent" | "purple" | "green";

const STEP_TONE: Record<StepTone, { rail: string; num: string; ring: string }> = {
  amber: {
    rail: "bg-accent-amber",
    num: "border-accent-amber/40 bg-accent-amber/10 text-accent-amber",
    ring: "border-accent-amber/30",
  },
  accent: {
    rail: "bg-accent",
    num: "border-accent/40 bg-accent/10 text-accent",
    ring: "border-accent/30",
  },
  purple: {
    rail: "bg-accent-purple",
    num: "border-accent-purple/40 bg-accent-purple/10 text-accent-purple",
    ring: "border-accent-purple/30",
  },
  green: {
    rail: "bg-accent-green",
    num: "border-accent-green/40 bg-accent-green/10 text-accent-green",
    ring: "border-accent-green/30",
  },
};

const PLAYBOOK_STEPS: { n: string; title: string; detail: string; tone: StepTone }[] = [
  {
    n: "01",
    title: "Wazuh webhook",
    detail: "A rule_level >= 10 alert (SIDs 100100-100199) is pushed to the Shuffle webhook.",
    tone: "amber",
  },
  {
    n: "02",
    title: "Enrich",
    detail: "Attach src_ip context, recent ml_scores, and any prior soar_cases for the source.",
    tone: "accent",
  },
  {
    n: "03",
    title: "Stage-2 triage",
    detail: "Replay the advisory LLM verdict for the alert envelope (benign to malicious).",
    tone: "purple",
  },
  {
    n: "04",
    title: "Graded action",
    detail: "Size a proportionate action from the combined ML, LLM, and rule evidence.",
    tone: "purple",
  },
  {
    n: "05",
    title: "Case + notify",
    detail: "Write the graded case to soar_cases and notify the analyst channel.",
    tone: "green",
  },
];

function PlaybookChevron() {
  return (
    <div className="flex w-6 shrink-0 items-center justify-center self-center sm:w-8" aria-hidden>
      <svg viewBox="0 0 16 16" className="h-4 w-4 text-text-muted/50" fill="none">
        <path
          d="M5 3l5 5-5 5"
          stroke="currentColor"
          strokeWidth="1.75"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </div>
  );
}

function PlaybookFlow() {
  return (
    <div className="panel-card p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-widest text-accent-purple">
            Playbook flow
          </p>
          <h3 className="mt-1 text-sm font-semibold text-text-primary">
            From Wazuh trigger to a graded case
          </h3>
        </div>
        <span className="inline-flex items-center gap-1.5 font-mono text-[10px] text-text-muted">
          <span className="h-1.5 w-1.5 rounded-full bg-accent-purple" aria-hidden />
          soar_cases
        </span>
      </div>

      <div className="mt-4 overflow-x-auto pb-1">
        <ol className="flex min-w-[760px] items-stretch">
          {PLAYBOOK_STEPS.map((step, index) => {
            const tone = STEP_TONE[step.tone];
            return (
              <Fragment key={step.n}>
                <li
                  className={cn(
                    "relative flex flex-1 flex-col overflow-hidden rounded-lg border bg-surface/50 px-3 py-3",
                    tone.ring,
                  )}
                >
                  <span aria-hidden className={cn("absolute inset-x-0 top-0 h-0.5 opacity-80", tone.rail)} />
                  <span
                    className={cn(
                      "flex h-6 w-6 items-center justify-center rounded-full border font-mono text-[10px] font-semibold tabular-nums",
                      tone.num,
                    )}
                  >
                    {step.n}
                  </span>
                  <p className="mt-2 text-xs font-semibold text-text-primary">{step.title}</p>
                  <p className="mt-1 text-[11px] leading-relaxed text-text-muted">{step.detail}</p>
                </li>
                {index < PLAYBOOK_STEPS.length - 1 ? <PlaybookChevron /> : null}
              </Fragment>
            );
          })}
        </ol>
      </div>
    </div>
  );
}

function ComplementCard() {
  return (
    <div className="panel-card flex flex-col p-5">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-accent-purple">
        Defense in depth
      </p>
      <h3 className="mt-1 text-sm font-semibold text-text-primary">
        How Shuffle complements autoban
      </h3>
      <p className="mt-2 text-xs leading-relaxed text-text-muted">
        autoban optimises for latency: it drops a source at the SIP edge the instant a high-severity
        rule names it, with no analyst and no context beyond the trigger. Shuffle runs in parallel on
        that same trigger but optimises for judgement. It assembles the full case (Stage-1 score,
        Stage-2 verdict, rule history) and grades a proportionate action a human can confirm or
        override. The edge stays covered either way; Shuffle adds the graded, auditable decision a
        blunt ban cannot express.
      </p>
      <div className="mt-3 space-y-2">
        <div className="rounded-lg border border-accent-red/25 bg-accent-red/[0.06] px-3 py-2">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-accent-red">
            autoban · edge backstop
          </p>
          <p className="mt-0.5 text-[11px] leading-relaxed text-text-secondary">
            Already blocked the source inline. Shuffle never gates ingress latency.
          </p>
        </div>
        <div className="rounded-lg border border-accent-purple/25 bg-accent-purple/[0.06] px-3 py-2">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-accent-purple">
            Shuffle · graded layer
          </p>
          <p className="mt-0.5 text-[11px] leading-relaxed text-text-secondary">
            Monitor, throttle, or escalate with analyst sign-off, recorded in soar_cases.
          </p>
        </div>
      </div>
    </div>
  );
}

function actionTone(action: string): "attack" | "suspicious" | "info" | "default" {
  const a = action.toLowerCase();
  if (/(ban|block|escalat|isolat|drop)/.test(a)) return "attack";
  if (/(throttle|rate|quarantin|review|hold|tarpit)/.test(a)) return "suspicious";
  if (/(monitor|watch|notify|log|track|observe)/.test(a)) return "info";
  return "default";
}

function GradedActionDistribution({
  rows,
  total,
}: {
  rows: { action: string; count: number }[];
  total: number;
}) {
  return (
    <div className="panel-card flex flex-col p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-widest text-accent-purple">
            Graded action distribution
          </p>
          <h3 className="mt-1 text-sm font-semibold text-text-primary">
            graded_action across cases
          </h3>
        </div>
        <p className="text-xs tabular-nums text-text-muted">
          {formatInteger(total)} case{total === 1 ? "" : "s"} in window
        </p>
      </div>

      {rows.length === 0 ? (
        <div className="mt-4 flex flex-1 items-center justify-center rounded-lg border border-dashed border-surface-border/80 bg-surface/30 px-3 py-6 text-center text-xs text-text-muted">
          No graded actions in the selected window.
        </div>
      ) : (
        <div className="mt-4 space-y-3">
          {rows.map((row) => {
            const pct = total > 0 ? Math.round((row.count / total) * 100) : 0;
            return (
              <div key={row.action}>
                <div className="flex items-center justify-between gap-2 text-xs">
                  <Badge variant={actionTone(row.action)}>{row.action}</Badge>
                  <span className="tabular-nums text-text-muted">
                    {formatInteger(row.count)} ({pct}%)
                  </span>
                </div>
                <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-surface-overlay">
                  <div
                    className="h-full rounded-full bg-accent-purple/80 transition-all"
                    style={{ width: `${Math.max(pct, 2)}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function formatCaseTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function RecentCasesTable({ rows }: { rows: SoarCaseRecentRow[] }) {
  return (
    <div className="panel-card overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border/80 px-5 py-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-widest text-accent-purple">
            Recent cases
          </p>
          <h3 className="mt-1 text-sm font-semibold text-text-primary">
            Latest soar_cases rows with full pipeline context
          </h3>
        </div>
        <span className="font-mono text-[10px] text-text-muted">{rows.length} shown</span>
      </div>

      {rows.length === 0 ? (
        <div className="px-5 py-6">
          <div className="flex items-center gap-2.5 rounded-lg border border-dashed border-surface-border/80 bg-surface/30 px-3 py-3">
            <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-surface-border" aria-hidden />
            <p className="text-xs text-text-muted">
              No soar_cases rows in the selected window. Widen the time range to see seeded cases.
            </p>
          </div>
        </div>
      ) : (
        <div className="max-h-[360px] overflow-auto">
          <table className="data-table min-w-[720px]">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Graded action</th>
                <th className="numeric">Wazuh rule</th>
                <th>Stage 2</th>
                <th>ML label</th>
                <th className="numeric">ML score</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={`${row.case_time}-${row.src_ip}-${index}`}>
                  <td className="tabular-nums text-text-muted">{formatCaseTime(row.case_time)}</td>
                  <td className="mono">{row.src_ip}</td>
                  <td>
                    <Badge variant={actionTone(row.graded_action)}>{row.graded_action}</Badge>
                  </td>
                  <td className="numeric">
                    <span className="font-mono text-text-primary">{row.wazuh_rule_id || "-"}</span>
                    <span className="ml-1 text-[10px] text-text-muted">
                      {row.wazuh_rule_level != null ? `L${row.wazuh_rule_level}` : ""}
                    </span>
                  </td>
                  <td>
                    {row.stage2_verdict ? (
                      <Badge variant={severityVariant(row.stage2_verdict)}>
                        {row.stage2_verdict}
                      </Badge>
                    ) : (
                      <span className="text-text-muted">-</span>
                    )}
                  </td>
                  <td className="text-text-secondary">{row.ml_predicted_label || "-"}</td>
                  <td className="numeric font-mono">
                    {row.ml_attack_score != null ? row.ml_attack_score.toFixed(2) : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function ShuffleSoarSection({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { data, loading, error, meta } = useMetric<{
    graded_action: string;
    case_count: number;
  }>("soar-cases", hours, refreshMs, { limit: "25" });

  const tableMissing = Boolean(meta?.table_missing);
  const summaryRows = (data ?? [])
    .map((row) => ({ action: String(row?.graded_action ?? "unknown"), count: coerceCount(row?.case_count) }))
    .filter((row) => row.count > 0);
  const recent = parseSoarCaseRecent(meta);
  const totalCases = summaryRows.reduce((sum, row) => sum + row.count, 0);

  const showLoading = loading && summaryRows.length === 0 && recent.length === 0;
  const showError = Boolean(error) && summaryRows.length === 0 && recent.length === 0;

  return (
    <div className="space-y-5">
      <PlaybookFlow />

      {tableMissing ? (
        <EmptyState message="soar_cases table not present. Run the DDL before the first Shuffle workflow execution." />
      ) : showLoading ? (
        <div className="panel-card p-5">
          <LoadingSpinner />
        </div>
      ) : showError ? (
        <ErrorState message={error ?? "Request failed"} />
      ) : (
        <>
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
            <GradedActionDistribution rows={summaryRows} total={totalCases} />
            <ComplementCard />
          </div>
          <RecentCasesTable rows={recent} />
        </>
      )}
    </div>
  );
}
