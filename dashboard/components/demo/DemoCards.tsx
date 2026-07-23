"use client";

import { useCallback, useEffect, useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { AnimatedNumber } from "@/components/ui/AnimatedNumber";
import { cn } from "@/lib/utils";

const DEMO_BOOST_DURATION_SEC = 60;

const DEMO_COMMAND = "bash scripts/demo/run_pipeline_demo.sh";
const DIGEST_COMMAND = "bash scripts/demo/pipeline_digest.sh";

export interface DemoRunResult {
  run_id?: string;
  status?: string;
  detail?: string;
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }, [text]);

  return (
    <button
      type="button"
      onClick={copy}
      className="rounded-lg border border-surface-border bg-surface px-3 py-1.5 text-xs font-medium text-text-secondary transition hover:border-accent/40 hover:bg-surface-overlay focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
    >
      {copied ? "Copied" : label}
    </button>
  );
}

export function DemoRunCard({
  onRunDemo,
  running,
  runResult,
  runError,
  boostActive,
  boostRemainingSec = 0,
}: {
  onRunDemo: () => void;
  running: boolean;
  runResult: DemoRunResult | null;
  runError: string | null;
  boostActive: boolean;
  boostRemainingSec?: number;
}) {
  const boostProgress = boostActive
    ? Math.max(0, Math.min(100, (boostRemainingSec / DEMO_BOOST_DURATION_SEC) * 100))
    : 0;
  return (
    <div className="panel-card flex flex-col p-5">
      <h3 className="text-sm font-semibold text-text-primary">Run live demo</h3>
      <p className="mt-2 text-sm leading-relaxed text-text-secondary">
        Trigger a bounded, safe demo on the lab network: a short SIP recon scan followed by a
        REGISTER burst. The dashboard polls ClickHouse every few seconds while the pipeline reacts.
      </p>

      <div className="mt-4 rounded-lg border border-accent/20 bg-accent/5 p-4">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-accent">
          Bounded demo scope
        </p>
        <ul className="mt-2 space-y-1 text-xs text-text-secondary">
          <li>· sippts recon against the internal Kamailio SBC</li>
          <li>· Labeled REGISTER burst with ground-truth attack_labels</li>
          <li>· Not an arbitrary attack launcher; fixed script on demo-runner</li>
        </ul>
      </div>

      <button
        type="button"
        onClick={onRunDemo}
        disabled={running || boostActive}
        aria-busy={running || boostActive}
        className={cn(
          "mt-4 inline-flex w-full items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-semibold transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent",
          running || boostActive
            ? "cursor-not-allowed border border-surface-border bg-surface-overlay text-text-muted"
            : "border border-accent/40 bg-accent text-white shadow-[0_4px_16px_rgba(99,102,241,0.25)] hover:bg-accent-muted active:scale-[0.99]",
        )}
      >
        {running ? (
          <>
            <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-surface-border border-t-accent" />
            Starting demo...
          </>
        ) : boostActive ? (
          <>
            <span className="relative flex h-2 w-2" aria-hidden>
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent/70" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-accent" />
            </span>
            Demo running · {boostRemainingSec}s
          </>
        ) : (
          "Run live demo"
        )}
      </button>

      {runError ? (
        <div
          className="mt-3 rounded-lg border border-accent-amber/30 bg-accent-amber/5 px-3 py-2.5 text-xs text-accent-amber"
          role="status"
        >
          {runError}
        </div>
      ) : null}

      {runResult ? (
        <div
          className="mt-3 rounded-lg border border-accent-green/25 bg-accent-green/5 px-3 py-2.5 text-xs"
          role="status"
        >
          <p className="font-medium text-accent-green">
            {runResult.status ?? "started"}
            {runResult.run_id ? (
              <span className="ml-2 font-mono text-[10px] text-text-muted">{runResult.run_id}</span>
            ) : null}
          </p>
          {runResult.detail ? (
            <p className="mt-1 text-text-secondary">{runResult.detail}</p>
          ) : null}
        </div>
      ) : null}

      {boostActive ? (
        <div className="mt-3" role="status" aria-live="polite">
          <div className="flex items-center justify-between text-[10px] text-accent">
            <span>Fast refresh active · watching timeline and live logs</span>
            <span className="tabular-nums">{boostRemainingSec}s</span>
          </div>
          <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-surface-overlay">
            <div
              className="h-full rounded-full bg-accent transition-[width] duration-1000 ease-linear"
              style={{ width: `${boostProgress}%` }}
            />
          </div>
        </div>
      ) : null}

      <details className="group mt-5 border-t border-surface-border/80 pt-4">
        <summary className="cursor-pointer text-xs font-medium text-text-muted transition hover:text-text-secondary">
          Manual VM commands
        </summary>
        <div className="mt-3 space-y-3">
          <div className="rounded-lg border border-surface-border bg-surface/70 p-3">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">
              Live pipeline demo
            </p>
            <code className="mt-2 block overflow-x-auto font-mono text-xs text-accent-green">
              {DEMO_COMMAND}
            </code>
            <div className="mt-3">
              <CopyButton text={DEMO_COMMAND} label="Copy command" />
            </div>
          </div>

          <div className="rounded-lg border border-surface-border bg-surface/70 p-3">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">
              Post-run digest
            </p>
            <code className="mt-2 block overflow-x-auto font-mono text-xs text-text-secondary">
              {DIGEST_COMMAND}
            </code>
            <div className="mt-3">
              <CopyButton text={DIGEST_COMMAND} label="Copy digest command" />
            </div>
          </div>
        </div>
      </details>

      <p className="mt-4 text-xs text-text-muted">
        The dashboard only HTTP-calls the demo-runner service. It never executes attacks directly.
      </p>
    </div>
  );
}

export function DemoNarrativeHeader({
  srcIp,
  mitre,
  phase,
  attackId,
  live,
  boostActive,
}: {
  srcIp: string | null;
  mitre: string;
  phase: string;
  attackId: string;
  live: boolean;
  boostActive?: boolean;
}) {
  return (
    <div className="panel-card panel-card-accent p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-widest text-accent">
            Demo day
          </p>
          <h3 className="mt-1 text-display-sm font-semibold text-text-primary">
            End-to-end attack pipeline
          </h3>
        </div>
        <div className="flex flex-wrap gap-2">
          {boostActive ? <Badge variant="info">Demo running</Badge> : null}
          <Badge variant={live ? "healthy" : "stale"}>{live ? "Live feed" : "Awaiting attack"}</Badge>
        </div>
      </div>

      <p className="mt-3 max-w-4xl text-sm leading-relaxed text-text-secondary">
        One attacker source, traced across the lab. sippts scans and brute-forces the SIP edge,
        Kamailio and Suricata capture signaling, Wazuh raises NGN-SEC rules, Stage 1 ML scores the
        behavioural windows, Stage 2 LLM triages high-severity alerts (advisory only), and
        kamailio-autoban applies a deterministic ban. Every stage below correlates to{" "}
        <span className="font-mono text-text-primary">{srcIp ?? "attacker IP"}</span>.
      </p>

      {srcIp ? (
        <div className="mt-4 flex flex-wrap gap-2">
          <Badge variant="attack">{srcIp}</Badge>
          {mitre ? <Badge variant="info">{mitre}</Badge> : null}
          {phase ? <Badge variant="suspicious">{phase}</Badge> : null}
          {attackId ? (
            <span className="rounded-md bg-surface-overlay px-2 py-0.5 font-mono text-[10px] text-text-muted">
              {attackId}
            </span>
          ) : null}
        </div>
      ) : (
        <p className="mt-4 text-sm text-text-muted">
          No labeled attacker in the selected window. Run the live demo or the VM script to populate
          the timeline.
        </p>
      )}
    </div>
  );
}

export function DemoPipelineSummary({
  summary,
  srcIp,
  hours,
}: {
  summary: Record<string, number> | undefined;
  srcIp: string | null;
  hours: number;
}) {
  const items = [
    {
      key: "attack_labels",
      label: "Labels",
      caption: "Ground-truth attack_labels",
      accent: "border-accent-red/30 bg-accent-red/5",
      activeText: "text-accent-red",
      dot: "bg-accent-red",
    },
    {
      key: "sip_events",
      label: "SIP events",
      caption: "Signaling captured to sip_events",
      accent: "border-accent/30 bg-accent/5",
      activeText: "text-accent",
      dot: "bg-accent",
    },
    {
      key: "suricata_alerts",
      label: "Suricata",
      caption: "IDS signature alerts",
      accent: "border-accent-amber/30 bg-accent-amber/5",
      activeText: "text-accent-amber",
      dot: "bg-accent-amber",
    },
    {
      key: "wazuh_alerts",
      label: "Wazuh SIP",
      caption: "Rules 100100-100199 hits",
      accent: "border-accent-amber/25 bg-accent-amber/5",
      activeText: "text-accent-amber",
      dot: "bg-accent-amber",
    },
    {
      key: "ml_scores",
      label: "Stage 1 ML",
      caption: "Behavioural scorer output",
      accent: "border-accent-purple/30 bg-accent-purple/5",
      activeText: "text-accent-purple",
      dot: "bg-accent-purple",
    },
    {
      key: "llm_verdicts",
      label: "Stage 2 LLM",
      caption: "Advisory triage verdicts",
      accent: "border-cyan-500/30 bg-cyan-500/5",
      activeText: "text-cyan-300",
      dot: "bg-cyan-400",
    },
    {
      key: "ban_actions",
      label: "Autoban",
      caption: "ban_audit enforcement actions",
      accent: "border-accent-purple/25 bg-accent-purple/5",
      activeText: "text-accent-purple",
      dot: "bg-accent-purple",
    },
  ];

  return (
    <div className="panel-card p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-text-primary">Pipeline result</h3>
          <p className="mt-1 text-xs text-text-muted">
            {srcIp
              ? `Per-stage event counts for attacker ${srcIp}`
              : "Counts appear once an attacker source is selected"}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {srcIp ? (
            <span className="rounded-md border border-surface-border bg-surface px-2 py-1 font-mono text-[10px] text-text-primary">
              {srcIp}
            </span>
          ) : null}
          <span className="rounded-md border border-surface-border bg-surface px-2 py-1 text-[10px] text-text-muted">
            Last {hours}h window
          </span>
        </div>
      </div>

      <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 2xl:grid-cols-7">
        {items.map((item) => {
          const count = summary?.[item.key] ?? 0;
          const active = count > 0;
          return (
            <div
              key={item.key}
              className={cn(
                "flex min-h-[108px] min-w-0 flex-col rounded-xl border p-3 transition-all duration-300 sm:min-h-[120px] sm:p-4",
                active
                  ? cn(item.accent, "shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]")
                  : "border-surface-border/80 bg-surface/30 opacity-90",
              )}
            >
              <div className="flex items-center gap-1.5">
                <span
                  className={cn(
                    "h-1.5 w-1.5 shrink-0 rounded-full transition-colors duration-300",
                    active ? cn(item.dot, "animate-pulse") : "bg-surface-border",
                  )}
                  aria-hidden
                />
                <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">
                  {item.label}
                </p>
              </div>
              <p
                className={cn(
                  "mt-3 text-3xl font-semibold tabular-nums leading-none transition-colors duration-300",
                  active ? item.activeText : "text-text-muted/70",
                )}
              >
                <AnimatedNumber value={count} />
              </p>
              <p className="mt-auto pt-3 text-[10px] leading-snug text-text-muted">
                {active ? item.caption : "0 · inactive in window"}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
