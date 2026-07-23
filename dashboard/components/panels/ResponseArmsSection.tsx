"use client";

import { Fragment, type ReactNode } from "react";
import { BanAuditPanel } from "@/components/panels/BanAuditPanel";
import { SoarCasesPanel } from "@/components/panels/SoarCasesPanel";
import { cn } from "@/lib/utils";

type Tone = "red" | "purple";

const TONE: Record<
  Tone,
  {
    text: string;
    headerBorder: string;
    cardBorder: string;
    chip: string;
    iconWrap: string;
    fireBox: string;
    fireLabel: string;
    rail: string;
  }
> = {
  red: {
    text: "text-accent-red",
    headerBorder: "border-accent-red/25",
    cardBorder: "border-accent-red/25",
    chip: "border-accent-red/25 bg-accent-red/10 text-accent-red",
    iconWrap: "bg-accent-red/15 text-accent-red",
    fireBox: "border-accent-red/30 bg-accent-red/[0.07]",
    fireLabel: "text-accent-red",
    rail: "bg-accent-red",
  },
  purple: {
    text: "text-accent-purple",
    headerBorder: "border-accent-purple/25",
    cardBorder: "border-accent-purple/25",
    chip: "border-accent-purple/25 bg-accent-purple/10 text-accent-purple",
    iconWrap: "bg-accent-purple/15 text-accent-purple",
    fireBox: "border-accent-purple/30 bg-accent-purple/[0.07]",
    fireLabel: "text-accent-purple",
    rail: "bg-accent-purple",
  },
};

function BoltIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9">
      <path d="M13 2 4 14h7l-1 8 9-12h-7l1-8z" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

function FlowIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="6" cy="5" r="2.4" />
      <circle cx="6" cy="19" r="2.4" />
      <circle cx="18" cy="12" r="2.4" />
      <path d="M8.4 5H13a3 3 0 0 1 3 3v1.2M8.4 19H13a3 3 0 0 0 3-3v-1.2" strokeLinecap="round" />
    </svg>
  );
}

function FlowSteps({ steps, tone }: { steps: string[]; tone: Tone }) {
  return (
    <div className="flex flex-wrap items-center gap-x-1.5 gap-y-1">
      {steps.map((step, index) => (
        <Fragment key={step}>
          <span
            className={cn(
              "rounded-md border px-2 py-1 text-[10px] font-medium",
              TONE[tone].chip,
            )}
          >
            {step}
          </span>
          {index < steps.length - 1 ? (
            <span className="text-text-muted/60" aria-hidden>
              -&gt;
            </span>
          ) : null}
        </Fragment>
      ))}
    </div>
  );
}

function ArmCard({
  tone,
  kicker,
  badge,
  icon,
  title,
  tagline,
  chips,
  whenFires,
  mechanism,
  flow,
  effect,
  table,
  mountIndex,
  children,
}: {
  tone: Tone;
  kicker: string;
  badge: string;
  icon: ReactNode;
  title: string;
  tagline: string;
  chips: string[];
  whenFires: string;
  mechanism: string;
  flow: string[];
  effect: string;
  table: string;
  mountIndex: number;
  children: ReactNode;
}) {
  const t = TONE[tone];

  return (
    <article
      className={cn(
        "card-mount panel-card relative flex flex-col overflow-hidden",
        t.cardBorder,
      )}
      style={{ "--mount-index": mountIndex } as React.CSSProperties}
    >
      <span aria-hidden className={cn("absolute inset-x-0 top-0 h-0.5 opacity-80", t.rail)} />

      <header className={cn("border-b px-5 py-4", t.headerBorder)}>
        <div className="flex items-center justify-between gap-2">
          <p className={cn("text-[10px] font-semibold uppercase tracking-widest", t.text)}>
            {kicker}
          </p>
          <span
            className={cn(
              "rounded-full border px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wide",
              t.chip,
            )}
          >
            {badge}
          </span>
        </div>
        <h4 className="mt-2 flex items-center gap-2 text-base font-semibold text-text-primary">
          <span className={cn("inline-flex h-7 w-7 items-center justify-center rounded-lg", t.iconWrap)}>
            {icon}
          </span>
          {title}
        </h4>
        <p className="mt-2 text-xs leading-relaxed text-text-muted">{tagline}</p>
        <div className="mt-3 flex flex-wrap gap-1.5">
          {chips.map((chip) => (
            <span
              key={chip}
              className={cn("rounded-md border px-2 py-0.5 text-[10px] font-medium", t.chip)}
            >
              {chip}
            </span>
          ))}
        </div>
      </header>

      <div className="space-y-4 px-5 py-4">
        <div className={cn("rounded-lg border px-3 py-2.5", t.fireBox)}>
          <p className={cn("text-[10px] font-semibold uppercase tracking-wide", t.fireLabel)}>
            When this fires
          </p>
          <p className="mt-0.5 text-xs leading-relaxed text-text-secondary">{whenFires}</p>
        </div>

        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wide text-text-muted">
            How it acts
          </p>
          <p className="mt-1 text-xs leading-relaxed text-text-secondary">{mechanism}</p>
          <div className="mt-2.5">
            <FlowSteps steps={flow} tone={tone} />
          </div>
        </div>

        <div className="flex items-start gap-2 rounded-lg bg-surface/50 px-3 py-2.5">
          <span className={cn("mt-0.5 shrink-0", t.text)} aria-hidden>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M5 12h14M13 6l6 6-6 6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </span>
          <p className="text-xs leading-relaxed text-text-secondary">
            <span className="font-semibold text-text-primary">Effect </span>
            {effect}
          </p>
        </div>
      </div>

      <div className="mt-auto border-t border-surface-border/80 px-5 py-4">
        <div className="mb-3 flex items-center justify-between">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">
            Live data
          </p>
          <span className="inline-flex items-center gap-1.5 font-mono text-[10px] text-text-muted">
            <span className={cn("h-1.5 w-1.5 rounded-full", t.rail)} aria-hidden />
            {table}
          </span>
        </div>
        {children}
      </div>
    </article>
  );
}

const COMPARISON: { dimension: string; autoban: string; soar: string }[] = [
  { dimension: "Speed", autoban: "Immediate, inline", soar: "Graded, queued" },
  { dimension: "Human", autoban: "None, fully automated", soar: "Analyst in the loop" },
  { dimension: "Decision", autoban: "Deterministic block", soar: "Proportionate, playbook" },
  { dimension: "Scope", autoban: "Single src_ip at edge", soar: "Case with full context" },
  { dimension: "Record", autoban: "ban_audit", soar: "soar_cases" },
];

function ComparisonStrip() {
  return (
    <div className="panel-card overflow-hidden">
      <div className="grid grid-cols-[1.1fr_1fr_1fr] items-stretch border-b border-surface-border/80 bg-surface/40 text-[10px] font-semibold uppercase tracking-wide">
        <div className="px-4 py-2.5 text-text-muted">Dimension</div>
        <div className="border-l border-surface-border/60 px-4 py-2.5 text-accent-red">Autoban</div>
        <div className="border-l border-surface-border/60 px-4 py-2.5 text-accent-purple">Shuffle SOAR</div>
      </div>
      {COMPARISON.map((row) => (
        <div
          key={row.dimension}
          className="grid grid-cols-[1.1fr_1fr_1fr] items-stretch border-b border-surface-border/40 text-xs last:border-b-0"
        >
          <div className="px-4 py-2.5 font-medium text-text-muted">{row.dimension}</div>
          <div className="border-l border-surface-border/60 px-4 py-2.5 text-text-secondary">
            {row.autoban}
          </div>
          <div className="border-l border-surface-border/60 px-4 py-2.5 text-text-secondary">
            {row.soar}
          </div>
        </div>
      ))}
    </div>
  );
}

export function ResponseArmsSection({
  hours,
  refreshMs,
}: {
  hours: number;
  refreshMs: number;
}) {
  return (
    <div className="space-y-4">
      <div className="panel-card px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-widest text-accent">
              RESPOND stage
            </p>
            <h3 className="mt-1 text-sm font-semibold text-text-primary">
              Two response arms from one trigger source
            </h3>
          </div>
          <div className="flex items-center gap-2 text-[10px]">
            <span className="rounded-md border border-accent-red/25 bg-accent-red/10 px-2 py-1 font-medium text-accent-red">
              Automated · deterministic
            </span>
            <span className="text-text-muted">vs</span>
            <span className="rounded-md border border-accent-purple/25 bg-accent-purple/10 px-2 py-1 font-medium text-accent-purple">
              Graded · human-in-the-loop
            </span>
          </div>
        </div>
        <p className="mt-2.5 text-xs leading-relaxed text-text-muted">
          A high-severity Wazuh alert or a high ML attack score triggers two independent arms.
          kamailio-autoban drops the source at the SIP edge with no analyst; Shuffle SOAR opens a
          graded case for analyst review. The panels below show the live evidence for each arm.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <ArmCard
          tone="red"
          kicker="Arm 1 · Automated edge enforcement"
          badge="No human"
          icon={<BoltIcon />}
          title="kamailio-autoban"
          tagline="Fast, deterministic block at the SIP ingress. The backstop that always runs."
          chips={["Automated", "Immediate", "Deterministic", "Edge drop"]}
          whenFires="A high-severity Wazuh alert (rule_level >= 10) or a high ML attack score names a src_ip."
          mechanism="Kamailio active-response plus an nftables ipset drop reject the offending src_ip at ingress, and the action is written to ban_audit with a never-ban allowlist and RFC 3261 anti-spoofing."
          flow={["Wazuh / ML trigger", "drop src_ip", "ban_audit"]}
          effect="The source is rejected at ingress immediately, with no analyst in the loop."
          table="ban_audit"
          mountIndex={0}
        >
          <BanAuditPanel hours={hours} refreshMs={refreshMs} />
        </ArmCard>

        <ArmCard
          tone="purple"
          kicker="Arm 2 · Graded case management"
          badge="Analyst"
          icon={<FlowIcon />}
          title="Shuffle SOAR"
          tagline="Playbook-driven, proportionate response with full pipeline context for analysts."
          chips={["Playbook", "Enriched", "Proportionate", "Human-in-loop"]}
          whenFires="A Wazuh webhook hands the alert to Shuffle, which opens a case for graded handling."
          mechanism="The playbook runs enrich -> triage -> graded action and records a case in soar_cases with the graded_action, Wazuh rule id and level, the Stage-2 verdict, and the ML predicted label and score, then notifies analysts."
          flow={["Wazuh webhook", "enrich", "triage", "graded action", "notify"]}
          effect="Slower, human-in-the-loop, and proportionate. The response is sized to the evidence."
          table="soar_cases"
          mountIndex={1}
        >
          <SoarCasesPanel hours={hours} refreshMs={refreshMs} />
        </ArmCard>
      </div>

      <ComparisonStrip />
    </div>
  );
}
