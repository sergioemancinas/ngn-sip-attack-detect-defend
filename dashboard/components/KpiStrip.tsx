"use client";

import { useMemo } from "react";
import { useMetric } from "@/components/hooks/useMetric";
import { AnimatedNumber } from "@/components/ui/AnimatedNumber";
import { KpiSkeleton } from "@/components/ui/States";
import { coerceCount } from "@/lib/chart-utils";
import { parsePipelineCounts } from "@/lib/pipeline-counts";
import { parseSummaryCounts } from "@/types/layout";
import { cn } from "@/lib/utils";

type KpiTone = "default" | "danger" | "success" | "warning";

interface KpiCardProps {
  label: string;
  value: number;
  hint?: string;
  tone?: KpiTone;
  index?: number;
}

const TONE_TEXT: Record<KpiTone, string> = {
  default: "text-text-primary",
  danger: "text-accent-red",
  success: "text-accent-green",
  warning: "text-accent-amber",
};

const TONE_BAR: Record<KpiTone, string> = {
  default: "bg-accent/40",
  danger: "bg-accent-red",
  success: "bg-accent-green",
  warning: "bg-accent-amber",
};

function KpiCard({ label, value, hint, tone = "default", index = 0 }: KpiCardProps) {
  return (
    <div
      className="stat-card card-mount relative overflow-hidden transition-all duration-300 hover:-translate-y-0.5"
      style={{ "--mount-index": index } as React.CSSProperties}
    >
      <span className={cn("stat-accent-bar", TONE_BAR[tone])} aria-hidden />
      <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">{label}</p>
      <p className={cn("mt-2 text-2xl font-semibold tabular-nums", TONE_TEXT[tone])}>
        <AnimatedNumber value={value} />
      </p>
      {hint ? <p className="mt-1 text-xs text-text-muted">{hint}</p> : null}
    </div>
  );
}

export function KpiStrip({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const pipeline = useMetric<never>("pipeline-summary", hours, refreshMs);
  const timeline = useMetric<{ event_type: string }>("attack-timeline", hours, refreshMs);
  const bans = useMetric<{ action: string; action_count: number }>("ban-audit", hours, refreshMs);
  const ml = useMetric<{ predicted_class: string; score_count: number }>("ml-scores", hours, refreshMs);
  const llm = useMetric<{ verdict: string; verdict_count: number }>("llm-verdicts", hours, refreshMs);

  const loading =
    pipeline.loading || timeline.loading || bans.loading || ml.loading || llm.loading;

  const metrics = useMemo(() => {
    const counts = parsePipelineCounts(pipeline.meta);
    const sipEvents = counts.sip_events;

    const attacks = (timeline.data ?? []).filter(
      (row) => row?.event_type === "attack_label" || row?.event_type === "ban",
    ).length;

    const banRows = bans.data ?? [];
    const banned =
      banRows.find((row) => row?.action === "ban")?.action_count ??
      banRows.reduce((sum, row) => sum + coerceCount(row?.action_count), 0);

    const stage1 = parseSummaryCounts(ml.meta, "summary", "score_count");
    const stage2 = parseSummaryCounts(llm.meta, "summary", "verdict_count");

    return { sipEvents, attacks, banned, stage1, stage2 };
  }, [pipeline.meta, timeline.data, bans.data, ml.meta, llm.meta]);

  if (loading) return <KpiSkeleton />;

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
      <KpiCard label="Total SIP events" value={metrics.sipEvents} hint={`Last ${hours}h window`} index={0} />
      <KpiCard
        label="Attacks detected"
        value={metrics.attacks}
        hint="Labels and ban events"
        tone={metrics.attacks > 0 ? "danger" : "default"}
        index={1}
      />
      <KpiCard
        label="Sources banned"
        value={metrics.banned}
        hint="Autoban actions"
        tone={metrics.banned > 0 ? "warning" : "default"}
        index={2}
      />
      <KpiCard label="Stage 1 verdicts" value={metrics.stage1} hint="ML scorer output" index={3} />
      <KpiCard label="Stage 2 verdicts" value={metrics.stage2} hint="LLM triage output" index={4} />
    </div>
  );
}

export function useKpiLastUpdated(hours: number, refreshMs: number): Date | null {
  const pipeline = useMetric<never>("pipeline-summary", hours, refreshMs);
  return pipeline.lastUpdated ?? null;
}
