"use client";

import { useCallback, useEffect, useState } from "react";
import { useMetric } from "@/components/hooks/useMetric";
import { usePrefersReducedMotion } from "@/components/hooks/useMotion";
import { AnimatedNumber } from "@/components/ui/AnimatedNumber";
import { ArchitectureDiagram } from "@/components/how-it-works/ArchitectureDiagram";
import { Badge } from "@/components/ui/Badge";
import { LoadingSpinner } from "@/components/ui/States";
import { PIPELINE_STAGES } from "@/lib/pipeline-stages";
import { parsePipelineCounts } from "@/lib/pipeline-counts";
import { cn } from "@/lib/utils";
import type { DiagramStageId } from "@/components/how-it-works/ArchitectureDiagram";

const STEP_INTERVAL_MS = 4000;

const OBSERVE_STAGE = {
  id: "observe" as const,
  title: "7. Observe",
  summary:
    "Telemetry from every pipeline stage lands in ClickHouse. Grafana and this dashboard query ngn_sip.* while Keycloak gates SSO access.",
  metrics: ["sip_events", "ml_scores", "ban_audit"] as const,
};

const STEPPER_STAGES = [...PIPELINE_STAGES, OBSERVE_STAGE];

const METRIC_LABELS: Record<string, string> = {
  attack_labels: "Attack labels",
  sip_events: "SIP events",
  suricata_alerts: "Suricata alerts",
  wazuh_sip: "Wazuh SIP rules",
  ml_scores: "ML scores",
  llm_verdicts: "LLM verdicts",
  ban_audit: "Ban audit rows",
  soar_cases: "SOAR cases",
};

export function PipelineStepper({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const [activeStep, setActiveStep] = useState(0);
  const [playing, setPlaying] = useState(true);
  const prefersReducedMotion = usePrefersReducedMotion();
  const { meta, loading } = useMetric<never>("pipeline-summary", hours, refreshMs);
  const counts = parsePipelineCounts(meta);

  const step = STEPPER_STAGES[activeStep];
  const autoPlay = playing && !prefersReducedMotion;

  const goNext = useCallback(() => {
    setActiveStep((current) => (current + 1) % STEPPER_STAGES.length);
  }, []);

  const goPrev = useCallback(() => {
    setActiveStep((current) => (current - 1 + STEPPER_STAGES.length) % STEPPER_STAGES.length);
  }, []);

  useEffect(() => {
    if (!autoPlay) return;
    const timer = window.setInterval(goNext, STEP_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [autoPlay, goNext]);

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-surface-border bg-surface-raised/60 shadow-card">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-surface-border/80 p-3">
          <div className="flex flex-wrap gap-1">
            {STEPPER_STAGES.map((entry, index) => (
              <button
                key={entry.id}
                type="button"
                onClick={() => setActiveStep(index)}
                className={cn(
                  "rounded-lg px-3 py-2 text-sm font-medium transition",
                  activeStep === index
                    ? "bg-accent/15 text-accent"
                    : "text-text-muted hover:bg-surface-overlay/60 hover:text-text-secondary",
                )}
              >
                {entry.title}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => setPlaying((value) => !value)}
            className="rounded-lg border border-surface-border px-3 py-1.5 text-xs font-medium text-text-secondary transition hover:bg-surface-overlay"
            aria-pressed={autoPlay}
          >
            {autoPlay ? "Pause" : "Play"}
          </button>
        </div>

        <div className="p-5">
          {loading ? (
            <LoadingSpinner />
          ) : (
            <>
              <h3 className="text-base font-semibold text-text-primary">{step.title}</h3>
              <p className="mt-2 max-w-3xl text-sm leading-relaxed text-text-secondary">
                {step.summary}
              </p>

              <div className="mt-4 grid grid-cols-2 gap-2 sm:flex sm:flex-wrap">
                {step.metrics.map((key) => (
                  <div
                    key={key}
                    className="min-w-[132px] flex-1 rounded-lg border border-surface-border bg-surface/50 px-3 py-2 sm:min-w-[140px]"
                  >
                    <p className="text-[10px] font-medium uppercase tracking-wide text-text-muted">
                      {METRIC_LABELS[key]}
                    </p>
                    <p className="mt-0.5 text-lg font-semibold tabular-nums text-text-primary">
                      <AnimatedNumber value={counts[key] ?? 0} />
                    </p>
                    <p className="text-[10px] text-text-muted">last {hours}h</p>
                  </div>
                ))}
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={goPrev}
                  className="rounded-lg border border-surface-border px-3 py-1.5 text-xs text-text-secondary transition hover:bg-surface-overlay"
                >
                  Previous
                </button>
                <button
                  type="button"
                  onClick={goNext}
                  className="rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white transition hover:bg-accent-muted"
                >
                  Next step
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      <ArchitectureDiagram activeStage={step.id as DiagramStageId} animate={!prefersReducedMotion} />
    </div>
  );
}

export function PipelineStatusBadges({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { meta, loading } = useMetric<never>("pipeline-summary", hours, refreshMs);
  const counts = parsePipelineCounts(meta);

  if (loading) return null;

  const live = counts.sip_events > 0 || counts.suricata_alerts > 0;
  return (
    <div className="flex flex-wrap gap-2">
      <Badge variant={live ? "healthy" : "stale"}>{live ? "Pipeline active" : "Awaiting data"}</Badge>
      {counts.soar_cases === 0 ? <Badge variant="not_deployed">SOAR not deployed</Badge> : null}
      {counts.llm_verdicts === 0 ? <Badge variant="not_deployed">LLM idle</Badge> : null}
    </div>
  );
}
