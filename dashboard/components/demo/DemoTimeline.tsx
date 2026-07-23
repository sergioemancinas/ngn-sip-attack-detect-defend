"use client";

import { MetricFrame, useMetric } from "@/components/hooks/useMetric";
import { Badge, severityVariant } from "@/components/ui/Badge";
import { formatInteger } from "@/lib/chart-utils";
import type { DemoStageHighlight, DemoTimelineEvent } from "@/types/layout";
import { cn } from "@/lib/utils";

const DEMO_REFRESH_MS = 5000;

const STAGE_VARIANTS: Record<string, "attack" | "info" | "malicious" | "suspicious" | "benign" | "ban" | "default"> = {
  attack_label: "attack",
  sip: "info",
  suricata: "suspicious",
  wazuh: "malicious",
  ml: "suspicious",
  llm: "info",
  ban: "ban",
};

function formatTime(value: string | null): string {
  if (!value) return "n/a";
  return new Date(value).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function StageTimeline({ highlights }: { highlights: DemoStageHighlight[] }) {
  const stages = Array.isArray(highlights) ? highlights : [];
  if (stages.length === 0) {
    return (
      <p className="text-sm text-text-muted">
        Pipeline stages will appear once a correlated attacker is selected.
      </p>
    );
  }

  return (
    <ol className="relative space-y-0" aria-label="Pipeline stage timeline">
      {stages.map((stage, index) => {
        const isLast = index === highlights.length - 1;
        const variant = STAGE_VARIANTS[stage.stage] ?? "default";

        return (
          <li key={stage.stage} className="relative flex gap-4 pb-6 last:pb-0">
            {!isLast ? (
              <span
                aria-hidden
                className={cn(
                  "absolute left-[15px] top-8 h-[calc(100%-12px)] w-0.5",
                  stage.active ? "bg-accent/50" : "bg-surface-border",
                )}
              />
            ) : null}

            <div
              className={cn(
                "relative z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border-2 transition-all duration-500",
                stage.active
                  ? "border-accent bg-accent/20 shadow-[0_0_16px_rgba(59,130,246,0.35)]"
                  : "border-surface-border bg-surface-overlay",
              )}
              aria-hidden
            >
              <span
                className={cn(
                  "h-2.5 w-2.5 rounded-full transition-colors duration-500",
                  stage.active ? "bg-accent animate-pulse" : "bg-surface-border",
                )}
              />
            </div>

            <div
              className={cn(
                "min-w-0 flex-1 rounded-xl border p-4 transition-all duration-500",
                stage.active
                  ? "border-accent/30 bg-accent/5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]"
                  : "border-surface-border/70 bg-surface/30 opacity-70",
              )}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <h4 className="text-sm font-semibold text-text-primary">{stage.label}</h4>
                  <Badge variant={stage.active ? variant : "not_deployed"}>
                    {stage.active ? "Active" : "Pending"}
                  </Badge>
                </div>
                <span className="font-mono text-[10px] tabular-nums text-text-muted">
                  {formatTime(stage.latest_time)}
                </span>
              </div>

              <p className="mt-2 text-sm text-text-secondary">{stage.key_value}</p>
              {stage.detail ? (
                <p className="mt-1 truncate text-xs text-text-muted">{stage.detail}</p>
              ) : null}
              <p className="mt-2 text-[10px] uppercase tracking-wide text-text-muted">
                {formatInteger(stage.count)} event{stage.count === 1 ? "" : "s"}
              </p>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

function EventStream({ events }: { events: DemoTimelineEvent[] }) {
  const rows = Array.isArray(events) ? events : [];
  if (rows.length === 0) {
    return (
      <p className="text-sm text-text-muted">
        Correlated events will stream here as the attack progresses.
      </p>
    );
  }

  return (
    <div className="max-h-[320px] space-y-2 overflow-auto pr-1" aria-label="Correlated event stream">
      {rows.map((event, index) => (
        <div
          key={`${event.event_time}-${event.stage}-${event.key}-${index}`}
          className="flex items-start gap-3 rounded-lg border border-surface-border/70 bg-surface/40 px-3 py-2"
        >
          <span className="min-w-[68px] font-mono text-[10px] tabular-nums text-text-muted">
            {formatTime(event.event_time)}
          </span>
          <Badge variant={STAGE_VARIANTS[event.stage] ?? severityVariant(event.value)}>
            {event.stage}
          </Badge>
          <div className="min-w-0 flex-1">
            <p className="text-xs text-text-primary">
              <span className="font-medium">{event.key}</span>
              <span className="text-text-muted"> · </span>
              <span className="font-mono">{event.value}</span>
            </p>
            {event.detail ? (
              <p className="mt-0.5 truncate text-[10px] text-text-muted">{event.detail}</p>
            ) : null}
          </div>
        </div>
      ))}
    </div>
  );
}

function parseHighlights(meta: Record<string, unknown> | undefined): DemoStageHighlight[] {
  const raw = meta?.stage_highlights;
  if (!Array.isArray(raw)) return [];
  return raw
    .filter(
      (item): item is DemoStageHighlight =>
        typeof item === "object" &&
        item !== null &&
        typeof (item as DemoStageHighlight).stage === "string",
    )
    .map((item) => ({
      ...item,
      count: typeof item.count === "number" ? item.count : Number(item.count) || 0,
      active: Boolean(item.active),
      latest_time: typeof item.latest_time === "string" ? item.latest_time : null,
      key_value: String(item.key_value ?? "Awaiting data"),
      detail: String(item.detail ?? ""),
      label: String(item.label ?? item.stage),
    }));
}

function parseSummary(meta: Record<string, unknown> | undefined): Record<string, number> {
  const raw = meta?.summary;
  if (typeof raw !== "object" || raw === null) return {};
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof value === "number" && Number.isFinite(value)) {
      out[key] = value;
    }
  }
  return out;
}

export function DemoTimelinePanel({
  hours,
  refreshMs = DEMO_REFRESH_MS,
  refetchNonce,
}: {
  hours: number;
  refreshMs?: number;
  refetchNonce?: number;
}) {
  const { data, meta, loading, error, empty, lastUpdated } = useMetric<DemoTimelineEvent>(
    "demo-timeline",
    hours,
    refreshMs,
    { limit: "80" },
    refetchNonce,
  );

  const highlights = parseHighlights(meta);
  const srcIp = typeof meta?.src_ip === "string" ? meta.src_ip : null;
  const demoHours = typeof meta?.demo_hours === "number" ? meta.demo_hours : hours;
  const events = Array.isArray(data) ? data : [];

  return (
    <div className="panel-card p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold text-text-primary">Correlated attack timeline</h3>
          <p className="mt-1 text-xs text-text-muted">
            Auto-refreshes every {Math.round(refreshMs / 1000)}s · correlated attacker source
            {srcIp ? (
              <>
                {" "}
                · <span className="font-mono text-text-secondary">{srcIp}</span>
              </>
            ) : null}
            {demoHours > hours ? (
              <span className="text-text-muted"> · correlation window {demoHours}h</span>
            ) : null}
          </p>
        </div>
        {lastUpdated ? (
          <span className="text-[10px] tabular-nums text-text-muted">
            Updated {formatTime(lastUpdated.toISOString())}
          </span>
        ) : null}
      </div>

      <div className="mt-5">
        <MetricFrame loading={loading} error={error} empty={empty && highlights.length === 0 && events.length === 0}>
          <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <StageTimeline highlights={highlights} />
            <div>
              <h4 className="mb-3 text-xs font-semibold uppercase tracking-widest text-text-muted">
                Event stream
              </h4>
              <EventStream events={events} />
            </div>
          </div>
        </MetricFrame>
      </div>
    </div>
  );
}

export { DEMO_REFRESH_MS, parseSummary };
