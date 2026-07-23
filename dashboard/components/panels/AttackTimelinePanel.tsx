"use client";

import { MetricFrame, useMetric } from "@/components/hooks/useMetric";
import { Badge, severityVariant } from "@/components/ui/Badge";
import type { AttackTimelineRow } from "@/types/layout";

export function AttackTimelinePanel({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { data, loading, error, empty } = useMetric<AttackTimelineRow>(
    "attack-timeline",
    hours,
    refreshMs,
  );

  const rows = data ?? [];

  return (
    <MetricFrame loading={loading} error={error} empty={empty || rows.length === 0}>
      <div className="max-h-[260px] space-y-2 overflow-auto pr-1">
        {rows.map((row, index) => (
          <div
            key={`${row?.event_time ?? index}-${row?.src_ip ?? index}-${row?.event_type ?? index}`}
            className="flex items-start gap-3 rounded-xl border border-surface-border/70 bg-surface/40 px-3 py-2.5 transition hover:bg-surface-overlay/40"
          >
            <div className="min-w-[76px] text-[10px] tabular-nums text-text-muted">
              {row?.event_time ? new Date(row.event_time).toLocaleTimeString() : "n/a"}
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-text-primary">{row?.src_ip ?? "n/a"}</span>
                <Badge
                  variant={
                    row?.event_type === "ban"
                      ? "ban"
                      : row?.event_type === "attack_label"
                        ? "attack"
                        : severityVariant(row?.severity ?? "")
                  }
                >
                  {row?.event_type ?? "event"}
                </Badge>
              </div>
              <p className="mt-1 text-xs text-text-muted">{row?.detail || row?.severity || "n/a"}</p>
            </div>
          </div>
        ))}
      </div>
    </MetricFrame>
  );
}
