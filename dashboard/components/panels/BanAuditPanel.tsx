"use client";

import { MetricFrame, useMetric } from "@/components/hooks/useMetric";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/States";
import { formatInteger } from "@/lib/chart-utils";
import { parseBanAuditRecent } from "@/types/layout";

export function BanAuditPanel({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { data, loading, error, empty, meta } = useMetric<{ action: string; action_count: number }>(
    "ban-audit",
    hours,
    refreshMs,
  );

  if (meta?.table_missing) {
    return <EmptyState message="ban_audit not created yet (autoban sidecar idle)" />;
  }

  const rows = data ?? [];
  const recent = parseBanAuditRecent(meta);

  return (
    <MetricFrame loading={loading} error={error} empty={empty && recent.length === 0 && rows.length === 0}>
      <div className="grid grid-cols-2 gap-3">
        {(rows ?? []).map((row) => (
          <div key={String(row?.action ?? "unknown")} className="rounded-xl border border-surface-border bg-surface/60 p-3">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">
              {row?.action ?? "action"}
            </p>
            <p className="mt-1 text-2xl font-semibold tabular-nums text-text-primary">
              {formatInteger(row?.action_count)}
            </p>
          </div>
        ))}
      </div>
      {recent.length > 0 ? (
        <div className="mt-4 space-y-2">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">Recent</p>
          {recent.slice(0, 5).map((row) => (
            <div key={`${row.event_time}-${row.src_ip}`} className="flex items-center justify-between gap-2 text-xs">
              <span className="font-mono text-text-secondary">{row.src_ip}</span>
              <Badge variant={row.action === "ban" ? "ban" : "default"}>{row.action}</Badge>
            </div>
          ))}
        </div>
      ) : null}
    </MetricFrame>
  );
}
