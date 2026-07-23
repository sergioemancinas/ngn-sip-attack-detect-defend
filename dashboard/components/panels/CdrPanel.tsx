"use client";

import { useState } from "react";
import { MetricFrame, useMetric } from "@/components/hooks/useMetric";
import { formatInteger } from "@/lib/chart-utils";
import { cn } from "@/lib/utils";
import type { CdrRow } from "@/types/layout";

export function CdrPanel({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const [groupBy, setGroupBy] = useState<"src_ip" | "response_code">("src_ip");
  const extra = groupBy === "response_code" ? "response_code" : "src_ip";
  const { data, loading, error, empty, meta } = useMetric<CdrRow>(
    "cdr",
    hours,
    refreshMs,
    { groupBy: extra },
  );

  return (
    <div className="flex h-full flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex gap-1">
          {(["src_ip", "response_code"] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => setGroupBy(mode)}
              className={cn(
                "rounded-lg px-2.5 py-1 text-[10px] font-medium uppercase tracking-wide transition",
                groupBy === mode
                  ? "bg-accent/15 text-accent"
                  : "bg-surface-overlay text-text-muted hover:text-text-secondary",
              )}
            >
              {mode === "src_ip" ? "By source IP" : "By response"}
            </button>
          ))}
        </div>
        {meta?.qos_available === false ? (
          <span className="text-[10px] text-accent-amber">MOS / Loss / Delay pending HEP RTCP</span>
        ) : null}
      </div>
      <MetricFrame loading={loading} error={error} empty={empty || data.length === 0}>
        <div className="max-h-[300px] overflow-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Group</th>
                <th className="numeric">Calls</th>
                <th className="numeric">INVITE</th>
                <th className="numeric">REGISTER</th>
                <th className="numeric">2xx</th>
                <th className="numeric">401/403</th>
                <th className="numeric">MOS</th>
                <th className="numeric">Loss</th>
                <th className="numeric">Delay</th>
              </tr>
            </thead>
            <tbody>
              {(data ?? []).map((row) => (
                <tr key={String(row?.group_key ?? "unknown")}>
                  <td className="mono">{row?.group_key ?? "n/a"}</td>
                  <td className="numeric">{formatInteger(row?.call_count)}</td>
                  <td className="numeric">{formatInteger(row?.invite_count)}</td>
                  <td className="numeric">{formatInteger(row?.register_count)}</td>
                  <td className="numeric">{formatInteger(row?.success_2xx)}</td>
                  <td className="numeric">{formatInteger(row?.auth_failures)}</td>
                  <td className="numeric text-text-muted">{row.mos ?? "pending"}</td>
                  <td className="numeric text-text-muted">{row.packet_loss_pct ?? "pending"}</td>
                  <td className="numeric text-text-muted">{row.delay_ms ?? "pending"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </MetricFrame>
    </div>
  );
}
