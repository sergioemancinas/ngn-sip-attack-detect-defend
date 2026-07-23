"use client";

import { useMetric } from "@/components/hooks/useMetric";
import { LoadingSpinner } from "@/components/ui/States";
import { cn } from "@/lib/utils";

export const LIVE_EVENTS_REFRESH_MS = 5000;

export interface LiveLogColumn<T> {
  key: keyof T | string;
  label: string;
  className?: string;
  render?: (row: T) => React.ReactNode;
}

function formatLogTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value.slice(0, 19);
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function LiveEventsLog<T extends Record<string, unknown>>({
  metric,
  title = "Live events",
  caption,
  hours,
  limit = 15,
  columns,
  emptyMessage = "No events in the selected window.",
  extraParams,
  refreshMs = LIVE_EVENTS_REFRESH_MS,
}: {
  metric: string;
  title?: string;
  caption?: string;
  hours: number;
  limit?: number;
  columns: LiveLogColumn<T>[];
  emptyMessage?: string;
  extraParams?: Record<string, string>;
  refreshMs?: number;
}) {
  const { data, loading, error, lastUpdated } = useMetric<T>(
    metric,
    hours,
    refreshMs,
    {
      limit: String(limit),
      ...extraParams,
    },
  );

  const rows = data ?? [];

  return (
    <div className="panel-card">
      <div className="flex flex-wrap items-end justify-between gap-2 border-b border-surface-border/80 px-4 py-3">
        <div>
          <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
          {caption ? <p className="mt-0.5 text-xs text-text-muted">{caption}</p> : null}
        </div>
        <p className="text-[10px] text-text-muted">
          Auto-refresh {Math.round(refreshMs / 1000)}s
          {lastUpdated
            ? ` · updated ${lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`
            : null}
        </p>
      </div>

      <div className="p-4">
        {loading && rows.length === 0 ? (
          <LoadingSpinner />
        ) : error && rows.length === 0 ? (
          <div className="flex items-center gap-2.5 rounded-lg border border-accent-red/25 bg-accent-red/5 px-3 py-3">
            <svg
              width="15"
              height="15"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              className="shrink-0 text-accent-red"
              aria-hidden
            >
              <circle cx="12" cy="12" r="10" />
              <path d="M12 8v5M12 16h.01" strokeLinecap="round" />
            </svg>
            <p className="font-mono text-[11px] leading-relaxed text-accent-red">{error}</p>
          </div>
        ) : rows.length === 0 ? (
          <div className="flex items-center gap-2.5 rounded-lg border border-dashed border-surface-border/80 bg-surface/30 px-3 py-3">
            <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-surface-border" aria-hidden />
            <p className="text-xs text-text-muted">{emptyMessage}</p>
          </div>
        ) : (
          <div className="max-h-[240px] overflow-auto rounded-lg border border-surface-border/70">
            <table className="data-table">
              <thead>
                <tr>
                  {columns.map((col) => (
                    <th key={String(col.key)} className={col.className}>
                      {col.label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row, index) => (
                  <tr key={`${String(row.event_time ?? row.verdict_time ?? index)}-${index}`}>
                    {columns.map((col) => {
                      const raw = row[col.key as keyof T];
                      const content = col.render
                        ? col.render(row)
                        : raw == null
                          ? "n/a"
                          : String(raw);
                      return (
                        <td
                          key={String(col.key)}
                          className={cn(
                            "font-mono text-[11px]",
                            col.key === "event_time" && "tabular-nums text-text-muted",
                            (col.key === "src" || col.key === "src_ip") && "text-text-primary",
                            col.className,
                          )}
                        >
                          {col.key === "event_time" || col.key === "verdict_time"
                            ? formatLogTime(String(raw))
                            : content}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
