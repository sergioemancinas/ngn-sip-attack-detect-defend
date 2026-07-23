"use client";

import { MetricFrame, useMetric } from "@/components/hooks/useMetric";
import { Badge } from "@/components/ui/Badge";
import { formatInteger } from "@/lib/chart-utils";
import {
  STACK_HEALTH_NO_UI,
  stackHealthUiLink,
} from "@/lib/stack-health-links";
import { parseServiceHealthRow, type ServiceHealthStatus } from "@/lib/stack-health";
import type { StackHealthRow } from "@/types/layout";

type StackHealthApiRow = StackHealthRow & { detail?: string };

function ExternalLinkIcon() {
  return (
    <svg
      width="10"
      height="10"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
      <polyline points="15 3 21 3 21 9" />
      <line x1="10" y1="14" x2="21" y2="3" />
    </svg>
  );
}

function formatStatus(status: ServiceHealthStatus): string {
  if (status === "not_deployed") return "not deployed";
  return status;
}

function badgeVariant(status: ServiceHealthStatus): "healthy" | "stale" | "attack" | "not_deployed" {
  switch (status) {
    case "healthy":
      return "healthy";
    case "idle":
      return "stale";
    case "down":
      return "attack";
    case "not_deployed":
      return "not_deployed";
  }
}

export function StackHealthPanel({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { data, loading, error, empty } = useMetric<StackHealthApiRow>(
    "stack-health",
    hours,
    refreshMs,
  );

  const rows = (data ?? []).map((row) => parseServiceHealthRow(row));

  return (
    <MetricFrame loading={loading} error={error} empty={empty || rows.length === 0}>
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-4">
          {rows.map((row) => {
            const uiLink = stackHealthUiLink(row.component);
            const noUi = STACK_HEALTH_NO_UI.has(row.component);

            return (
              <div
                key={row.component}
                className="rounded-xl border border-surface-border/80 bg-surface/50 p-3 transition hover:border-surface-border"
              >
                <div className="flex items-start justify-between gap-2">
                  <p className="text-xs font-medium capitalize text-text-primary">
                    {row.component.replace(/_/g, " ")}
                  </p>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <Badge variant={badgeVariant(row.status)}>{formatStatus(row.status)}</Badge>
                    {uiLink ? (
                      <a
                        href={uiLink.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        title={`SSH tunnel: -L ${uiLink.tunnelPort}:${uiLink.tunnelPort}`}
                        className="inline-flex items-center gap-1 text-[10px] font-medium text-accent transition hover:text-accent-muted"
                      >
                        Open
                        <ExternalLinkIcon />
                      </a>
                    ) : noUi ? (
                      <span className="text-[10px] text-text-muted">no UI</span>
                    ) : null}
                  </div>
                </div>
                <p className="mt-1 text-[10px] text-text-muted">{row.role}</p>
                <p className="mt-2 line-clamp-2 text-[11px] leading-snug text-text-secondary">
                  {row.detail}
                </p>
                {row.row_count > 0 ? (
                  <p className="mt-2 text-sm font-semibold tabular-nums text-text-primary">
                    {formatInteger(row.row_count)}
                    <span className="ml-1 text-[10px] font-normal text-text-muted">
                      rows / {hours}h
                    </span>
                  </p>
                ) : null}
              </div>
            );
          })}
        </div>
        <p className="text-[10px] leading-relaxed text-text-muted">
          Open links use localhost and require the matching SSH tunnel (for example{" "}
          <code className="rounded bg-surface-overlay/60 px-1 py-0.5 font-mono text-[9px]">
            ssh -L 3000:localhost:3000 lab
          </code>
          ).
        </p>
      </div>
    </MetricFrame>
  );
}
