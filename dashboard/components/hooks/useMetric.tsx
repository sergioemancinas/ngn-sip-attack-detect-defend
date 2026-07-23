"use client";

import { useEffect, useState } from "react";
import type { MetricResponse } from "@/types/layout";
import { EmptyState, ErrorState, LoadingSpinner } from "@/components/ui/States";

function sanitizeMetricError(raw: unknown): string {
  if (typeof raw !== "string" || raw.trim() === "") {
    return "Request failed";
  }

  const trimmed = raw.trim();
  if (trimmed.startsWith("{") && trimmed.includes("exception")) {
    try {
      const parsed = JSON.parse(trimmed) as { exception?: string; message?: string };
      if (typeof parsed.exception === "string" && parsed.exception.trim()) {
        return parsed.exception.trim().slice(0, 240);
      }
      if (typeof parsed.message === "string" && parsed.message.trim()) {
        return parsed.message.trim().slice(0, 240);
      }
    } catch {
      // fall through to plain text
    }
  }

  return trimmed.slice(0, 240);
}

export function useMetric<T>(
  metric: string,
  hours: number,
  refreshMs: number,
  extraParams?: Record<string, string>,
  refetchNonce?: number,
) {
  const [state, setState] = useState<{
    data: T[];
    meta?: Record<string, unknown>;
    loading: boolean;
    error?: string;
    empty?: boolean;
    lastUpdated?: Date;
  }>({ data: [], loading: true });

  useEffect(() => {
    let cancelled = false;

    async function load() {
      const params = new URLSearchParams({
        metric,
        hours: String(hours),
        ...extraParams,
      });
      try {
        const res = await fetch(`/api/metrics?${params.toString()}`, {
          cache: "no-store",
        });
        const json = (await res.json()) as MetricResponse<T> & Record<string, unknown>;
        if (cancelled) return;
        if (!res.ok) {
          setState({
            data: [],
            loading: false,
            error: sanitizeMetricError(json.error),
            lastUpdated: new Date(),
          });
          return;
        }
        const { data, error, empty, ...rest } = json;
        const rows = Array.isArray(data) ? data : [];
        const hasRows = rows.length > 0;
        const hasMetaContent = Object.entries(rest).some(([key, value]) => {
          if (key === "hours" || key === "empty") return false;
          if (Array.isArray(value)) return value.length > 0;
          if (typeof value === "object" && value !== null) return Object.keys(value).length > 0;
          return value != null && value !== "";
        });
        setState({
          data: rows,
          meta: rest,
          loading: false,
          error:
            error && !hasRows && !hasMetaContent ? sanitizeMetricError(error) : undefined,
          empty: Boolean(empty) && !hasRows && !hasMetaContent,
          lastUpdated: new Date(),
        });
      } catch (err) {
        if (!cancelled) {
          setState({
            data: [],
            loading: false,
            error: sanitizeMetricError(err instanceof Error ? err.message : err),
            lastUpdated: new Date(),
          });
        }
      }
    }

    load();
    const timer = setInterval(load, refreshMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [metric, hours, refreshMs, extraParams ? JSON.stringify(extraParams) : "", refetchNonce ?? 0]);

  return state;
}

export function MetricFrame({
  loading,
  error,
  empty,
  children,
}: {
  loading: boolean;
  error?: string;
  empty?: boolean;
  children: React.ReactNode;
}) {
  if (loading) return <LoadingSpinner />;
  if (error) return <ErrorState message={error} />;
  if (empty) return <EmptyState />;
  return <>{children}</>;
}
