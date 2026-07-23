"use client";

import { useCallback, useEffect, useState } from "react";
import { grafanaBaseUrl, grafanaDashboardEmbedUrl } from "@/lib/grafana-embed";
import { cn } from "@/lib/utils";

const LOAD_TIMEOUT_MS = 12000;

export function EmbeddedGrafana({
  dashboardUid,
  title,
  caption,
  minHeight = 360,
  className,
}: {
  dashboardUid: string;
  title: string;
  caption?: string;
  minHeight?: number;
  className?: string;
}) {
  const baseUrl = grafanaBaseUrl();
  const embedUrl = grafanaDashboardEmbedUrl(dashboardUid);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "error">("loading");

  const markReady = useCallback(() => {
    setLoadState("ready");
  }, []);

  const markError = useCallback(() => {
    setLoadState("error");
  }, []);

  useEffect(() => {
    if (!embedUrl) return;
    setLoadState("loading");
    const timer = window.setTimeout(() => {
      setLoadState((current) => (current === "loading" ? "error" : current));
    }, LOAD_TIMEOUT_MS);
    return () => window.clearTimeout(timer);
  }, [embedUrl]);

  if (!baseUrl || !embedUrl) {
    return (
      <div
        className={cn(
          "rounded-xl border border-dashed border-surface-border bg-surface-raised/40 p-5",
          className,
        )}
      >
        <h4 className="text-sm font-semibold text-text-primary">{title}</h4>
        {caption ? <p className="mt-1 text-xs text-text-muted">{caption}</p> : null}
        <div
          className="mt-4 flex flex-col items-center justify-center rounded-lg border border-surface-border/80 bg-surface/50 px-4 py-8 text-center"
          style={{ minHeight: Math.min(minHeight, 220) }}
        >
          <p className="text-sm font-medium text-text-secondary">Grafana dashboards not configured</p>
          <p className="mt-2 max-w-md text-xs leading-relaxed text-text-muted">
            Set{" "}
            <code className="rounded bg-surface-overlay px-1.5 py-0.5 font-mono text-[10px] text-accent">
              NEXT_PUBLIC_GRAFANA_URL
            </code>{" "}
            to your Grafana origin (for example{" "}
            <code className="font-mono text-[10px]">https://grafana.ngn-sip.lab</code> behind the
            Caddy proxy). Dashboard UIDs are defined in{" "}
            <code className="font-mono text-[10px]">lib/grafana-embed.ts</code>.
          </p>
          <p className="mt-3 text-[10px] text-text-muted">
            Grafana must allow iframe embedding (anonymous viewer or auth cookie on the same site).
          </p>
        </div>
      </div>
    );
  }

  return (
    <div
      className={cn(
        "flex min-w-0 flex-col overflow-hidden rounded-xl border border-surface-border bg-surface-raised/60 shadow-card",
        className,
      )}
    >
      <div className="shrink-0 border-b border-surface-border/80 px-4 py-3">
        <h4 className="text-sm font-semibold text-text-primary">{title}</h4>
        {caption ? <p className="mt-0.5 text-xs text-text-muted">{caption}</p> : null}
      </div>

      <div
        className="relative w-full min-w-0 shrink-0 overflow-hidden bg-surface/40"
        style={{ minHeight }}
      >
        {loadState === "loading" ? (
          <div className="absolute inset-0 flex items-center justify-center bg-surface/60" aria-busy="true">
            <div className="h-6 w-6 animate-spin rounded-full border-2 border-surface-border border-t-accent" />
          </div>
        ) : null}

        {loadState === "error" ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-surface/90 px-4 text-center">
            <p className="text-xs font-medium text-text-secondary">Dashboard unavailable</p>
            <p className="max-w-xs text-[10px] leading-relaxed text-text-muted">
              Check the dashboard UID in lib/grafana-embed.ts, Grafana embed settings, and that you
              are signed in to Grafana on this origin.
            </p>
            <a
              href={embedUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[10px] font-medium text-accent hover:text-accent-muted"
            >
              Open dashboard in Grafana
            </a>
          </div>
        ) : null}

        <iframe
          title={title}
          src={embedUrl}
          className={cn(
            "absolute inset-0 h-full w-full border-0 transition-opacity duration-300",
            loadState === "ready" ? "opacity-100" : "opacity-0",
          )}
          loading="lazy"
          sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
          referrerPolicy="no-referrer"
          onLoad={markReady}
          onError={markError}
        />
      </div>
    </div>
  );
}
