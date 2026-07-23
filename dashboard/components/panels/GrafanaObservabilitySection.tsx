"use client";

import { EmbeddedGrafana } from "@/components/grafana/EmbeddedGrafana";
import {
  GRAFANA_EMBED_DASHBOARDS,
  grafanaBaseUrl,
  isGrafanaEmbedConfigured,
} from "@/lib/grafana-embed";

export function GrafanaObservabilitySection({
  panelIds,
  title = "Grafana observability",
  description = "Full-dashboard kiosk embeds from provisioned D1-D7 dashboards. Set NEXT_PUBLIC_GRAFANA_URL to the Caddy-proxied Grafana origin (https://grafana.ngn-sip.lab).",
}: {
  panelIds?: string[];
  title?: string;
  description?: string;
}) {
  const dashboards = panelIds
    ? GRAFANA_EMBED_DASHBOARDS.filter((entry) => panelIds.includes(entry.id))
    : GRAFANA_EMBED_DASHBOARDS;

  const grafanaUrl = grafanaBaseUrl();
  const configured = isGrafanaEmbedConfigured();

  return (
    <div className="rounded-xl border border-surface-border bg-surface-raised/40 p-5 shadow-card">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
          <p className="mt-1 text-xs leading-relaxed text-text-muted">{description}</p>
          {configured ? (
            <p className="mt-2 text-[10px] text-text-muted">
              Embedding from{" "}
              <code className="rounded bg-surface-overlay px-1 py-0.5 font-mono text-accent">
                {grafanaUrl}
              </code>
              {" · "}
              kiosk mode · theme dark · last 6h
            </p>
          ) : null}
        </div>
        {configured && grafanaUrl ? (
          <a
            href={grafanaUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="shrink-0 rounded-lg border border-surface-border bg-surface px-3 py-1.5 text-xs font-medium text-text-secondary transition hover:border-accent/40 hover:text-accent"
          >
            Open Grafana
          </a>
        ) : null}
      </div>

      <div className="grid gap-4 sm:grid-cols-1 lg:grid-cols-2">
        {dashboards.map((entry) => (
          <EmbeddedGrafana
            key={entry.id}
            dashboardUid={entry.dashboardUid}
            title={entry.title}
            caption={entry.caption}
            minHeight={entry.minHeight}
          />
        ))}
      </div>
    </div>
  );
}
