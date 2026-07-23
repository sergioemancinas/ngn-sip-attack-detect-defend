export interface GrafanaDashboardSpec {
  id: string;
  title: string;
  caption: string;
  /** Provisioned Grafana dashboard UID (observability/grafana/provisioning/). */
  dashboardUid: string;
  minHeight?: number;
}

export const GRAFANA_EMBED_DEFAULTS = {
  orgId: 1,
  theme: "dark" as const,
  from: "now-6h",
  to: "now",
} as const;

/** Operator-editable dashboard list for kiosk iframe embeds. */
export const GRAFANA_EMBED_DASHBOARDS: GrafanaDashboardSpec[] = [
  {
    id: "sip-overview",
    title: "D1 SIP Overview",
    caption: "SIP alert rate and ingress health",
    dashboardUid: "d1-sip-overview",
    minHeight: 360,
  },
  {
    id: "attack-timeline",
    title: "D2 Attack Timeline",
    caption: "Labeled campaign timeline and attack phases",
    dashboardUid: "d2-attack-timeline",
    minHeight: 360,
  },
  {
    id: "suricata-rate",
    title: "D3 Suricata Detection",
    caption: "Signature hits and IDS alert rate",
    dashboardUid: "d3-suricata-detection",
    minHeight: 360,
  },
  {
    id: "attack-evidence",
    title: "D4 Attack Evidence",
    caption: "Correlated evidence and source drill-down",
    dashboardUid: "d4-attack-evidence",
    minHeight: 360,
  },
  {
    id: "system-health",
    title: "D5 System Health",
    caption: "Pipeline freshness and ClickHouse activity",
    dashboardUid: "d5-system-health",
    minHeight: 360,
  },
  {
    id: "mitre-coverage",
    title: "D6 MITRE Coverage",
    caption: "Detection technique coverage map",
    dashboardUid: "d6-mitre-coverage",
    minHeight: 360,
  },
  {
    id: "wazuh-sip",
    title: "D7 Wazuh SIP Correlation",
    caption: "Wazuh SIP rule hits and correlation",
    dashboardUid: "d7-wazuh-sip-correlation",
    minHeight: 360,
  },
];

/** @deprecated Use GRAFANA_EMBED_DASHBOARDS */
export const GRAFANA_EMBED_PANELS = GRAFANA_EMBED_DASHBOARDS;

export function grafanaBaseUrl(): string | null {
  const raw = process.env.NEXT_PUBLIC_GRAFANA_URL?.trim();
  if (!raw) return null;
  return raw.replace(/\/$/, "");
}

export function isGrafanaEmbedConfigured(): boolean {
  return grafanaBaseUrl() !== null;
}

export interface GrafanaEmbedOptions {
  orgId?: number;
  theme?: string;
  from?: string;
  to?: string;
}

export function grafanaDashboardEmbedUrl(
  dashboardUid: string,
  options: GrafanaEmbedOptions = {},
): string | null {
  const base = grafanaBaseUrl();
  if (!base || !dashboardUid.trim()) return null;

  const orgId = options.orgId ?? GRAFANA_EMBED_DEFAULTS.orgId;
  const theme = options.theme ?? GRAFANA_EMBED_DEFAULTS.theme;
  const from = options.from ?? GRAFANA_EMBED_DEFAULTS.from;
  const to = options.to ?? GRAFANA_EMBED_DEFAULTS.to;
  const uid = encodeURIComponent(dashboardUid.trim());

  return `${base}/d/${uid}?orgId=${orgId}&kiosk&theme=${encodeURIComponent(theme)}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
}
