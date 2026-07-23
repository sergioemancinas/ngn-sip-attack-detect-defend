export const CHART_COLORS = [
  "#6366f1",
  "#22c55e",
  "#f59e0b",
  "#ef4444",
  "#a855f7",
  "#38bdf8",
  "#fb923c",
] as const;

export const CHART_AXIS = {
  tick: { fill: "#94a3b8", fontSize: 11 },
  stroke: "#334155",
};

export const CHART_GRID = {
  strokeDasharray: "3 3",
  stroke: "#1e293b",
  vertical: false,
};

export const CHART_TOOLTIP = {
  contentStyle: {
    background: "#0f172a",
    border: "1px solid #334155",
    borderRadius: 10,
    fontSize: 12,
    boxShadow: "0 8px 24px rgba(0,0,0,0.35)",
  },
  labelStyle: { color: "#e2e8f0" },
  itemStyle: { color: "#cbd5e1" },
};

export const CHART_LEGEND = {
  wrapperStyle: { fontSize: 11, color: "#94a3b8" },
};

export const VERDICT_COLORS: Record<string, string> = {
  benign: "#22c55e",
  malicious: "#ef4444",
  suspicious: "#f59e0b",
  credentials: "#ef4444",
  recon: "#f59e0b",
  injection: "#a855f7",
  dos: "#fb923c",
  attack: "#ef4444",
  needs_review: "#38bdf8",
};

export function verdictColor(label: string, index = 0): string {
  return VERDICT_COLORS[label.toLowerCase()] ?? CHART_COLORS[index % CHART_COLORS.length];
}
