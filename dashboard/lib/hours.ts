export function parseHours(raw: string | null): number {
  const n = Number.parseInt(raw ?? "24", 10);
  if (!Number.isFinite(n) || n < 1) return 24;
  return Math.min(n, 168);
}

export function parseGroupBy(raw: string | null): "src_ip" | "response_code" {
  return raw === "response_code" ? "response_code" : "src_ip";
}

export function parseLimit(raw: string | null, fallback = 20, max = 100): number {
  const n = Number.parseInt(raw ?? String(fallback), 10);
  if (!Number.isFinite(n) || n < 1) return fallback;
  return Math.min(n, max);
}
