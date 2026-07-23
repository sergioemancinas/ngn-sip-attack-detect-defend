export function coerceCount(value: unknown): number {
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : 0;
  }
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

/** Format integers without accidental string concatenation leading zeros. */
export function formatInteger(value: unknown): string {
  return coerceCount(value).toLocaleString("en-US", { maximumFractionDigits: 0 });
}

export function sumValues(rows: { value: unknown }[]): number {
  return rows.reduce((sum, row) => sum + coerceCount(row.value), 0);
}

export function sumField<T extends Record<string, unknown>>(rows: T[], field: keyof T): number {
  return rows.reduce((sum, row) => sum + coerceCount(row[field]), 0);
}

export function isSparseData(pointCount: number, threshold = 3): boolean {
  return pointCount > 0 && pointCount < threshold;
}

export function formatBucketTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export interface TimeBucketPoint {
  bucket: string;
  time: string;
  value: number;
}

/** Collapse or pass through time buckets so charts stay readable with sparse ingest. */
export function normalizeTimeSeries(
  rows: { bucket: string; value: number }[],
  maxBuckets = 24,
): TimeBucketPoint[] {
  if (rows.length === 0) return [];

  const sorted = [...rows].sort(
    (a, b) => new Date(a.bucket).getTime() - new Date(b.bucket).getTime(),
  );

  if (sorted.length <= maxBuckets) {
    return sorted.map((row) => ({
      bucket: row.bucket,
      time: formatBucketTime(row.bucket),
      value: row.value,
    }));
  }

  const groupSize = Math.ceil(sorted.length / maxBuckets);
  const buckets: TimeBucketPoint[] = [];

  for (let i = 0; i < sorted.length; i += groupSize) {
    const slice = sorted.slice(i, i + groupSize);
    const value = slice.reduce((sum, row) => sum + row.value, 0);
    const anchor = slice[0];
    buckets.push({
      bucket: anchor.bucket,
      time: formatBucketTime(anchor.bucket),
      value,
    });
  }

  return buckets;
}

/** Ensure at least two x-axis slots so a lone point does not collapse the axis. */
export function padSparseSeries(points: TimeBucketPoint[]): TimeBucketPoint[] {
  if (points.length !== 1) return points;
  const only = points[0];
  const anchor = new Date(only.bucket);
  const padTime = Number.isNaN(anchor.getTime())
    ? only.time
    : formatBucketTime(new Date(anchor.getTime() - 5 * 60 * 1000).toISOString());
  return [
    { bucket: only.bucket, time: padTime, value: 0 },
    only,
  ];
}

export function formatPercent(value: number, digits = 2): string {
  if (!Number.isFinite(value)) return "n/a";
  return value.toFixed(digits);
}

/** LLM confidence is stored as 0-1; display as a readable percentage without leading-zero string bugs. */
export function formatConfidence(value: unknown, digits = 1): string {
  const raw = coerceCount(value);
  if (!Number.isFinite(raw)) return "n/a";
  const pct = raw <= 1 && raw >= 0 ? raw * 100 : raw;
  return `${pct.toFixed(digits)}%`;
}

export function confusionHeatColor(count: number, max: number): string {
  if (count === 0 || max === 0) return "rgb(15 23 42 / 0.6)";
  const t = Math.min(1, count / max);
  const r = Math.round(30 + t * 200);
  const g = Math.round(40 + (1 - t) * 80);
  const b = Math.round(60 + (1 - t) * 100);
  return `rgb(${r} ${g} ${b})`;
}
