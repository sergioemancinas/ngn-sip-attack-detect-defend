"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartContainer } from "@/components/charts/ChartContainer";
import { LowDataBanner } from "@/components/charts/LowDataBanner";
import { MetricFrame, useMetric } from "@/components/hooks/useMetric";
import { Badge, severityVariant } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/States";
import {
  CHART_AXIS,
  CHART_GRID,
  CHART_LEGEND,
  CHART_TOOLTIP,
  verdictColor,
} from "@/lib/chart-theme";
import {
  coerceCount,
  formatBucketTime,
  formatConfidence,
  formatInteger,
  isSparseData,
  padSparseSeries,
} from "@/lib/chart-utils";
import {
  parseLlmVerdictRecent,
  parseVerdictSummary,
  type VerdictSummaryRow,
} from "@/types/layout";

const VERDICT_ORDER = ["benign", "suspicious", "malicious", "needs_review"] as const;

function orderVerdicts(rows: VerdictSummaryRow[]): VerdictSummaryRow[] {
  const byVerdict = new Map(rows.map((row) => [row.verdict.toLowerCase(), row]));
  const ordered = VERDICT_ORDER.map((key) => byVerdict.get(key)).filter(
    (row): row is VerdictSummaryRow => row != null,
  );
  for (const row of rows) {
    if (!VERDICT_ORDER.includes(row.verdict.toLowerCase() as (typeof VERDICT_ORDER)[number])) {
      ordered.push(row);
    }
  }
  return ordered;
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function safeConfidence(value: unknown): number | null {
  const n = coerceCount(value);
  if (!Number.isFinite(n)) return null;
  return n;
}

export function LlmVerdictsPanel({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { data, loading, error, empty, meta } = useMetric<{
    bucket: string;
    verdict: string;
    avg_confidence: number;
    verdict_count: number;
  }>("llm-verdicts", hours, refreshMs, { limit: "12" });

  if (meta?.table_missing) {
    return <EmptyState message="llm_verdicts table not present (Stage 2 worker not deployed)" />;
  }

  const seriesRows = data ?? [];
  const summary = orderVerdicts(parseVerdictSummary(meta));
  const recent = parseLlmVerdictRecent(meta);
  const totalVerdicts = summary.reduce((sum, row) => sum + coerceCount(row.verdict_count), 0);
  const verdicts = summary.map((row) => row.verdict);

  const distribution = summary.map((row, index) => ({
    verdict: row.verdict,
    count: coerceCount(row.verdict_count),
    fill: verdictColor(row.verdict, index),
  }));

  const bucketMap = new Map<string, Record<string, number | string>>();
  for (const row of seriesRows) {
    const bucketKey = String(row?.bucket ?? "");
    if (!bucketKey) continue;
    const existing = bucketMap.get(bucketKey) ?? {
      bucket: bucketKey,
      time: formatBucketTime(bucketKey),
      total: 0,
    };
    const verdict = String(row?.verdict ?? "unknown");
    const count = coerceCount(row?.verdict_count);
    existing[verdict] = count;
    existing.total = coerceCount(existing.total) + count;
    bucketMap.set(bucketKey, existing);
  }

  let timelineData = Array.from(bucketMap.values()).sort(
    (a, b) => new Date(String(a.bucket)).getTime() - new Date(String(b.bucket)).getTime(),
  );
  if (timelineData.length === 1) {
    timelineData = padSparseSeries(
      timelineData.map((row) => ({
        bucket: String(row.bucket),
        time: String(row.time),
        value: coerceCount(row.total),
      })),
    ).map((point) => {
      const original = bucketMap.get(point.bucket);
      return original ?? { bucket: point.bucket, time: point.time, total: point.value };
    });
  }

  const sparse = isSparseData(timelineData.length, 3) || totalVerdicts < 10;
  const singleVerdict = verdicts.length === 1;
  const hasData = totalVerdicts > 0 || recent.length > 0;

  return (
    <MetricFrame loading={loading} error={error} empty={empty && !hasData}>
      {totalVerdicts === 0 ? (
        <EmptyState message="No LLM verdicts in the selected window. Stage 2 runs on high-severity Wazuh alerts." />
      ) : (
        <>
          <div className="mb-4 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-surface-border bg-surface/40 px-3 py-2 text-xs">
            <span className="text-text-secondary">
              <span className="font-semibold tabular-nums text-text-primary">
                {formatInteger(totalVerdicts)}
              </span>{" "}
              LLM verdict{totalVerdicts === 1 ? "" : "s"} in window
            </span>
            {sparse ? (
              <span className="text-text-muted">
                Low volume: counts and single-bucket timeline (no broken axis)
              </span>
            ) : null}
          </div>

          {sparse ? (
            <LowDataBanner
              count={totalVerdicts}
              unit="verdicts"
              detail={`${formatInteger(timelineData.length)} bucket${timelineData.length === 1 ? "" : "s"} · ${formatInteger(verdicts.length)} verdict type${verdicts.length === 1 ? "" : "s"}`}
            />
          ) : null}

          <div className="grid gap-5 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
            <div className="space-y-4">
              <div>
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-text-muted">
                  Verdicts over time
                </p>
                {timelineData.length === 0 ? (
                  <p className="rounded-lg border border-surface-border bg-surface/40 px-3 py-6 text-center text-xs text-text-muted">
                    No time buckets in window. Summary counts below still reflect llm_verdicts.
                  </p>
                ) : singleVerdict && timelineData.length <= 2 ? (
                  <ChartContainer height={180}>
                    <BarChart
                      data={timelineData}
                      margin={{ top: 8, right: 8, left: 0, bottom: 0 }}
                    >
                      <CartesianGrid {...CHART_GRID} />
                      <XAxis dataKey="time" tick={CHART_AXIS.tick} stroke={CHART_AXIS.stroke} />
                      <YAxis
                        tick={CHART_AXIS.tick}
                        stroke={CHART_AXIS.stroke}
                        width={36}
                        allowDecimals={false}
                        domain={[0, Math.max(totalVerdicts, 1)]}
                      />
                      <Tooltip
                        {...CHART_TOOLTIP}
                        formatter={(value: number) => [formatInteger(value), verdicts[0] ?? "count"]}
                      />
                      <Bar
                        dataKey={verdicts[0] ?? "total"}
                        name={verdicts[0] ?? "count"}
                        fill={verdictColor(verdicts[0] ?? "unknown", 0)}
                        radius={[4, 4, 0, 0]}
                        maxBarSize={48}
                      />
                    </BarChart>
                  </ChartContainer>
                ) : (
                  <ChartContainer height={220}>
                    <BarChart
                      data={timelineData}
                      margin={{ top: 8, right: 8, left: 0, bottom: 0 }}
                    >
                      <CartesianGrid {...CHART_GRID} />
                      <XAxis dataKey="time" tick={CHART_AXIS.tick} stroke={CHART_AXIS.stroke} />
                      <YAxis
                        tick={CHART_AXIS.tick}
                        stroke={CHART_AXIS.stroke}
                        width={36}
                        allowDecimals={false}
                        domain={[0, "auto"]}
                      />
                      <Tooltip
                        {...CHART_TOOLTIP}
                        formatter={(value: number, name: string) => [formatInteger(value), name]}
                      />
                      <Legend {...CHART_LEGEND} />
                      {verdicts.map((verdict, index) => (
                        <Bar
                          key={verdict}
                          dataKey={verdict}
                          name={verdict}
                          stackId="verdicts"
                          fill={verdictColor(verdict, index)}
                          maxBarSize={32}
                        />
                      ))}
                    </BarChart>
                  </ChartContainer>
                )}
              </div>

              <div>
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-text-muted">
                  Verdict distribution
                </p>
                <ChartContainer height={Math.max(120, distribution.length * 36 + 24)}>
                  <BarChart
                    data={distribution}
                    layout="vertical"
                    margin={{ left: 4, right: 16, top: 4, bottom: 4 }}
                  >
                    <CartesianGrid {...CHART_GRID} horizontal={false} />
                    <XAxis
                      type="number"
                      tick={CHART_AXIS.tick}
                      stroke={CHART_AXIS.stroke}
                      allowDecimals={false}
                      domain={[0, Math.max(totalVerdicts, 1)]}
                    />
                    <YAxis
                      type="category"
                      dataKey="verdict"
                      tick={CHART_AXIS.tick}
                      stroke={CHART_AXIS.stroke}
                      width={88}
                    />
                    <Tooltip
                      {...CHART_TOOLTIP}
                      formatter={(value: number, name: string) => [
                        `${formatInteger(value)} (${totalVerdicts > 0 ? Math.round((value / totalVerdicts) * 100) : 0}%)`,
                        name,
                      ]}
                    />
                    <Bar dataKey="count" name="Count" radius={[0, 4, 4, 0]} maxBarSize={22}>
                      {distribution.map((row) => (
                        <Cell key={row.verdict} fill={row.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </ChartContainer>
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-text-muted">
                  Avg confidence by verdict
                </p>
                <div className="overflow-x-auto rounded-lg border border-surface-border/70">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Verdict</th>
                        <th className="numeric">Count</th>
                        <th className="numeric">Avg conf.</th>
                      </tr>
                    </thead>
                    <tbody>
                      {summary.map((row) => {
                        const conf = safeConfidence(row.avg_confidence);
                        return (
                          <tr key={row.verdict}>
                            <td>
                              <Badge variant={severityVariant(row.verdict)}>{row.verdict}</Badge>
                            </td>
                            <td className="numeric">{formatInteger(row.verdict_count)}</td>
                            <td className="numeric font-mono">
                              {conf == null ? "n/a" : formatConfidence(conf, 1)}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              <div>
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-text-muted">
                  Recent verdicts
                </p>
                {recent.length === 0 ? (
                  <p className="text-xs text-text-muted">No recent rows returned.</p>
                ) : (
                  <div className="max-h-[220px] space-y-2 overflow-auto pr-1">
                    {recent.map((row, index) => (
                      <div
                        key={`${row.verdict_time}-${row.src_ip}-${index}`}
                        className="flex items-start gap-2 rounded-lg border border-surface-border/70 bg-surface/40 px-3 py-2"
                      >
                        <span className="min-w-[68px] font-mono text-[10px] tabular-nums text-text-muted">
                          {formatTime(row.verdict_time)}
                        </span>
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge variant={severityVariant(row.verdict)}>{row.verdict}</Badge>
                            <span className="font-mono text-[10px] text-text-muted">
                              conf{" "}
                              {safeConfidence(row.confidence) == null
                                ? "n/a"
                                : formatConfidence(row.confidence, 1)}
                            </span>
                          </div>
                          <p className="mt-1 truncate text-xs text-text-secondary">
                            <span className="font-mono">{row.src_ip}</span>
                            {row.alert_rule_id ? (
                              <span className="text-text-muted"> · rule {row.alert_rule_id}</span>
                            ) : null}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </MetricFrame>
  );
}
