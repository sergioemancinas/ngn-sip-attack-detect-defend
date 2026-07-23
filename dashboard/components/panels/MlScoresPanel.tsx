"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartContainer } from "@/components/charts/ChartContainer";
import { LowDataBanner } from "@/components/charts/LowDataBanner";
import { MetricFrame, useMetric } from "@/components/hooks/useMetric";
import { EmptyState } from "@/components/ui/States";
import {
  CHART_AXIS,
  CHART_GRID,
  CHART_LEGEND,
  CHART_TOOLTIP,
  verdictColor,
} from "@/lib/chart-theme";
import { formatInteger, isSparseData, coerceCount, formatBucketTime } from "@/lib/chart-utils";

export function MlScoresPanel({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { data, loading, error, empty, meta } = useMetric<{
    bucket: string;
    predicted_class: string;
    avg_proba: number;
    score_count: number;
  }>("ml-scores", hours, refreshMs);

  if (meta?.table_missing) {
    return (
      <EmptyState message="ml_scores table not present (Stage 1 scorer not deployed)" />
    );
  }

  const rows = data ?? [];
  const classes = [...new Set(rows.map((row) => String(row?.predicted_class ?? "unknown")))];
  const buckets = new Map<string, Record<string, number | string>>();
  let totalScores = 0;

  for (const row of rows) {
    totalScores += coerceCount(row?.score_count);
    const bucketKey = String(row?.bucket ?? "");
    const existing = buckets.get(bucketKey) ?? {
      bucket: bucketKey,
      time: formatBucketTime(bucketKey),
    };
    const cls = String(row?.predicted_class ?? "unknown");
    existing[cls] = coerceCount(row?.avg_proba);
    buckets.set(bucketKey, existing);
  }

  const chartData = Array.from(buckets.values()).sort(
    (a, b) => new Date(String(a.bucket)).getTime() - new Date(String(b.bucket)).getTime(),
  );

  const classTotals = classes.map((cls) => ({
    class: cls,
    total: rows
      .filter((row) => String(row?.predicted_class ?? "") === cls)
      .reduce((sum, row) => sum + coerceCount(row?.score_count), 0),
  }));

  const sparse = isSparseData(chartData.length, 3);

  return (
    <MetricFrame loading={loading} error={error} empty={empty || rows.length === 0}>
      {sparse ? (
        <LowDataBanner
          count={totalScores}
          unit="scored windows"
          detail={`${formatInteger(chartData.length)} bucket${chartData.length === 1 ? "" : "s"} · ${formatInteger(classes.length)} class${classes.length === 1 ? "" : "es"}`}
        />
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          {chartData.length <= 2 ? (
            <ChartContainer height={220}>
              <BarChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid {...CHART_GRID} />
                <XAxis dataKey="time" tick={CHART_AXIS.tick} stroke={CHART_AXIS.stroke} />
                <YAxis domain={[0, 1]} tick={CHART_AXIS.tick} stroke={CHART_AXIS.stroke} width={36} />
                <Tooltip {...CHART_TOOLTIP} />
                <Legend {...CHART_LEGEND} />
                {classes.map((cls, index) => (
                  <Bar
                    key={cls}
                    dataKey={cls}
                    name={cls}
                    fill={verdictColor(cls, index)}
                    radius={[4, 4, 0, 0]}
                    stackId="proba"
                  />
                ))}
              </BarChart>
            </ChartContainer>
          ) : (
            <ChartContainer height={220}>
              <LineChart data={chartData}>
                <CartesianGrid {...CHART_GRID} />
                <XAxis dataKey="time" tick={CHART_AXIS.tick} stroke={CHART_AXIS.stroke} />
                <YAxis domain={[0, 1]} tick={CHART_AXIS.tick} stroke={CHART_AXIS.stroke} width={36} />
                <Tooltip {...CHART_TOOLTIP} />
                <Legend {...CHART_LEGEND} />
                {classes.map((cls, index) => (
                  <Line
                    key={cls}
                    type="monotone"
                    dataKey={cls}
                    name={cls}
                    stroke={verdictColor(cls, index)}
                    dot={{ r: chartData.length <= 6 ? 3 : 0 }}
                    strokeWidth={2}
                  />
                ))}
              </LineChart>
            </ChartContainer>
          )}
        </div>

        <div>
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-text-muted">
            By predicted class
          </p>
          <ChartContainer height={220}>
            <BarChart data={classTotals} layout="vertical" margin={{ left: 4, right: 8 }}>
              <CartesianGrid {...CHART_GRID} horizontal={false} />
              <XAxis type="number" tick={CHART_AXIS.tick} stroke={CHART_AXIS.stroke} allowDecimals={false} />
              <YAxis
                type="category"
                dataKey="class"
                tick={CHART_AXIS.tick}
                stroke={CHART_AXIS.stroke}
                width={72}
              />
              <Tooltip
                {...CHART_TOOLTIP}
                formatter={(value: number) => [value.toLocaleString(), "Windows"]}
              />
              <Bar dataKey="total" name="Windows" radius={[0, 4, 4, 0]} maxBarSize={20}>
                {classTotals.map((row, index) => (
                  <Cell key={row.class} fill={verdictColor(row.class, index)} />
                ))}
              </Bar>
            </BarChart>
          </ChartContainer>
        </div>
      </div>

    </MetricFrame>
  );
}
