"use client";

import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
} from "recharts";
import { ChartContainer } from "@/components/charts/ChartContainer";
import { LowDataBanner } from "@/components/charts/LowDataBanner";
import { MetricFrame, useMetric } from "@/components/hooks/useMetric";
import { CHART_COLORS, CHART_LEGEND, CHART_TOOLTIP } from "@/lib/chart-theme";
import { coerceCount, isSparseData, sumValues } from "@/lib/chart-utils";

export function SipResponsesPanel({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { data, loading, error, empty } = useMetric<{ label: string; value: number }>(
    "sip-responses",
    hours,
    refreshMs,
  );

  const rows = (data ?? [])
    .map((row) => ({ label: String(row?.label ?? "unknown"), value: coerceCount(row?.value) }))
    .filter((row) => row.value > 0);
  const total = sumValues(rows);
  const sparse = isSparseData(rows.length, 2) || total < 10;

  return (
    <MetricFrame loading={loading} error={error} empty={empty || rows.length === 0}>
      {sparse ? (
        <LowDataBanner
          count={total}
          unit="SIP events"
          detail={`${rows.length} response ${rows.length === 1 ? "category" : "categories"} in window`}
        />
      ) : null}
      <div className="relative">
        <ChartContainer height={rows.length === 1 ? 200 : 220}>
          <PieChart>
            <Pie
              data={rows}
              dataKey="value"
              nameKey="label"
              innerRadius={rows.length === 1 ? "58%" : "52%"}
              outerRadius="78%"
              paddingAngle={rows.length > 1 ? 2 : 0}
              stroke="transparent"
              startAngle={90}
              endAngle={-270}
            >
              {rows.map((entry, index) => (
                <Cell key={entry.label} fill={CHART_COLORS[index % CHART_COLORS.length]} />
              ))}
            </Pie>
            <Tooltip
              {...CHART_TOOLTIP}
              formatter={(value: number, name: string) => [
                `${value.toLocaleString()} (${total > 0 ? Math.round((value / total) * 100) : 0}%)`,
                name,
              ]}
            />
            <Legend {...CHART_LEGEND} />
          </PieChart>
        </ChartContainer>
        {rows.length === 1 ? (
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center pt-2">
            <p className="text-2xl font-semibold tabular-nums text-text-primary">
              {rows[0].value.toLocaleString()}
            </p>
            <p className="max-w-[8rem] truncate text-center text-[10px] text-text-muted">
              {rows[0].label}
            </p>
          </div>
        ) : null}
      </div>
    </MetricFrame>
  );
}
