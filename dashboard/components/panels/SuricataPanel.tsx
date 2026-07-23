"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartContainer } from "@/components/charts/ChartContainer";
import { LowDataBanner } from "@/components/charts/LowDataBanner";
import { MetricFrame, useMetric } from "@/components/hooks/useMetric";
import { CHART_AXIS, CHART_GRID, CHART_TOOLTIP } from "@/lib/chart-theme";
import { isSparseData, normalizeTimeSeries, padSparseSeries, sumValues, coerceCount } from "@/lib/chart-utils";

export function SuricataPanel({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { data, loading, error, empty } = useMetric<{ bucket: string; alert_count: number }>(
    "suricata",
    hours,
    refreshMs,
  );

  const normalized = padSparseSeries(
    normalizeTimeSeries(
      (data ?? []).map((row) => ({
        bucket: String(row?.bucket ?? ""),
        value: coerceCount(row?.alert_count),
      })),
      hours <= 6 ? 12 : 24,
    ),
  );

  const totalAlerts = sumValues((data ?? []).map((row) => ({ value: row?.alert_count })));
  const sparse = isSparseData((data ?? []).length, 3);

  return (
    <MetricFrame loading={loading} error={error} empty={empty || data.length === 0}>
      {sparse ? (
        <LowDataBanner
          count={totalAlerts}
          unit="Suricata alerts"
          detail={`${data.length} time ${data.length === 1 ? "bucket" : "buckets"} in window`}
        />
      ) : null}
      <ChartContainer height={220}>
        <BarChart data={normalized} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid {...CHART_GRID} />
          <XAxis
            dataKey="time"
            tick={CHART_AXIS.tick}
            stroke={CHART_AXIS.stroke}
            interval={normalized.length <= 6 ? 0 : "preserveStartEnd"}
            angle={normalized.length > 8 ? -24 : 0}
            textAnchor={normalized.length > 8 ? "end" : "middle"}
            height={normalized.length > 8 ? 48 : 30}
          />
          <YAxis
            tick={CHART_AXIS.tick}
            stroke={CHART_AXIS.stroke}
            width={40}
            allowDecimals={false}
          />
          <Tooltip
            {...CHART_TOOLTIP}
            formatter={(value: number) => [value.toLocaleString(), "Alerts"]}
          />
          <Bar dataKey="value" name="Alerts" fill="#6366f1" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ChartContainer>
    </MetricFrame>
  );
}
