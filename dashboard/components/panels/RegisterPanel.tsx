"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartContainer } from "@/components/charts/ChartContainer";
import { LowDataBanner } from "@/components/charts/LowDataBanner";
import { MetricFrame, useMetric } from "@/components/hooks/useMetric";
import { CHART_AXIS, CHART_GRID, CHART_LEGEND, CHART_TOOLTIP } from "@/lib/chart-theme";
import { formatBucketTime, formatInteger, isSparseData, sumValues, coerceCount } from "@/lib/chart-utils";

interface RegisterChartRow {
  bucket: string;
  time: string;
  success_count: number;
  auth_401_count: number;
}

export function RegisterPanel({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { data, loading, error, empty } = useMetric<{
    bucket: string;
    success_count: number;
    auth_401_count: number;
    total: number;
  }>("register", hours, refreshMs);

  let chartData: RegisterChartRow[] = (data ?? []).map((row) => ({
    bucket: String(row?.bucket ?? ""),
    time: formatBucketTime(String(row?.bucket ?? "")),
    success_count: coerceCount(row?.success_count),
    auth_401_count: coerceCount(row?.auth_401_count),
  }));

  if (chartData.length === 1) {
    const only = chartData[0];
    const anchor = new Date(only.bucket);
    const padBucket = Number.isNaN(anchor.getTime())
      ? only.bucket
      : new Date(anchor.getTime() - 5 * 60 * 1000).toISOString();
    chartData = [
      {
        bucket: padBucket,
        time: formatBucketTime(padBucket),
        success_count: 0,
        auth_401_count: 0,
      },
      only,
    ];
  }

  const total = sumValues((data ?? []).map((row) => ({ value: row?.total })));
  const sparse = isSparseData((data ?? []).length, 3);

  return (
    <MetricFrame loading={loading} error={error} empty={empty || data.length === 0}>
      {sparse ? (
        <LowDataBanner
          count={total}
          unit="REGISTER attempts"
          detail={`${data.length} time ${data.length === 1 ? "bucket" : "buckets"}`}
        />
      ) : null}
      <ChartContainer height={220}>
        <AreaChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid {...CHART_GRID} />
          <XAxis
            dataKey="time"
            tick={CHART_AXIS.tick}
            stroke={CHART_AXIS.stroke}
            interval={chartData.length <= 6 ? 0 : "preserveStartEnd"}
          />
          <YAxis tick={CHART_AXIS.tick} stroke={CHART_AXIS.stroke} width={40} allowDecimals={false} />
          <Tooltip {...CHART_TOOLTIP} />
          <Legend {...CHART_LEGEND} />
          <Area
            type="monotone"
            dataKey="success_count"
            stackId="1"
            stroke="#22c55e"
            fill="rgba(34, 197, 94, 0.2)"
            name="Success"
          />
          <Area
            type="monotone"
            dataKey="auth_401_count"
            stackId="2"
            stroke="#ef4444"
            fill="rgba(239, 68, 68, 0.18)"
            name="401/403"
          />
        </AreaChart>
      </ChartContainer>
    </MetricFrame>
  );
}
