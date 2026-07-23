"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartContainer } from "@/components/charts/ChartContainer";
import { LowDataBanner } from "@/components/charts/LowDataBanner";
import { MetricFrame, useMetric } from "@/components/hooks/useMetric";
import { Badge } from "@/components/ui/Badge";
import { CHART_AXIS, CHART_COLORS, CHART_GRID, CHART_TOOLTIP } from "@/lib/chart-theme";
import { coerceCount, formatInteger, isSparseData } from "@/lib/chart-utils";
import type { TopSourceRow } from "@/types/layout";

function normalizeTopSourceRow(row: TopSourceRow): TopSourceRow {
  return {
    src_ip: String(row?.src_ip ?? "unknown"),
    total: coerceCount(row?.total),
    is_labeled_attack: coerceCount(row?.is_labeled_attack),
    mitre_technique: String(row?.mitre_technique ?? ""),
    attack_id: String(row?.attack_id ?? ""),
    ban_count: coerceCount(row?.ban_count),
  };
}

export function TopSourcesPanel({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { data, loading, error, empty } = useMetric<TopSourceRow>("top-sources", hours, refreshMs);

  const rows = (data ?? []).map(normalizeTopSourceRow).filter((row) => row.src_ip !== "unknown" || row.total > 0);

  const chartRows = rows.slice(0, 10).map((row) => ({
    ip: row.src_ip,
    shortIp: row.src_ip.length > 14 ? `${row.src_ip.slice(0, 12)}…` : row.src_ip,
    total: row.total,
    attack: row.is_labeled_attack > 0,
  }));

  const sparse = isSparseData(rows.length, 3);

  return (
    <MetricFrame loading={loading} error={error} empty={empty || rows.length === 0}>
      {sparse ? (
        <LowDataBanner
          count={rows.reduce((sum, row) => sum + row.total, 0)}
          unit={`source ${rows.length === 1 ? "IP" : "IPs"}`}
          detail={`top volume ${formatInteger(rows[0]?.total)} events`}
        />
      ) : null}

      <ChartContainer height={Math.max(160, chartRows.length * 28 + 40)}>
        <BarChart data={chartRows} layout="vertical" margin={{ left: 4, right: 12, top: 4, bottom: 4 }}>
          <CartesianGrid {...CHART_GRID} horizontal={false} />
          <XAxis type="number" tick={CHART_AXIS.tick} stroke={CHART_AXIS.stroke} />
          <YAxis
            type="category"
            dataKey="shortIp"
            tick={CHART_AXIS.tick}
            stroke={CHART_AXIS.stroke}
            width={88}
          />
          <Tooltip
            {...CHART_TOOLTIP}
            formatter={(value: number) => [value.toLocaleString(), "Events"]}
            labelFormatter={(_label, payload) => {
              const row = payload?.[0]?.payload as { ip?: string } | undefined;
              return row?.ip ?? "Source IP";
            }}
          />
          <Bar dataKey="total" name="Events" radius={[0, 4, 4, 0]} maxBarSize={22}>
            {chartRows.map((row, index) => (
              <Cell
                key={row.ip}
                fill={row.attack ? "#ef4444" : CHART_COLORS[index % CHART_COLORS.length]}
              />
            ))}
          </Bar>
        </BarChart>
      </ChartContainer>

      <div className="mt-4 max-h-[220px] overflow-auto rounded-lg border border-surface-border/70">
        <table className="data-table">
          <thead>
            <tr>
              <th>Source IP</th>
              <th className="numeric">Volume</th>
              <th>Flags</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.src_ip}>
                <td className="mono">{row.src_ip}</td>
                <td className="numeric">{formatInteger(row.total)}</td>
                <td>
                  <div className="flex flex-wrap gap-1">
                    {row.is_labeled_attack ? (
                      <Badge variant="attack">{row.mitre_technique || "labeled"}</Badge>
                    ) : null}
                    {row.ban_count > 0 ? <Badge variant="ban">banned</Badge> : null}
                    {!row.is_labeled_attack && row.ban_count === 0 ? (
                      <Badge variant="benign">benign</Badge>
                    ) : null}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </MetricFrame>
  );
}
