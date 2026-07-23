"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartContainer } from "@/components/charts/ChartContainer";
import { Badge } from "@/components/ui/Badge";
import { C3_CAMPAIGN_DATE, C3_PRIMARY_ARMS, C3_TAKEAWAY } from "@/lib/c3-metrics";
import { CHART_AXIS, CHART_GRID, CHART_LEGEND, CHART_TOOLTIP } from "@/lib/chart-theme";
import { formatPercent } from "@/lib/chart-utils";
import { XGBOOST_GROUPED_CV } from "@/lib/stage1-metrics";

const CHART_ROWS = C3_PRIMARY_ARMS.map((arm) => ({
  arm: arm.name,
  recall: arm.recall,
  fpRate: arm.fpRate,
  f1: arm.f1,
}));

export function C3SummaryPanel() {
  return (
    <div className="flex h-full flex-col gap-5 text-sm">
      <div className="rounded-xl border border-accent-green/35 bg-accent-green/5 p-4">
        <Badge variant="healthy">Current honest result</Badge>
        <p className="mt-3 text-3xl font-semibold tabular-nums text-text-primary">
          Binary F1 {formatPercent(XGBOOST_GROUPED_CV.oofBinaryF1, 2)}
        </p>
        <p className="mt-1 text-xs text-text-muted">
          95% CI [{formatPercent(XGBOOST_GROUPED_CV.oofF1Ci.lo, 2)},{" "}
          {formatPercent(XGBOOST_GROUPED_CV.oofF1Ci.hi, 2)}] · leakage-free grouped CV by source IP
        </p>
        <p className="mt-3 text-xs leading-relaxed text-text-secondary">
          Defensible operating point for reported and production claims. Source:{" "}
          docs/results/RESULTS_stage1_grouped_2026-06-10.md
        </p>
      </div>

      <div className="rounded-xl border border-surface-border bg-surface/40 p-4">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">
              C3 three-arm comparison
            </p>
            <p className="mt-1 text-xs text-text-muted">
              Same labeled campaign ({C3_CAMPAIGN_DATE}) · source-IP level scoring
            </p>
          </div>
          <Badge variant="info">Static eval</Badge>
        </div>

        <div className="mt-4 overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Arm</th>
                <th>Paradigm</th>
                <th className="numeric">Recall</th>
                <th className="numeric">FP rate</th>
                <th className="numeric">F1</th>
              </tr>
            </thead>
            <tbody>
              {C3_PRIMARY_ARMS.map((arm) => (
                <tr key={arm.id}>
                  <td className="font-medium text-text-primary">{arm.name}</td>
                  <td className="text-text-secondary">{arm.paradigm}</td>
                  <td className="numeric">{formatPercent(arm.recall, 2)}</td>
                  <td className="numeric">{formatPercent(arm.fpRate, 2)}</td>
                  <td className="numeric font-semibold">{formatPercent(arm.f1, 2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <ChartContainer height={220}>
          <BarChart data={CHART_ROWS} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid {...CHART_GRID} />
            <XAxis dataKey="arm" tick={CHART_AXIS.tick} stroke={CHART_AXIS.stroke} />
            <YAxis
              domain={[0, 1.05]}
              tick={CHART_AXIS.tick}
              stroke={CHART_AXIS.stroke}
              width={36}
              tickFormatter={(value) => formatPercent(Number(value), 2)}
            />
            <Tooltip
              {...CHART_TOOLTIP}
              formatter={(value: number, name: string) => [formatPercent(value, 2), name]}
            />
            <Legend {...CHART_LEGEND} />
            <Bar dataKey="recall" name="Recall" fill="#6366f1" radius={[4, 4, 0, 0]} maxBarSize={36} />
            <Bar dataKey="fpRate" name="FP rate" fill="#ef4444" radius={[4, 4, 0, 0]} maxBarSize={36} />
            <Bar dataKey="f1" name="F1" fill="#22c55e" radius={[4, 4, 0, 0]} maxBarSize={36} />
          </BarChart>
        </ChartContainer>

        <p className="mt-3 text-xs leading-relaxed text-text-secondary">{C3_TAKEAWAY}</p>
        <ul className="mt-2 space-y-1 text-[11px] text-text-muted">
          {C3_PRIMARY_ARMS.map((arm) => (
            <li key={arm.id}>
              <span className="font-medium text-text-secondary">{arm.name}:</span> {arm.note}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
