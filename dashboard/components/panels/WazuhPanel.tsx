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
import { formatInteger, isSparseData, coerceCount, sumField } from "@/lib/chart-utils";
import {
  parseWazuhAgentSummary,
  parseWazuhMitre,
  parseWazuhRecent,
} from "@/types/layout";

const FALLBACK_AGENT = {
  agent_id: "001",
  agent_name: "sip-lab-host",
};

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function WazuhPanel({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { data, loading, error, empty, meta } = useMetric<{
    rule_id: number;
    rule_description: string;
    max_level: number;
    hit_count: number;
  }>("wazuh", hours, refreshMs, { limit: "12" });

  const rows = data ?? [];
  const chartData = rows.slice(0, 12).map((row) => ({
    name: String(row?.rule_id ?? ""),
    hits: coerceCount(row?.hit_count),
    level: coerceCount(row?.max_level),
    description: String(row?.rule_description ?? ""),
  }));

  const agentFromDb = parseWazuhAgentSummary(meta);
  const agent = agentFromDb ?? {
    ...FALLBACK_AGENT,
    alert_count: sumField(rows, "hit_count"),
  };
  const mitre = parseWazuhMitre(meta);
  const recent = parseWazuhRecent(meta);
  const totalHits = sumField(rows, "hit_count");
  const sparse = isSparseData(chartData.length, 2);

  return (
    <MetricFrame loading={loading} error={error} empty={empty && chartData.length === 0 && recent.length === 0}>
      <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-lg border border-surface-border bg-surface/50 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">Agent</p>
          <p className="mt-1 font-mono text-sm text-text-primary">{agent.agent_name}</p>
          <p className="text-[10px] text-text-muted">id {agent.agent_id}</p>
        </div>
        <div className="rounded-lg border border-surface-border bg-surface/50 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">SIP rule hits</p>
          <p className="mt-1 text-2xl font-semibold tabular-nums text-text-primary">
            {formatInteger(totalHits)}
          </p>
        </div>
        <div className="rounded-lg border border-surface-border bg-surface/50 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">Distinct rules</p>
          <p className="mt-1 text-2xl font-semibold tabular-nums text-text-primary">
            {formatInteger(rows.length)}
          </p>
        </div>
        <div className="rounded-lg border border-surface-border bg-surface/50 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">MITRE techniques</p>
          <p className="mt-1 text-2xl font-semibold tabular-nums text-text-primary">
            {formatInteger(mitre.length)}
          </p>
        </div>
      </div>

      {!agentFromDb ? (
        <p className="mb-3 text-xs text-text-muted">
          Agent identity from lab config (sip-lab-host, id 001). NGN-SEC logs reach the manager via
          localfile ingest, not a deployed Wazuh agent.
        </p>
      ) : null}

      {sparse ? (
        <LowDataBanner
          count={totalHits}
          unit="rule hits"
          detail={`${formatInteger(chartData.length)} SIP rule${chartData.length === 1 ? "" : "s"} fired`}
        />
      ) : null}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <div>
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-text-muted">
            Rule breakdown (100100-100199)
          </p>
          {chartData.length === 0 ? (
            <p className="text-xs text-text-muted">No SIP rule hits in window.</p>
          ) : (
            <ChartContainer height={Math.max(180, chartData.length * 30 + 48)}>
              <BarChart
                data={chartData}
                layout="vertical"
                margin={{ left: 8, right: 16, top: 8, bottom: 8 }}
              >
                <CartesianGrid {...CHART_GRID} horizontal={false} />
                <XAxis
                  type="number"
                  tick={CHART_AXIS.tick}
                  stroke={CHART_AXIS.stroke}
                  allowDecimals={false}
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  tick={CHART_AXIS.tick}
                  stroke={CHART_AXIS.stroke}
                  width={52}
                />
                <Tooltip
                  {...CHART_TOOLTIP}
                  formatter={(value: number, _name, item) => {
                    const payload = item?.payload as { description?: string; level?: number } | undefined;
                    const level = payload?.level != null ? ` · level ${payload.level}` : "";
                    return [`${formatInteger(value)} hits${level}`, payload?.description ?? "Rule"];
                  }}
                />
                <Bar dataKey="hits" name="Hits" radius={[0, 4, 4, 0]} maxBarSize={24}>
                  {chartData.map((row, index) => (
                    <Cell key={row.name} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ChartContainer>
          )}

          {mitre.length > 0 ? (
            <div className="mt-4">
              <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-text-muted">
                MITRE technique mapping
              </p>
              <div className="flex flex-wrap gap-2">
                {mitre.map((row) => (
                  <Badge key={row.mitre_id} variant="info">
                    {row.mitre_id} · {formatInteger(row.hit_count)}
                  </Badge>
                ))}
              </div>
            </div>
          ) : null}
        </div>

        <div>
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-text-muted">
            Recent alerts
          </p>
          {recent.length === 0 ? (
            <p className="text-xs text-text-muted">No recent SIP alerts in window.</p>
          ) : (
            <div className="max-h-[320px] overflow-auto rounded-lg border border-surface-border/70">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th className="numeric">Rule</th>
                    <th className="numeric">Lvl</th>
                    <th>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map((row, index) => (
                    <tr key={`${row.alert_time}-${row.rule_id}-${index}`}>
                      <td className="tabular-nums text-text-muted">{formatTime(row.alert_time)}</td>
                      <td className="numeric">
                        <span className="font-mono">{row.rule_id}</span>
                        <p className="mt-0.5 max-w-[12rem] truncate text-[10px] text-text-muted">
                          {row.rule_description}
                        </p>
                      </td>
                      <td className="numeric">{row.rule_level}</td>
                      <td className="mono">{row.srcip || "n/a"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </MetricFrame>
  );
}
