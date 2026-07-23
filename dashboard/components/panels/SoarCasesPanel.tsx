"use client";

import { MetricFrame, useMetric } from "@/components/hooks/useMetric";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/States";
import { formatInteger } from "@/lib/chart-utils";
import { parseSoarCaseRecent } from "@/types/layout";

export function SoarCasesPanel({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { data, loading, error, empty, meta } = useMetric<{ graded_action: string; case_count: number }>(
    "soar-cases",
    hours,
    refreshMs,
  );

  if (meta?.table_missing) {
    return (
      <EmptyState message="soar_cases table not present. Run DDL before first workflow execution." />
    );
  }

  const rows = data ?? [];
  const recent = parseSoarCaseRecent(meta);
  const totalCases = rows.reduce((sum, row) => sum + (row?.case_count ?? 0), 0);

  return (
    <MetricFrame loading={loading} error={error} empty={empty && recent.length === 0 && rows.length === 0}>
      <div className="grid grid-cols-2 gap-3">
        {rows.length > 0 ? (
          rows.map((row) => (
            <div
              key={String(row?.graded_action ?? "unknown")}
              className="rounded-xl border border-surface-border bg-surface/60 p-3"
            >
              <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">
                {row?.graded_action ?? "action"}
              </p>
              <p className="mt-1 text-2xl font-semibold tabular-nums text-text-primary">
                {formatInteger(row?.case_count)}
              </p>
            </div>
          ))
        ) : (
          <div className="col-span-2 rounded-lg border border-dashed border-surface-border px-3 py-4 text-center text-xs text-text-muted">
            No graded actions in window ({formatInteger(totalCases)} cases)
          </div>
        )}
      </div>

      {recent.length > 0 ? (
        <div className="mt-4 max-h-[220px] overflow-auto">
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-text-muted">
            Recent cases
          </p>
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Action</th>
                <th className="numeric">Rule</th>
                <th className="numeric">Lv</th>
                <th>ML / LLM</th>
                <th className="numeric">Score</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((row) => (
                <tr key={`${row.case_time}-${row.src_ip}`}>
                  <td className="tabular-nums text-text-muted">
                    {new Date(row.case_time).toLocaleTimeString()}
                  </td>
                  <td className="font-mono text-xs">{row.src_ip}</td>
                  <td>
                    <Badge>{row.graded_action}</Badge>
                  </td>
                  <td className="numeric">{row.wazuh_rule_id || "-"}</td>
                  <td className="numeric">{row.wazuh_rule_level ?? "-"}</td>
                  <td className="text-xs">
                    {row.ml_predicted_label || "-"} / {row.stage2_verdict || "-"}
                  </td>
                  <td className="numeric font-mono text-xs">
                    {row.ml_attack_score != null ? row.ml_attack_score.toFixed(2) : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="mt-4 text-xs text-text-muted">
          No recent soar_cases rows. Shuffle workflows populate this table when Stage 3 is deployed.
        </p>
      )}
    </MetricFrame>
  );
}
