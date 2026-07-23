import { ConfusionMatrixHeatmap } from "@/components/ml/ConfusionMatrixHeatmap";
import {
  ISOLATION_FOREST_BASELINE,
  PER_CLASS_METRICS,
  STAGE1_COUNT_FEATURES,
  STAGE1_RATIO_FEATURES,
  XGBOOST_GROUPED_CV,
  XGBOOST_MODEL,
} from "@/lib/stage1-metrics";
import { formatPercent } from "@/lib/chart-utils";
import { cn } from "@/lib/utils";

export function Stage1EvalSection() {
  return (
    <div className="space-y-4">
      <HeadlineComparison />

      <div className="grid gap-4 xl:grid-cols-2">
        <EvalCard
          title="Confusion matrix (XGBoost holdout)"
          subtitle={`Multiclass eval, n=${XGBOOST_GROUPED_CV.nSamples}`}
        >
          <ConfusionMatrixHeatmap />
        </EvalCard>

        <EvalCard title="Per-class metrics" subtitle="Precision / recall / F1 / support">
          <PerClassTable />
        </EvalCard>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <EvalCard title="Feature contract (22 features)" subtitle="Counts + ratios per 5-min window">
          <FeatureContract />
        </EvalCard>

        <EvalCard title="Model configuration" subtitle="Production scorer parameters">
          <ModelDetails />
        </EvalCard>
      </div>
    </div>
  );
}

function HeadlineComparison() {
  return (
    <div className="rounded-xl border border-accent-green/35 bg-accent-green/5 p-5">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-accent-green">
        Honest headline (leakage-free)
      </p>
      <p className="mt-2 text-3xl font-semibold tabular-nums text-text-primary">
        Binary F1 {formatPercent(XGBOOST_GROUPED_CV.oofBinaryF1, 2)}
      </p>
      <p className="mt-1 text-sm text-text-muted">
        95% CI [{formatPercent(XGBOOST_GROUPED_CV.oofF1Ci.lo, 2)},{" "}
        {formatPercent(XGBOOST_GROUPED_CV.oofF1Ci.hi, 2)}] · ROC-AUC{" "}
        {formatPercent(XGBOOST_GROUPED_CV.rocAuc, 3)}
      </p>
      <p className="mt-3 text-xs leading-relaxed text-text-muted">
        StratifiedGroupKFold with groups = source IP ({XGBOOST_GROUPED_CV.nGroups} groups,{" "}
        {XGBOOST_GROUPED_CV.nSamples} windows). The bootstrap OOF CI agrees with the grouped-CV mean (
        {formatPercent(XGBOOST_GROUPED_CV.meanBinaryF1, 3)}) and the holdout F1 (
        {formatPercent(XGBOOST_GROUPED_CV.holdoutF1, 3)}).
      </p>
    </div>
  );
}

function PerClassTable() {
  return (
    <div className="overflow-x-auto">
      <table className="data-table">
        <thead>
          <tr>
            <th>Class</th>
            <th className="numeric">Precision</th>
            <th className="numeric">Recall</th>
            <th className="numeric">F1</th>
            <th className="numeric">Support</th>
          </tr>
        </thead>
        <tbody>
          {PER_CLASS_METRICS.map((row) => {
            const highlightTollfraud = row.class === "tollfraud" && row.recall === 0;
            const lowSupport = row.support > 0 && row.support < 30;
            return (
              <tr
                key={row.class}
                className={cn(
                  highlightTollfraud && "bg-accent-red/10",
                  lowSupport && !highlightTollfraud && "bg-accent-amber/5",
                )}
              >
                <td className="font-medium capitalize text-text-primary">{row.class}</td>
                <td className="numeric">{formatMetric(row.precision, row.support)}</td>
                <td
                  className={cn(
                    "numeric",
                    highlightTollfraud && "font-semibold text-accent-red",
                  )}
                >
                  {formatMetric(row.recall, row.support)}
                </td>
                <td className="numeric">{formatMetric(row.f1, row.support)}</td>
                <td className="numeric">{row.support}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="mt-2 text-[10px] text-text-muted">
        tollfraud recall 0.00 on n=4 support (all misclassified as injection). Classes below 30
        samples are highlighted; per-class claims need more campaigns.
      </p>
    </div>
  );
}

function formatMetric(value: number, support: number): string {
  if (support === 0) return "n/a";
  return formatPercent(value, 2);
}

function FeatureContract() {
  return (
    <div className="space-y-3 text-xs">
      <div>
        <p className="font-medium text-text-secondary">Count features (12)</p>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {STAGE1_COUNT_FEATURES.map((feature) => (
            <code
              key={feature}
              className="rounded-md border border-surface-border bg-surface px-1.5 py-0.5 font-mono text-[10px] text-text-muted"
            >
              {feature}
            </code>
          ))}
        </div>
      </div>
      <div>
        <p className="font-medium text-text-secondary">Ratio features (10)</p>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {STAGE1_RATIO_FEATURES.map((feature) => (
            <code
              key={feature}
              className="rounded-md border border-surface-border bg-surface px-1.5 py-0.5 font-mono text-[10px] text-text-muted"
            >
              {feature}
            </code>
          ))}
        </div>
      </div>
      <p className="leading-relaxed text-text-muted">
        Joined to attack_labels by source IP and window start. Same contract at train and score
        time; no response-level or HEP features yet.
      </p>
    </div>
  );
}

function ModelDetails() {
  return (
    <div className="space-y-4 text-xs">
      <div className="rounded-lg border border-surface-border bg-surface/50 p-3">
        <p className="font-semibold text-text-primary">XGBoost (production scorer)</p>
        <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1.5 text-text-muted">
          <div>
            <dt>n_estimators</dt>
            <dd className="font-mono text-text-secondary">{XGBOOST_MODEL.n_estimators}</dd>
          </div>
          <div>
            <dt>max_depth</dt>
            <dd className="font-mono text-text-secondary">{XGBOOST_MODEL.max_depth}</dd>
          </div>
          <div>
            <dt>learning_rate</dt>
            <dd className="font-mono text-text-secondary">{XGBOOST_MODEL.learning_rate}</dd>
          </div>
          <div>
            <dt>label_mode</dt>
            <dd className="font-mono text-text-secondary">{XGBOOST_MODEL.label_mode}</dd>
          </div>
        </dl>
      </div>
      <div className="rounded-lg border border-surface-border bg-surface/50 p-3">
        <p className="font-semibold text-text-primary">Isolation Forest (baseline)</p>
        <p className="mt-2 text-text-muted">
          Unsupervised anomaly detector on the same 22 features. Grouped-CV binary F1{" "}
          {formatPercent(ISOLATION_FOREST_BASELINE.groupedCvF1, 3)} · OOF{" "}
          {formatPercent(ISOLATION_FOREST_BASELINE.oofF1Ci.point, 3)} [
          {formatPercent(ISOLATION_FOREST_BASELINE.oofF1Ci.lo, 3)},{" "}
          {formatPercent(ISOLATION_FOREST_BASELINE.oofF1Ci.hi, 3)}] · ROC-AUC{" "}
          {formatPercent(ISOLATION_FOREST_BASELINE.rocAuc, 3)}.
        </p>
        <p className="mt-2 text-text-muted">
          XGBoost carries the operating point; Isolation Forest validates that supervised features
          beat unsupervised separation on this dataset.
        </p>
      </div>
    </div>
  );
}

function EvalCard({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-surface-border bg-surface-raised/60 shadow-card">
      <div className="border-b border-surface-border/80 px-5 py-4">
        <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
        <p className="mt-0.5 text-xs text-text-muted">{subtitle}</p>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}
