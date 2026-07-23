import {
  CONFUSION_LABELS,
  CONFUSION_MATRIX,
  XGBOOST_GROUPED_CV,
  type ConfusionLabel,
} from "@/lib/stage1-metrics";
import { confusionHeatColor } from "@/lib/chart-utils";

export function ConfusionMatrixHeatmap() {
  const maxCell = Math.max(...CONFUSION_MATRIX.flat(), 1);

  return (
    <div className="overflow-x-auto">
      <div className="inline-block min-w-full">
        <table className="w-full border-collapse text-center text-[11px]">
          <thead>
            <tr>
              <th className="pb-2 pr-2 text-left text-[10px] font-medium uppercase tracking-wide text-text-muted">
                Actual \ Predicted
              </th>
              {CONFUSION_LABELS.map((label) => (
                <th
                  key={label}
                  className="px-1 pb-2 text-[10px] font-medium uppercase tracking-wide text-text-muted"
                >
                  {shortLabel(label)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {CONFUSION_LABELS.map((actual, rowIndex) => (
              <tr key={actual}>
                <td className="py-1 pr-2 text-left font-medium capitalize text-text-secondary">
                  {actual}
                </td>
                {CONFUSION_MATRIX[rowIndex].map((count, colIndex) => {
                  const predicted = CONFUSION_LABELS[colIndex] as ConfusionLabel;
                  const isDiagonal = actual === predicted;
                  return (
                    <td key={`${actual}-${predicted}`} className="p-0.5">
                      <div
                        className="flex h-9 min-w-[2.25rem] items-center justify-center rounded-md border tabular-nums"
                        style={{
                          backgroundColor: confusionHeatColor(count, maxCell),
                          borderColor: isDiagonal && count > 0
                            ? "rgb(var(--accent-green) / 0.5)"
                            : count > 0 && !isDiagonal
                              ? "rgb(var(--accent-red) / 0.35)"
                              : "rgb(var(--surface-border) / 0.5)",
                          color: count > maxCell * 0.55 ? "#f8fafc" : "#cbd5e1",
                        }}
                        title={`Actual ${actual}, predicted ${predicted}: ${count}`}
                      >
                        {count}
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-2 text-[10px] text-text-muted">
        Holdout eval n={XGBOOST_GROUPED_CV.nSamples} · green border = correct class · red border =
        misclassification
      </p>
    </div>
  );
}

function shortLabel(label: ConfusionLabel): string {
  if (label === "credentials") return "creds";
  if (label === "tollfraud") return "toll";
  return label.slice(0, 6);
}
