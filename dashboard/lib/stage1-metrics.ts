/**
 * Stage 1 eval metrics (leakage-free StratifiedGroupKFold by source IP).
 * Source of truth: docs/results/stage1_metrics_grouped_2026-06-10.json, copied to
 * dashboard/lib/stage1_metrics_grouped.json so it is inside the Docker build context
 * (the build context is ./dashboard; imports cannot reach ../../docs). Refresh the
 * copy when the metrics are regenerated (e.g. after the C1 retrain).
 */
import groupedMetrics from "./stage1_metrics_grouped.json";

interface GroupedCv {
  mean_binary_f1: number;
  n_groups: number;
  oof_binary_f1_ci95: { lo95: number; point: number; hi95: number };
  splits: number;
  splitter: string;
}

interface DetectorMetrics {
  binary: { f1: number };
  confusion_matrix: { labels: string[]; matrix: number[][] };
  cv: { mean_binary_f1: number };
  grouped_cv: GroupedCv;
  per_class: Record<
    string,
    { f1: number; precision: number; recall: number; support: number }
  >;
  roc_auc: number;
  samples: number;
}

const xgb = groupedMetrics.detectors.xgboost as DetectorMetrics;
const iso = groupedMetrics.detectors.isolation_forest as DetectorMetrics;

export const STAGE1_EVAL_DATE = groupedMetrics.created_at.slice(0, 10);
/** Inflated F1 from leaky per-window StratifiedKFold (documented contrast). */
export const LEAKY_WINDOW_CV_F1 = 0.988;

export const STAGE1_FEATURE_COLUMNS = groupedMetrics.feature_columns as readonly string[];

export const STAGE1_COUNT_FEATURES = STAGE1_FEATURE_COLUMNS.slice(0, 12);
export const STAGE1_RATIO_FEATURES = STAGE1_FEATURE_COLUMNS.slice(12);

export const XGBOOST_MODEL = {
  n_estimators: 80,
  max_depth: 3,
  learning_rate: 0.08,
  label_mode: "multiclass",
} as const;

export const ISOLATION_FOREST_BASELINE = {
  groupedCvF1: iso.grouped_cv.mean_binary_f1,
  oofF1Ci: {
    lo: iso.grouped_cv.oof_binary_f1_ci95.lo95,
    point: iso.grouped_cv.oof_binary_f1_ci95.point,
    hi: iso.grouped_cv.oof_binary_f1_ci95.hi95,
  },
  rocAuc: iso.roc_auc,
} as const;

export const XGBOOST_GROUPED_CV = {
  meanBinaryF1: xgb.grouped_cv.mean_binary_f1,
  oofBinaryF1: xgb.grouped_cv.oof_binary_f1_ci95.point,
  oofF1Ci: {
    lo: xgb.grouped_cv.oof_binary_f1_ci95.lo95,
    hi: xgb.grouped_cv.oof_binary_f1_ci95.hi95,
  },
  rocAuc: xgb.roc_auc,
  holdoutF1: xgb.binary.f1,
  nGroups: xgb.grouped_cv.n_groups,
  nSamples: xgb.samples,
} as const;

export const CONFUSION_LABELS = xgb.confusion_matrix.labels as readonly string[];

export type ConfusionLabel = (typeof CONFUSION_LABELS)[number];

export const CONFUSION_MATRIX: number[][] = xgb.confusion_matrix.matrix;

export interface PerClassMetric {
  class: ConfusionLabel;
  precision: number;
  recall: number;
  f1: number;
  support: number;
}

export const PER_CLASS_METRICS: PerClassMetric[] = CONFUSION_LABELS.map((label) => {
  const row = xgb.per_class[label];
  return {
    class: label as ConfusionLabel,
    precision: row?.precision ?? 0,
    recall: row?.recall ?? 0,
    f1: row?.f1 ?? 0,
    support: row?.support ?? 0,
  };
});
