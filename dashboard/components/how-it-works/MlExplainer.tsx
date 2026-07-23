"use client";

import { useEffect, useState } from "react";
import { usePrefersReducedMotion } from "@/components/hooks/useMotion";
import {
  ISOLATION_FOREST_BASELINE,
  LEAKY_WINDOW_CV_F1,
  STAGE1_EVAL_DATE,
  STAGE1_FEATURE_COLUMNS,
  XGBOOST_GROUPED_CV,
  XGBOOST_MODEL,
} from "@/lib/stage1-metrics";
import { formatPercent } from "@/lib/chart-utils";
import { cn } from "@/lib/utils";

type Tone = "ingress" | "feature" | "split" | "model" | "sink";

const TRAINING_STEPS: {
  id: string;
  step: string;
  label: string;
  sub: string;
  tone: Tone;
}[] = [
  { id: "raw", step: "01", label: "Raw sip_events", sub: "Suricata EVE via Vector into ClickHouse", tone: "ingress" },
  { id: "window", step: "02", label: "5-min windows", sub: "Aggregate per src_ip over fixed windows", tone: "feature" },
  { id: "features", step: "03", label: "22-feature vector", sub: "Volume, rate, auth ratios, diversity", tone: "feature" },
  { id: "labels", step: "04", label: "Label join", sub: "attack_labels from campaigns by src_ip + window", tone: "feature" },
  { id: "split", step: "05", label: "Grouped split", sub: "StratifiedGroupKFold by src_ip (leakage-free)", tone: "split" },
  { id: "train", step: "06", label: "Train detectors", sub: "XGBoost + Isolation Forest", tone: "model" },
  { id: "score", step: "07", label: "Score windows", sub: "Online scorer emits predicted_class + proba", tone: "sink" },
  { id: "sink", step: "08", label: "ml_scores", sub: "Predictions stored for the dashboard", tone: "sink" },
];

const TONE_CARD: Record<Tone, string> = {
  ingress: "border-accent/40 bg-accent/[0.07]",
  feature: "border-accent-purple/40 bg-accent-purple/[0.07]",
  split: "border-cyan-500/40 bg-cyan-500/[0.07]",
  model: "border-accent-amber/40 bg-accent-amber/[0.07]",
  sink: "border-accent-green/40 bg-accent-green/[0.07]",
};

const TONE_TEXT: Record<Tone, string> = {
  ingress: "text-accent",
  feature: "text-accent-purple",
  split: "text-cyan-300",
  model: "text-accent-amber",
  sink: "text-accent-green",
};

export function MlExplainer() {
  const prefersReducedMotion = usePrefersReducedMotion();
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    if (prefersReducedMotion) return;
    const timer = window.setInterval(() => {
      setActiveIndex((prev) => (prev + 1) % TRAINING_STEPS.length);
    }, 2600);
    return () => window.clearInterval(timer);
  }, [prefersReducedMotion]);

  return (
    <div className="rounded-xl border border-surface-border bg-surface-raised/60 shadow-card">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-surface-border/80 px-5 py-4">
        <div>
          <h3 className="text-base font-semibold text-text-primary">How Stage 1 is trained</h3>
          <p className="mt-1 text-xs text-text-muted">
            Offline pipeline from sip_events to leakage-free grouped evaluation ({STAGE1_EVAL_DATE})
          </p>
        </div>
        <div className="rounded-lg border border-accent-green/30 bg-accent-green/5 px-4 py-2.5 text-right">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-accent-green">
            Honest grouped F1
          </p>
          <p className="text-xl font-semibold tabular-nums text-text-primary">
            {formatPercent(XGBOOST_GROUPED_CV.oofBinaryF1, 2)}
          </p>
          <p className="text-[10px] text-text-muted">
            [{formatPercent(XGBOOST_GROUPED_CV.oofF1Ci.lo, 2)},{" "}
            {formatPercent(XGBOOST_GROUPED_CV.oofF1Ci.hi, 2)}]
          </p>
        </div>
      </div>

      <div className="p-5">
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4 xl:grid-cols-8">
          {TRAINING_STEPS.map((step, index) => {
            const isActive = !prefersReducedMotion && index === activeIndex;
            return (
              <div
                key={step.id}
                className={cn(
                  "flex flex-col rounded-lg border p-2.5 transition-all duration-500",
                  TONE_CARD[step.tone],
                  isActive && "ring-1 ring-white/20 shadow-card",
                )}
              >
                <div className="flex items-center justify-between">
                  <span
                    className={cn("font-mono text-[10px] font-bold tabular-nums", TONE_TEXT[step.tone])}
                  >
                    {step.step}
                  </span>
                  {index < TRAINING_STEPS.length - 1 ? (
                    <svg
                      viewBox="0 0 16 16"
                      className="h-3 w-3 text-text-muted/60"
                      fill="none"
                      aria-hidden
                    >
                      <path
                        d="M5 3l5 5-5 5"
                        stroke="currentColor"
                        strokeWidth="1.75"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </svg>
                  ) : null}
                </div>
                <p className={cn("mt-1.5 text-[11px] font-semibold", TONE_TEXT[step.tone])}>
                  {step.label}
                </p>
                <p className="mt-1 text-[10px] leading-relaxed text-text-muted">{step.sub}</p>
              </div>
            );
          })}
        </div>

        <div className="mt-5 grid gap-3 lg:grid-cols-3">
          <div className="rounded-lg border border-surface-border bg-surface/50 p-4 text-xs leading-relaxed">
            <p className="font-semibold text-text-primary">Dataset construction</p>
            <p className="mt-2 text-text-muted">
              {STAGE1_FEATURE_COLUMNS.length} features per 5-minute window: message volume and rate,
              auth failures, success/error ratios, diversity, and body-size statistics. Labels from{" "}
              <span className="font-mono text-text-secondary">attack_labels</span> joined by source
              IP and window start.
            </p>
          </div>
          <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-4 text-xs leading-relaxed">
            <p className="font-semibold text-text-primary">Leakage-free evaluation</p>
            <p className="mt-2 text-text-muted">
              StratifiedGroupKFold with groups = source IP ({XGBOOST_GROUPED_CV.nGroups} groups,{" "}
              {XGBOOST_GROUPED_CV.nSamples} windows) keeps each campaign in one fold. Per-window
              StratifiedKFold leaked and inflated F1 to {formatPercent(LEAKY_WINDOW_CV_F1, 3)}; the
              grouped value is the honest {formatPercent(XGBOOST_GROUPED_CV.oofBinaryF1, 2)}.
            </p>
          </div>
          <div className="rounded-lg border border-surface-border bg-surface/50 p-4 text-xs leading-relaxed">
            <p className="font-semibold text-text-primary">Two model arms</p>
            <p className="mt-2 text-text-muted">
              <span className="font-medium text-text-secondary">XGBoost</span> (production):
              n_estimators={XGBOOST_MODEL.n_estimators}, max_depth={XGBOOST_MODEL.max_depth},
              lr={XGBOOST_MODEL.learning_rate}.{" "}
              <span className="font-medium text-text-secondary">Isolation Forest</span> (baseline):
              grouped-CV F1 {formatPercent(ISOLATION_FOREST_BASELINE.groupedCvF1, 3)} vs XGBoost{" "}
              {formatPercent(XGBOOST_GROUPED_CV.meanBinaryF1, 3)}. XGBoost carries the operating point.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
