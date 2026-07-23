/** Static C3 three-arm comparison from docs/results/RESULTS_c3_comparison_2026-06-02.md */

export const C3_CAMPAIGN_DATE = "2026-06-02";

export interface C3ArmMetric {
  id: string;
  name: string;
  paradigm: string;
  recall: number;
  fpRate: number;
  f1: number;
  note?: string;
}

/** Primary three-arm comparison (Suricata, Wazuh IOC, behavioural ML). */
export const C3_PRIMARY_ARMS: C3ArmMetric[] = [
  {
    id: "suricata",
    name: "Suricata",
    paradigm: "Signature IDS",
    recall: 0.71,
    fpRate: 1.0,
    f1: 0.71,
    note: "30/42 attack sources flagged; 12/12 benign sources flagged on tool-shaped sippts traffic",
  },
  {
    id: "wazuh",
    name: "Wazuh",
    paradigm: "Correlation / IOC",
    recall: 0.71,
    fpRate: 1.0,
    f1: 0.71,
    note: "Any SIP rule 100100-100199; same IOC blind spot as Suricata on low-rate benign probes",
  },
  {
    id: "ml",
    name: "XGBoost ML",
    paradigm: "Behavioural ML",
    recall: 0.75,
    fpRate: 0.03,
    f1: 0.75,
    note: "Grouped-CV OOF F1 0.75 [0.68, 0.81]; ~3% benign FP from holdout eval (not the leaky 0.99 figure)",
  },
];

export const C3_TAKEAWAY =
  "Signature and IOC-correlation arms retain recall on attacks but flag 100% of tool-shaped benign sources. Behavioural ML adds the specificity those arms lack at an honest grouped-CV operating point.";
