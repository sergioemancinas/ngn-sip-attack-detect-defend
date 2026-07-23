import type { PanelDefinition, PanelId } from "@/types/layout";

export const PANEL_CATALOG: PanelDefinition[] = [
  {
    id: "stack-health",
    title: "Stack Health",
    description: "Data freshness proxy for lab components",
    category: "overview",
  },
  {
    id: "c3-summary",
    title: "C3 Detector Comparison",
    description: "Published Stage 1 grouped-CV metrics",
    category: "overview",
  },
  {
    id: "sip-responses",
    title: "SIP Responses",
    description: "Response code and method mix from sip_events",
    category: "sip",
  },
  {
    id: "top-sources",
    title: "Top Source IPs",
    description: "Volume leaders with attack label and ban flags",
    category: "sip",
  },
  {
    id: "cdr-grid",
    title: "CDR / QoS Grid",
    description: "Per-source or per-response aggregates (QoS pending HEP RTCP)",
    category: "sip",
  },
  {
    id: "register-chart",
    title: "REGISTER Activity",
    description: "REGISTER success vs 401 over time",
    category: "sip",
  },
  {
    id: "suricata-rate",
    title: "Suricata Alert Rate",
    description: "IDS alert volume from suricata_alerts",
    category: "detection",
  },
  {
    id: "wazuh-sip",
    title: "Wazuh SIP Rules",
    description: "Rule hits for 100100-100199",
    category: "detection",
  },
  {
    id: "ml-scores",
    title: "Live ML scores",
    description: "predicted_class probability and volume from ml_scores",
    category: "detection",
  },
  {
    id: "llm-verdicts",
    title: "Stage 2 LLM Verdicts",
    description: "Advisory triage from llm_verdicts",
    category: "detection",
  },
  {
    id: "ban-audit",
    title: "Autoban Actions",
    description: "ban_audit tallies (ban_table out of scope)",
    category: "response",
  },
  {
    id: "soar-cases",
    title: "SOAR Cases",
    description: "Shuffle orchestration outcomes",
    category: "response",
  },
  {
    id: "attack-timeline",
    title: "Attack Timeline",
    description: "attack_labels overlaid with ban_audit",
    category: "response",
  },
];

export const PANEL_MAP = Object.fromEntries(
  PANEL_CATALOG.map((p) => [p.id, p]),
) as Record<PanelId, PanelDefinition>;
