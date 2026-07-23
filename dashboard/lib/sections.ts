import type { PanelId } from "@/types/layout";

export type SectionId =
  | "overview"
  | "demo"
  | "sip"
  | "detection"
  | "ml"
  | "llm"
  | "response"
  | "shuffle"
  | "stack-health"
  | "how-it-works"
  | "sources";

export interface DashboardSection {
  id: SectionId;
  label: string;
  title: string;
  subtitle: string;
  description: string;
  panelIds: PanelId[];
}

export const DASHBOARD_SECTIONS: DashboardSection[] = [
  {
    id: "overview",
    label: "Overview",
    title: "Project overview",
    subtitle: "SIP attack-detect-defend lab on the campus VM",
    description:
      "Labeled sippts campaigns generate ground truth in attack_labels. The sections below follow the pipeline stage by stage; each one reads its own evidence from ClickHouse.",
    panelIds: [],
  },
  {
    id: "demo",
    label: "Live Threats",
    title: "Live threats and honeypot intelligence",
    subtitle: "Real internet attackers captured on the exposed SIP edge",
    description:
      "The SIP edge is publicly exposed, so this view shows the real attackers hitting it in real time: who they are (geolocation, network, and Shodan intelligence on their own infrastructure), what they are doing, why each was flagged, and how the pipeline responds. Security Insights aggregates open-source threat intelligence across every captured source.",
    panelIds: [],
  },
  {
    id: "sip",
    label: "SIP / VoIP",
    title: "SIP and VoIP ingress",
    subtitle: "Kamailio SBC with rtpengine media relay",
    description:
      "Signaling enters through the Kamailio session border controller, which applies PIKE rate limiting, scanner-UA IOC checks, and sanity validation. Asterisk handles media and rtpengine relays RTP. Suricata captures SIP into sip_events via Vector.",
    panelIds: ["sip-responses", "top-sources", "cdr-grid", "register-chart"],
  },
  {
    id: "detection",
    label: "Detection",
    title: "Signature and SIEM detection",
    subtitle: "Suricata IDS plus Wazuh rules 100100-100199",
    description:
      "Suricata raises signature alerts on SIP captured in the Kamailio network namespace. Wazuh correlates Kamailio NGN-SEC logs with rules 100100-100199. The explainer below maps each attack vector to the layer that catches it.",
    panelIds: ["suricata-rate", "wazuh-sip", "c3-summary"],
  },
  {
    id: "ml",
    label: "Machine Learning",
    title: "Stage 1 behavioural detection",
    subtitle: "XGBoost plus Isolation Forest on 5-minute SIP windows",
    description:
      "Stage 1 trains XGBoost (supervised) and Isolation Forest (unsupervised) on 5-minute SIP feature windows joined to attack_labels. The online scorer writes predictions to ml_scores. Evaluation is grouped by source IP; the explainer below covers the protocol and the honest results.",
    panelIds: ["ml-scores"],
  },
  {
    id: "llm",
    label: "LLM Triage",
    title: "Stage 2 advisory triage",
    subtitle: "Local Ollama qwen2.5 with strict JSON and guardrails",
    description:
      "The Stage 2 worker sends high-severity Wazuh alerts to a local Ollama model and stores a strict JSON verdict in llm_verdicts. It is advisory only; blocking stays with kamailio-autoban. The explainer below covers the guardrails.",
    panelIds: ["llm-verdicts"],
  },
  {
    id: "response",
    label: "Response",
    title: "Defensive response",
    subtitle: "kamailio-autoban backstop and Shuffle SOAR orchestration",
    description:
      "Two arms act on the same trigger. kamailio-autoban drops a source at the SIP edge and writes ban_audit; Shuffle SOAR opens a graded case in soar_cases when Stage 3 is deployed.",
    panelIds: ["ban-audit", "soar-cases", "attack-timeline"],
  },
  {
    id: "shuffle",
    label: "Shuffle SOAR",
    title: "Shuffle SOAR orchestration",
    subtitle: "Stage 3 graded response recorded in soar_cases",
    description:
      "Shuffle runs the graded arm of the response stage. The same high-severity Wazuh trigger that drives autoban is handed to a playbook that enriches the source, replays Stage-2 triage, grades a proportionate action, and records a case in soar_cases for analyst review. This view reads those cases directly from ClickHouse.",
    panelIds: [],
  },
  {
    id: "stack-health",
    label: "Observability",
    title: "Observability and stack health",
    subtitle: "ClickHouse freshness proxy for lab services",
    description:
      "Health comes from ClickHouse row freshness, not container probes. A component with no table sink shows as not deployed rather than stale. Core tables (sip_events, alerts, ml_scores) drive the healthy or stale label for the selected window.",
    panelIds: ["stack-health"],
  },
  {
    id: "how-it-works",
    label: "How it works",
    title: "Pipeline walkthrough",
    subtitle: "Interactive stepper and architecture legend",
    description:
      "Step through the detect, decide, respond loop. Each stage shows its ClickHouse row count for the selected window and highlights the matching nodes in the architecture diagram.",
    panelIds: [],
  },
  {
    id: "sources",
    label: "Sources",
    title: "Sources and references",
    subtitle: "Standards, frameworks, tools, and libraries used in this project",
    description:
      "Standards, frameworks, tools, and prior work referenced across the lab. Links open public documentation in a new tab.",
    panelIds: [],
  },
];

export const SECTION_MAP = Object.fromEntries(
  DASHBOARD_SECTIONS.map((section) => [section.id, section]),
) as Record<SectionId, DashboardSection>;

export const FULL_WIDTH_PANELS = new Set<PanelId>([
  "top-sources",
  "cdr-grid",
  "soar-cases",
  "attack-timeline",
  "stack-health",
  "ml-scores",
  "llm-verdicts",
  "wazuh-sip",
  "c3-summary",
]);

export function resolveSectionId(raw: string | null): SectionId {
  if (raw && raw in SECTION_MAP) {
    return raw as SectionId;
  }
  return "overview";
}
