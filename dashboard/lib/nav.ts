import type { SectionId } from "@/lib/sections";

export interface NavItem {
  href: string;
  label: string;
  section: SectionId;
  /** Short qualifier shown beside the label, e.g. the Stage number. */
  hint?: string;
}

export type NavGroupKind = "plain" | "pipeline";

export interface NavGroup {
  id: string;
  label: string;
  /** "pipeline" groups render as an ordered, numbered stepper. */
  kind: NavGroupKind;
  caption?: string;
  items: NavItem[];
}

const sectionHref = (section: SectionId) => `/?section=${section}`;

/**
 * Navigation follows the pipeline order rather than a flat list: one entry
 * point, the ordered detect, decide, respond stages, then reference material.
 * The pipeline group renders as a numbered stepper so the sequence is visible
 * in the nav itself.
 */
export const NAV_GROUPS: NavGroup[] = [
  {
    id: "start",
    label: "Start here",
    kind: "plain",
    items: [{ href: sectionHref("overview"), label: "Overview", section: "overview" }],
  },
  {
    id: "pipeline",
    label: "Pipeline",
    kind: "pipeline",
    caption: "Detect, decide, respond",
    items: [
      { href: sectionHref("sip"), label: "SIP / Ingress", section: "sip" },
      { href: sectionHref("detection"), label: "Detection", section: "detection" },
      { href: sectionHref("ml"), label: "Machine Learning", section: "ml", hint: "Stage 1" },
      { href: sectionHref("llm"), label: "LLM Triage", section: "llm", hint: "Stage 2" },
      { href: sectionHref("response"), label: "Response", section: "response" },
      { href: sectionHref("shuffle"), label: "Shuffle SOAR", section: "shuffle", hint: "Stage 3" },
      { href: sectionHref("stack-health"), label: "Observability", section: "stack-health" },
    ],
  },
  {
    id: "reference",
    label: "Reference",
    kind: "plain",
    items: [
      { href: sectionHref("how-it-works"), label: "How it works", section: "how-it-works" },
      { href: sectionHref("sources"), label: "Sources", section: "sources" },
      { href: sectionHref("demo"), label: "Live Threats", section: "demo" },
    ],
  },
];

/** Flat list of every nav item, in pipeline order, for non-grouped consumers. */
export const NAV_ITEMS: NavItem[] = NAV_GROUPS.flatMap((group) => group.items);

/** Ordered section ids that make up the pipeline flow. */
export const PIPELINE_SECTION_IDS: SectionId[] =
  NAV_GROUPS.find((group) => group.id === "pipeline")?.items.map((item) => item.section) ?? [];

export const COMPONENT_LEGEND = [
  {
    group: "Ingress",
    items: [
      { name: "Internet / PSTN", table: null, container: "Public SIP 5060 + RTP range" },
      { name: "Kamailio SBC", table: "sip_events (via HEP/Vector)", container: "ngn-sip-kamailio-1" },
    ],
  },
  {
    group: "Detect",
    items: [
      { name: "Suricata IDS", table: "suricata_alerts, sip_events", container: "ngn-sip-ids-suricata-1" },
      { name: "Wazuh SIEM", table: "wazuh_alerts", container: "ngn-sip-wazuh-wazuh-manager-1" },
      { name: "Stage 1 ML", table: "ml_scores", container: "ngn-sip-stage1-scorer" },
      { name: "Stage 2 LLM", table: "llm_verdicts", container: "ngn-sip-stage2-worker + Ollama" },
    ],
  },
  {
    group: "Respond",
    items: [
      { name: "kamailio-autoban", table: "ban_audit", container: "kamailio-autoban sidecar" },
      { name: "Shuffle SOAR", table: "soar_cases", container: "ngn-sip-shuffle-backend-1" },
    ],
  },
  {
    group: "Observe",
    items: [
      { name: "ClickHouse", table: "ngn_sip.*", container: "ngn-sip-clickhouse-1" },
      { name: "Vector", table: null, container: "ngn-sip-vector-1" },
      { name: "Grafana", table: null, container: "ngn-sip-grafana-1" },
      { name: "This dashboard", table: null, container: "ngn-sip-dashboard-1" },
      { name: "Keycloak SSO", table: null, container: "ngn-sip-keycloak-1" },
    ],
  },
] as const;
