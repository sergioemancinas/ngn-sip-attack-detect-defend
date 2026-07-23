export const PIPELINE_STAGES = [
  {
    id: "attack",
    title: "1. Attack",
    summary: "Internet actors and PSTN trunk reach the public SIP edge (5060/RTP); labeled sippts campaigns generate ground truth in attack_labels.",
    metrics: ["attack_labels", "sip_events"] as const,
    nodes: ["internet", "scanners", "pstn", "frontdoor"] as const,
  },
  {
    id: "sbc",
    title: "2. SBC",
    summary: "Kamailio applies PIKE rate limits, scanner-UA IOC checks, and sanity validation at the SIP edge.",
    metrics: ["sip_events"] as const,
    nodes: ["kamailio"] as const,
  },
  {
    id: "detect",
    title: "3. Detect",
    summary: "Suricata captures SIP into sip_events while Wazuh correlates Kamailio NGN-SEC logs with rules 100100-199.",
    metrics: ["suricata_alerts", "wazuh_sip"] as const,
    nodes: ["suricata", "wazuh"] as const,
  },
  {
    id: "stage1",
    title: "4. Stage 1 ML",
    summary: "XGBoost and Isolation Forest score 5-minute feature windows and write ml_scores.",
    metrics: ["ml_scores"] as const,
    nodes: ["stage1"] as const,
  },
  {
    id: "stage2",
    title: "5. Stage 2 LLM",
    summary: "Ollama qwen2.5 produces advisory-only verdicts in llm_verdicts with prompt-injection guardrails.",
    metrics: ["llm_verdicts"] as const,
    nodes: ["stage2"] as const,
  },
  {
    id: "respond",
    title: "6. Respond",
    summary: "kamailio-autoban enforces bans via ban_audit while Shuffle SOAR records graded actions in soar_cases.",
    metrics: ["ban_audit", "soar_cases"] as const,
    nodes: ["autoban", "soar"] as const,
  },
] as const;

export type PipelineStageId = (typeof PIPELINE_STAGES)[number]["id"];

export function stageActiveNodes(stageId?: string): string[] {
  if (!stageId) return [];
  const stage = PIPELINE_STAGES.find((entry) => entry.id === stageId);
  return stage ? [...stage.nodes] : [];
}
