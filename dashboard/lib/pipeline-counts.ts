export interface PipelineCounts {
  attack_labels: number;
  sip_events: number;
  suricata_alerts: number;
  wazuh_sip: number;
  ml_scores: number;
  llm_verdicts: number;
  ban_audit: number;
  soar_cases: number;
}

function asNumber(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

export function parsePipelineCounts(meta: Record<string, unknown> | undefined): PipelineCounts {
  const source = meta ?? {};
  return {
    attack_labels: asNumber(source.attack_labels),
    sip_events: asNumber(source.sip_events),
    suricata_alerts: asNumber(source.suricata_alerts),
    wazuh_sip: asNumber(source.wazuh_sip),
    ml_scores: asNumber(source.ml_scores),
    llm_verdicts: asNumber(source.llm_verdicts),
    ban_audit: asNumber(source.ban_audit),
    soar_cases: asNumber(source.soar_cases),
  };
}
