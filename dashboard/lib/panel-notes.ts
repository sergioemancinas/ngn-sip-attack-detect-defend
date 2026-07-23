import type { PanelId } from "@/types/layout";

export const PANEL_NOTES: Partial<Record<PanelId, { shows: string; implements: string }>> = {
  "sip-responses": {
    shows: "Distribution of SIP response codes and methods seen in sip_events for the selected window.",
    implements:
      "ClickHouse GROUP BY on response_code / method from ngn_sip.sip_events, polled via /api/metrics?metric=sip-responses.",
  },
  "top-sources": {
    shows: "Highest-volume source IPs with attack_labels join and ban_audit flags for ground-truth context.",
    implements:
      "Aggregates sip_events by src_ip, LEFT JOIN attack_labels and ban_audit; served from /api/metrics?metric=top-sources.",
  },
  "cdr-grid": {
    shows: "CDR-style aggregates per source IP or response code: INVITE, REGISTER, 2xx, auth failures.",
    implements:
      "ClickHouse rollup on sip_events with optional QoS columns (MOS, loss, delay) when HEP RTCP is available.",
  },
  "register-chart": {
    shows: "REGISTER success (2xx) versus 401/403 authentication failures over time.",
    implements:
      "5-minute buckets from sip_events WHERE method = REGISTER, via /api/metrics?metric=register.",
  },
  "suricata-rate": {
    shows: "Suricata IDS alert volume over time from suricata_alerts ingested by Vector.",
    implements:
      "Time-bucketed COUNT(*) on ngn_sip.suricata_alerts; buckets widen automatically when the window is sparse.",
  },
  "wazuh-sip": {
    shows: "Hit counts for custom Wazuh SIP rules 100100-100199 correlated to Kamailio NGN-SEC logs.",
    implements:
      "GROUP BY rule_id from Wazuh alert index mirrored into ClickHouse; top 12 rules by hit_count.",
  },
  "ml-scores": {
    shows: "Live Stage 1 scorer output: average class probability per 5-minute bucket from ml_scores.",
    implements:
      "Polls ngn_sip.ml_scores grouped by bucket and predicted_class; static eval metrics are shown separately above.",
  },
  "llm-verdicts": {
    shows: "Stage 2 advisory verdict confidence over time (benign, suspicious, malicious, needs_review).",
    implements:
      "Ollama worker writes strict JSON to llm_verdicts; dashboard reads avg_confidence per bucket via /api/metrics.",
  },
  "ban-audit": {
    shows: "kamailio-autoban action tallies and the five most recent ban/unban events.",
    implements:
      "Polls ban_audit for action counts; autoban triggers on Wazuh rule_level >= 10 with never-ban allowlist.",
  },
  "soar-cases": {
    shows: "Shuffle SOAR graded response outcomes when Stage 3 orchestration is deployed.",
    implements:
      "Reads soar_cases with recent case rows in meta; shows not-deployed state when the table is absent.",
  },
  "attack-timeline": {
    shows: "attack_labels ground truth overlaid with ban_audit enforcement events on a shared timeline.",
    implements:
      "UNION of labeled campaign windows and ban actions ordered by event_time from ClickHouse.",
  },
  "stack-health": {
    shows: "Data freshness proxy for pipeline tables (healthy, stale, or not deployed).",
    implements:
      "Compares MAX(event_time) per sink table against the selected hours window; no container probes.",
  },
  "c3-summary": {
    shows: "Published C3 detector comparison: signature recall vs behavioural ML specificity at honest F1.",
    implements:
      "Static summary from docs/results/RESULTS_stage1_grouped_2026-06-10.md and C3 campaign eval.",
  },
};
