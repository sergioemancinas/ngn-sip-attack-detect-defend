import { clickhouseQuery, tableExists } from "@/lib/clickhouse";
import {
  DEMO_ATTACK_LABEL_EVENTS_QUERY,
  DEMO_ATTACK_META_QUERY,
  DEMO_BAN_EVENTS_QUERY,
  DEMO_BEST_ATTACKER_QUERY,
  DEMO_LATEST_BANNED_QUERY,
  DEMO_LLM_EVENTS_QUERY,
  DEMO_ML_EVENTS_QUERY,
  DEMO_SIP_BURST_QUERY,
  DEMO_SURICATA_EVENTS_QUERY,
  DEMO_WAZUH_EVENTS_QUERY,
} from "@/lib/queries";
import type { DemoStageHighlight, DemoTimelineEvent, DemoTimelineSummary } from "@/types/layout";

const STAGE_ORDER = [
  "attack_label",
  "sip",
  "suricata",
  "wazuh",
  "ml",
  "llm",
  "ban",
] as const;

const STAGE_LABELS: Record<(typeof STAGE_ORDER)[number], string> = {
  attack_label: "Ground truth label",
  sip: "SIP / SBC ingress",
  suricata: "Suricata IDS",
  wazuh: "Wazuh SIEM",
  ml: "Stage 1 ML",
  llm: "Stage 2 LLM",
  ban: "Autoban response",
};

/** Demo correlation uses at least 7 days so older campaigns still show stage evidence. */
export function demoEffectiveHours(hours: number): number {
  return Math.max(hours, 168);
}

function emptySummary(): DemoTimelineSummary {
  return {
    attack_labels: 0,
    sip_events: 0,
    suricata_alerts: 0,
    wazuh_alerts: 0,
    ml_scores: 0,
    llm_verdicts: 0,
    ban_actions: 0,
  };
}

function coerceCount(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

async function countForAttacker(
  hours: number,
  srcIp: string,
  table: string,
  timeColumn: string,
  ipFilter: string,
  extraWhere = "",
): Promise<{ count: number; error?: string }> {
  if (!(await tableExists(table))) return { count: 0 };
  const result = await clickhouseQuery<{ count: number }>(
    `SELECT count() AS count FROM ${table}
     WHERE ${timeColumn} >= now() - INTERVAL {hours:UInt32} HOUR
       AND ${ipFilter}
       ${extraWhere}`,
    { hours, srcIp },
  );
  return { count: coerceCount(result.data[0]?.count), error: result.error };
}

async function fetchStageSummary(hours: number, srcIp: string): Promise<DemoTimelineSummary> {
  const ipv6Match = "replaceOne(toString(src_ip), '::ffff:', '') = {srcIp:String}";
  const stringMatch = "src_ip = {srcIp:String}";
  const wazuhMatch = "srcip = {srcIp:String}";

  const [
    attack_labels,
    sip_events,
    suricata_alerts,
    wazuh_alerts,
    ml_scores,
    llm_verdicts,
    ban_actions,
  ] = await Promise.all([
    countForAttacker(hours, srcIp, "attack_labels", "label_time", ipv6Match),
    countForAttacker(hours, srcIp, "sip_events", "event_time", ipv6Match),
    countForAttacker(hours, srcIp, "suricata_alerts", "event_time", stringMatch),
    countForAttacker(
      hours,
      srcIp,
      "wazuh_alerts",
      "alert_time",
      wazuhMatch,
      "AND rule_id BETWEEN 100100 AND 100199",
    ),
    countForAttacker(hours, srcIp, "ml_scores", "scored_at", ipv6Match),
    countForAttacker(hours, srcIp, "llm_verdicts", "verdict_time", ipv6Match),
    countForAttacker(hours, srcIp, "ban_audit", "event_time", stringMatch),
  ]);

  return {
    attack_labels: attack_labels.count,
    sip_events: sip_events.count,
    suricata_alerts: suricata_alerts.count,
    wazuh_alerts: wazuh_alerts.count,
    ml_scores: ml_scores.count,
    llm_verdicts: llm_verdicts.count,
    ban_actions: ban_actions.count,
  };
}

async function resolveAttackerSrcIp(hours: number): Promise<string | null> {
  const effectiveHours = demoEffectiveHours(hours);

  if (await tableExists("attack_labels")) {
    const best = await clickhouseQuery<{ src_ip: string; stage_hits: number }>(
      DEMO_BEST_ATTACKER_QUERY,
      { hours: effectiveHours },
    );
    const bestIp = best.data[0]?.src_ip?.trim();
    if (bestIp) return bestIp;
  }

  if (await tableExists("ban_audit")) {
    const result = await clickhouseQuery<{ src_ip: string }>(DEMO_LATEST_BANNED_QUERY, {
      hours: effectiveHours,
    });
    const ip = result.data[0]?.src_ip?.trim();
    if (ip) return ip;
  }

  return null;
}

function buildHighlights(
  summary: DemoTimelineSummary,
  events: DemoTimelineEvent[],
): DemoStageHighlight[] {
  const latestByStage = new Map<string, DemoTimelineEvent>();
  for (const event of events) {
    latestByStage.set(event.stage, event);
  }

  return STAGE_ORDER.map((stage) => {
    const countKey =
      stage === "attack_label"
        ? "attack_labels"
        : stage === "sip"
          ? "sip_events"
          : stage === "suricata"
            ? "suricata_alerts"
            : stage === "wazuh"
              ? "wazuh_alerts"
              : stage === "ml"
                ? "ml_scores"
                : stage === "llm"
                  ? "llm_verdicts"
                  : "ban_actions";

    const count = summary[countKey] ?? 0;
    const latest = latestByStage.get(stage);

    return {
      stage,
      label: STAGE_LABELS[stage],
      active: count > 0,
      count,
      latest_time: latest?.event_time ?? null,
      key_value: latest ? `${latest.key}: ${latest.value}` : "Awaiting data",
      detail: latest?.detail ?? "",
    };
  });
}

function safeEvents<T extends DemoTimelineEvent>(
  result: { data?: T[]; error?: string },
): { data: T[]; error?: string } {
  return { data: Array.isArray(result.data) ? result.data : [], error: result.error };
}

export async function fetchDemoTimeline(hours: number, limit: number) {
  const effectiveHours = demoEffectiveHours(hours);
  const srcIp = await resolveAttackerSrcIp(hours);

  if (!srcIp) {
    return {
      src_ip: null as string | null,
      attack_id: "",
      mitre_technique: "",
      phase: "",
      summary: emptySummary(),
      events: [] as DemoTimelineEvent[],
      stage_highlights: buildHighlights(emptySummary(), []),
      error: undefined as string | undefined,
      demo_hours: effectiveHours,
    };
  }

  const params = { hours: effectiveHours, srcIp, limit };

  const [
    hasAttackLabels,
    hasMlScores,
    hasLlmVerdicts,
    hasBanAudit,
  ] = await Promise.all([
    tableExists("attack_labels"),
    tableExists("ml_scores"),
    tableExists("llm_verdicts"),
    tableExists("ban_audit"),
  ]);

  const [
    metaResult,
    summary,
    labelEventsResult,
    sipResult,
    suricataResult,
    wazuhResult,
    mlResult,
    llmResult,
    banResult,
  ] = await Promise.all([
    hasAttackLabels
      ? clickhouseQuery<{
          attack_id: string;
          mitre_technique: string;
          phase: string;
        }>(DEMO_ATTACK_META_QUERY, params)
      : Promise.resolve({ data: [] as { attack_id: string; mitre_technique: string; phase: string }[], error: undefined }),
    fetchStageSummary(effectiveHours, srcIp),
    hasAttackLabels
      ? clickhouseQuery<DemoTimelineEvent>(DEMO_ATTACK_LABEL_EVENTS_QUERY, params)
      : Promise.resolve({ data: [] as DemoTimelineEvent[] }),
    clickhouseQuery<DemoTimelineEvent>(DEMO_SIP_BURST_QUERY, params),
    clickhouseQuery<DemoTimelineEvent>(DEMO_SURICATA_EVENTS_QUERY, params),
    clickhouseQuery<DemoTimelineEvent>(DEMO_WAZUH_EVENTS_QUERY, params),
    hasMlScores
      ? clickhouseQuery<DemoTimelineEvent>(DEMO_ML_EVENTS_QUERY, params)
      : Promise.resolve({ data: [] as DemoTimelineEvent[] }),
    hasLlmVerdicts
      ? clickhouseQuery<DemoTimelineEvent>(DEMO_LLM_EVENTS_QUERY, params)
      : Promise.resolve({ data: [] as DemoTimelineEvent[] }),
    hasBanAudit
      ? clickhouseQuery<DemoTimelineEvent>(DEMO_BAN_EVENTS_QUERY, params)
      : Promise.resolve({ data: [] as DemoTimelineEvent[] }),
  ]);

  const meta = metaResult.data?.[0];

  const labelEvents = safeEvents(labelEventsResult);
  const sipEvents = safeEvents(sipResult);
  const suricataEvents = safeEvents(suricataResult);
  const wazuhEvents = safeEvents(wazuhResult);
  const mlEvents = safeEvents(mlResult);
  const llmEvents = safeEvents(llmResult);
  const banEvents = safeEvents(banResult);

  const events = [
    ...labelEvents.data,
    ...sipEvents.data,
    ...suricataEvents.data,
    ...wazuhEvents.data,
    ...mlEvents.data,
    ...llmEvents.data,
    ...banEvents.data,
  ]
    .filter((event) => event?.event_time)
    .sort((a, b) => new Date(a.event_time).getTime() - new Date(b.event_time).getTime())
    .slice(0, limit);

  const errors = [
    metaResult.error,
    labelEvents.error,
    sipEvents.error,
    suricataEvents.error,
    wazuhEvents.error,
    mlEvents.error,
    llmEvents.error,
    banEvents.error,
  ].filter(Boolean);

  return {
    src_ip: srcIp,
    attack_id: meta?.attack_id ?? "",
    mitre_technique: meta?.mitre_technique ?? "",
    phase: meta?.phase ?? "",
    summary,
    events,
    stage_highlights: buildHighlights(summary, events),
    error: errors[0],
    demo_hours: effectiveHours,
  };
}
