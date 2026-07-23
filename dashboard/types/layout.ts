export type PanelId =
  | "stack-health"
  | "c3-summary"
  | "sip-responses"
  | "top-sources"
  | "cdr-grid"
  | "register-chart"
  | "suricata-rate"
  | "wazuh-sip"
  | "ml-scores"
  | "llm-verdicts"
  | "ban-audit"
  | "soar-cases"
  | "attack-timeline";

export interface PanelDefinition {
  id: PanelId;
  title: string;
  description: string;
  category: "overview" | "sip" | "detection" | "response";
}

export interface MetricResponse<T> {
  data: T[];
  hours: number;
  empty?: boolean;
  error?: string;
  meta?: Record<string, unknown>;
}

export interface StackHealthRow {
  component: string;
  description: string;
  row_count: number;
  latest_event: string | null;
  status: "healthy" | "stale" | "not_deployed";
}

export interface TopSourceRow {
  src_ip: string;
  total: number;
  is_labeled_attack: number;
  mitre_technique: string;
  attack_id: string;
  ban_count: number;
}

export interface CdrRow {
  group_key: string;
  call_count: number;
  invite_count: number;
  register_count: number;
  success_2xx: number;
  auth_failures: number;
  avg_response_code: number | null;
  mos: number | null;
  packet_loss_pct: number | null;
  delay_ms: number | null;
}

export interface TimeBucketRow {
  bucket: string;
  [key: string]: string | number;
}

export interface AttackTimelineRow {
  event_time: string;
  src_ip: string;
  event_type: string;
  detail: string;
  severity: string;
}

export interface DemoTimelineEvent {
  event_time: string;
  stage: string;
  key: string;
  value: string;
  detail: string;
}

export interface DemoTimelineSummary {
  attack_labels: number;
  sip_events: number;
  suricata_alerts: number;
  wazuh_alerts: number;
  ml_scores: number;
  llm_verdicts: number;
  ban_actions: number;
}

export interface DemoStageHighlight {
  stage: string;
  label: string;
  active: boolean;
  count: number;
  latest_time: string | null;
  key_value: string;
  detail: string;
}

export interface BanAuditRecentRow {
  event_time: string;
  src_ip: string;
  action: string;
  reason: string;
}

export interface SoarCaseRecentRow {
  case_time: string;
  src_ip: string;
  graded_action: string;
  wazuh_rule_id: number;
  wazuh_rule_level?: number;
  stage2_verdict: string;
  ml_predicted_label: string;
  ml_attack_score?: number;
}

export interface ScoreSummaryRow {
  score_count: number;
}

export interface VerdictSummaryRow {
  verdict: string;
  avg_confidence: number;
  verdict_count: number;
}

export interface LlmVerdictRecentRow {
  verdict_time: string;
  src_ip: string;
  verdict: string;
  confidence: number;
  alert_rule_id: number;
}

export interface WazuhAgentSummary {
  agent_id: string;
  agent_name: string;
  alert_count: number;
}

export interface WazuhMitreRow {
  mitre_id: string;
  hit_count: number;
}

export interface WazuhRecentRow {
  alert_time: string;
  rule_id: number;
  rule_level: number;
  rule_description: string;
  srcip: string;
  agent_name: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asTimeString(value: unknown): string | null {
  if (typeof value === "string" && value.trim()) return value;
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value.toISOString();
  if (typeof value === "number" && Number.isFinite(value)) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
  }
  return null;
}

function asString(value: unknown): string | null {
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return null;
}

function isArrayOf<T>(
  value: unknown,
  guard: (item: unknown) => item is T,
): value is T[] {
  return Array.isArray(value) && value.every(guard);
}

export function parseSummaryCounts(
  meta: Record<string, unknown> | undefined,
  key: string,
  countField: string,
): number {
  const summary = meta?.[key];
  if (!isArrayOf(summary, (item): item is Record<string, unknown> => isRecord(item))) {
    return 0;
  }
  return summary.reduce((sum, row) => {
    const count = row[countField];
    if (typeof count === "number" && Number.isFinite(count)) return sum + count;
    if (typeof count === "string") {
      const parsed = Number(count);
      return sum + (Number.isFinite(parsed) ? parsed : 0);
    }
    return sum;
  }, 0);
}

export function parseVerdictSummary(
  meta: Record<string, unknown> | undefined,
): VerdictSummaryRow[] {
  const summary = meta?.summary;
  if (
    !isArrayOf(summary, (item): item is VerdictSummaryRow =>
      isRecord(item) &&
      typeof item.verdict === "string" &&
      (typeof item.avg_confidence === "number" || typeof item.avg_confidence === "string") &&
      (typeof item.verdict_count === "number" || typeof item.verdict_count === "string"),
    )
  ) {
    return [];
  }
  return summary.map((row) => ({
    verdict: row.verdict,
    avg_confidence:
      typeof row.avg_confidence === "number"
        ? row.avg_confidence
        : Number(row.avg_confidence) || 0,
    verdict_count:
      typeof row.verdict_count === "number"
        ? row.verdict_count
        : Number(row.verdict_count) || 0,
  }));
}

export function parseLlmVerdictRecent(
  meta: Record<string, unknown> | undefined,
): LlmVerdictRecentRow[] {
  const recent = meta?.recent;
  if (
    !isArrayOf(recent, (item): item is LlmVerdictRecentRow =>
      isRecord(item) &&
      typeof item.verdict_time === "string" &&
      typeof item.src_ip === "string" &&
      typeof item.verdict === "string" &&
      (typeof item.confidence === "number" || typeof item.confidence === "string") &&
      (typeof item.alert_rule_id === "number" || typeof item.alert_rule_id === "string"),
    )
  ) {
    return [];
  }
  return recent.map((row) => ({
    verdict_time: row.verdict_time,
    src_ip: row.src_ip,
    verdict: row.verdict,
    confidence: typeof row.confidence === "number" ? row.confidence : Number(row.confidence) || 0,
    alert_rule_id:
      typeof row.alert_rule_id === "number" ? row.alert_rule_id : Number(row.alert_rule_id) || 0,
  }));
}

export function parseWazuhAgentSummary(
  meta: Record<string, unknown> | undefined,
): WazuhAgentSummary | null {
  const agent = meta?.agent;
  if (
    !isRecord(agent) ||
    typeof agent.agent_id !== "string" ||
    typeof agent.agent_name !== "string"
  ) {
    return null;
  }
  const alertCount = agent.alert_count;
  return {
    agent_id: agent.agent_id,
    agent_name: agent.agent_name,
    alert_count:
      typeof alertCount === "number"
        ? alertCount
        : typeof alertCount === "string"
          ? Number(alertCount) || 0
          : 0,
  };
}

export function parseWazuhMitre(meta: Record<string, unknown> | undefined): WazuhMitreRow[] {
  const mitre = meta?.mitre;
  if (
    !isArrayOf(mitre, (item): item is WazuhMitreRow =>
      isRecord(item) &&
      typeof item.mitre_id === "string" &&
      (typeof item.hit_count === "number" || typeof item.hit_count === "string"),
    )
  ) {
    return [];
  }
  return mitre.map((row) => ({
    mitre_id: row.mitre_id,
    hit_count: typeof row.hit_count === "number" ? row.hit_count : Number(row.hit_count) || 0,
  }));
}

export function parseWazuhRecent(meta: Record<string, unknown> | undefined): WazuhRecentRow[] {
  const recent = meta?.recent;
  if (
    !isArrayOf(recent, (item): item is WazuhRecentRow =>
      isRecord(item) &&
      typeof item.alert_time === "string" &&
      (typeof item.rule_id === "number" || typeof item.rule_id === "string") &&
      (typeof item.rule_level === "number" || typeof item.rule_level === "string") &&
      typeof item.rule_description === "string" &&
      typeof item.srcip === "string" &&
      typeof item.agent_name === "string",
    )
  ) {
    return [];
  }
  return recent.map((row) => ({
    alert_time: row.alert_time,
    rule_id: typeof row.rule_id === "number" ? row.rule_id : Number(row.rule_id) || 0,
    rule_level: typeof row.rule_level === "number" ? row.rule_level : Number(row.rule_level) || 0,
    rule_description: row.rule_description,
    srcip: row.srcip,
    agent_name: row.agent_name,
  }));
}

export function parseBanAuditRecent(meta: Record<string, unknown> | undefined): BanAuditRecentRow[] {
  const recent = meta?.recent;
  if (!Array.isArray(recent)) return [];

  const rows: BanAuditRecentRow[] = [];
  for (const item of recent) {
    if (!isRecord(item)) continue;
    const eventTime = asTimeString(item.event_time);
    const srcIp = asString(item.src_ip);
    const action = asString(item.action);
    const reason = asString(item.reason);
    if (!eventTime || !srcIp || !action || !reason) continue;
    rows.push({ event_time: eventTime, src_ip: srcIp, action, reason });
  }
  return rows;
}

export function parseSoarCaseRecent(meta: Record<string, unknown> | undefined): SoarCaseRecentRow[] {
  const recent = meta?.recent;
  if (!Array.isArray(recent)) return [];

  const rows: SoarCaseRecentRow[] = [];
  for (const item of recent) {
    if (!isRecord(item)) continue;
    const caseTime = asTimeString(item.case_time);
    const srcIp = asString(item.src_ip);
    const gradedAction = asString(item.graded_action);
    const stage2Verdict = asString(item.stage2_verdict) ?? "";
    const mlLabel = asString(item.ml_predicted_label) ?? "";
    const ruleIdRaw = item.wazuh_rule_id;
    const ruleId =
      typeof ruleIdRaw === "number"
        ? ruleIdRaw
        : typeof ruleIdRaw === "string"
          ? Number(ruleIdRaw) || 0
          : 0;
    const ruleLevelRaw = item.wazuh_rule_level;
    const ruleLevel =
      typeof ruleLevelRaw === "number"
        ? ruleLevelRaw
        : typeof ruleLevelRaw === "string"
          ? Number(ruleLevelRaw) || undefined
          : undefined;
    const scoreRaw = item.ml_attack_score;
    const mlAttackScore =
      typeof scoreRaw === "number"
        ? scoreRaw
        : typeof scoreRaw === "string"
          ? Number(scoreRaw) || undefined
          : undefined;
    if (!caseTime || !srcIp || !gradedAction) continue;
    rows.push({
      case_time: caseTime,
      src_ip: srcIp,
      graded_action: gradedAction,
      wazuh_rule_id: ruleId,
      wazuh_rule_level: ruleLevel,
      stage2_verdict: stage2Verdict,
      ml_predicted_label: mlLabel,
      ml_attack_score: mlAttackScore,
    });
  }
  return rows;
}
