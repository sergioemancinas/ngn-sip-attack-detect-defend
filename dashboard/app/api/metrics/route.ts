import { NextResponse } from "next/server";
import { requireApiSession } from "@/lib/api-auth";
import { clickhouseQuery, tableExists } from "@/lib/clickhouse";
import { parseHours, parseLimit, parseGroupBy } from "@/lib/hours";
import {
  SIP_RESPONSES_QUERY,
  SIP_METHOD_MIX_QUERY,
  SIP_RESPONSE_CLASS_QUERY,
  SIP_RESPONSE_CODES_QUERY,
  SIP_EVENTS_RECENT_QUERY,
  TOP_SOURCES_QUERY,
  CDR_BY_SRC_IP_QUERY,
  CDR_BY_RESPONSE_QUERY,
  REGISTER_TIMESERIES_QUERY,
  SURICATA_RATE_QUERY,
  SURICATA_RECENT_QUERY,
  WAZUH_SIP_QUERY,
  WAZUH_TIMESERIES_QUERY,
  WAZUH_AGENT_SUMMARY_QUERY,
  WAZUH_MITRE_QUERY,
  WAZUH_RECENT_QUERY,
  ML_SCORES_TIMESERIES_QUERY,
  ML_SCORES_SUMMARY_QUERY,
  ML_SCORES_RECENT_QUERY,
  LLM_VERDICTS_TIMESERIES_QUERY,
  LLM_VERDICTS_SUMMARY_QUERY,
  LLM_VERDICTS_RECENT_QUERY,
  BAN_AUDIT_SUMMARY_QUERY,
  BAN_AUDIT_RECENT_QUERY,
  RESPONSE_LIVE_BAN_QUERY,
  RESPONSE_LIVE_SOAR_QUERY,
  SOAR_CASES_SUMMARY_QUERY,
  SOAR_CASES_RECENT_QUERY,
  ATTACK_TIMELINE_QUERY,
  EXTERNAL_ATTACKERS_QUERY,
} from "@/lib/queries";
import type { StackHealthRow } from "@/types/layout";
import {
  probeHttp,
  sipPlaneStatus,
  toStackHealthRow,
  type ServiceHealthRow,
} from "@/lib/stack-health";
import { fetchDemoTimeline } from "@/lib/demo-timeline";

function firstError(...errors: Array<string | undefined>): string | undefined {
  return errors.find(Boolean);
}

function jsonMetric<T>(
  data: T[] | undefined,
  hours: number,
  extra?: Record<string, unknown>,
  error?: string,
) {
  const rows = Array.isArray(data) ? data : [];
  return NextResponse.json({
    data: rows,
    hours,
    empty: rows.length === 0,
    error,
    ...extra,
  });
}

export async function GET(request: Request) {
  const denied = await requireApiSession();
  if (denied) return denied;

  const { searchParams } = new URL(request.url);
  const hours = parseHours(searchParams.get("hours"));
  const limit = parseLimit(searchParams.get("limit"));
  const metric = searchParams.get("metric");

  switch (metric) {
    case "sip-responses": {
      const result = await clickhouseQuery<{ label: string; value: number }>(
        SIP_RESPONSES_QUERY,
        { hours },
      );
      return jsonMetric(result.data, hours, undefined, result.error);
    }
    case "sip-breakdown": {
      const [methods, classes] = await Promise.all([
        clickhouseQuery<{ method: string; cnt: number }>(SIP_METHOD_MIX_QUERY, { hours }),
        clickhouseQuery<{ response_class: string; cnt: number }>(SIP_RESPONSE_CLASS_QUERY, { hours }),
      ]);
      return jsonMetric([], hours, {
        method_mix: methods.data ?? [],
        response_classes: classes.data ?? [],
        error: firstError(methods.error, classes.error),
      });
    }
    case "sip-response-codes": {
      const result = await clickhouseQuery<{
        response_code: number;
        response_phrase: string;
        cnt: number;
      }>(SIP_RESPONSE_CODES_QUERY, { hours });
      return jsonMetric(result.data, hours, undefined, result.error);
    }
    case "sip-events-recent": {
      const result = await clickhouseQuery(SIP_EVENTS_RECENT_QUERY, { hours, limit });
      return jsonMetric(result.data, hours, undefined, result.error);
    }
    case "external-attackers": {
      const result = await clickhouseQuery<{
        ip: string;
        events: number;
        methods: string;
        user_agents: string;
        first_seen: string;
        last_seen: string;
        banned: number;
      }>(EXTERNAL_ATTACKERS_QUERY, { hours, limit });
      return jsonMetric(result.data, hours, undefined, result.error);
    }
    case "detection-live": {
      const [suricata, wazuh] = await Promise.all([
        clickhouseQuery<{
          event_time: string;
          rule: string;
          level: string;
          src: string;
        }>(SURICATA_RECENT_QUERY, { hours, limit }),
        clickhouseQuery<{
          alert_time: string;
          rule_id: number;
          rule_level: number;
          rule_description: string;
          srcip: string;
        }>(WAZUH_RECENT_QUERY, { hours, limit }),
      ]);
      type LiveRow = {
        event_time: string;
        source: string;
        rule: string;
        level: string;
        src: string;
      };
      const merged: LiveRow[] = [
        ...(suricata.data ?? []).map((row) => ({
          event_time: row.event_time,
          source: "suricata",
          rule: row.rule,
          level: row.level,
          src: row.src,
        })),
        ...(wazuh.data ?? []).map((row) => ({
          event_time: row.alert_time,
          source: "wazuh",
          rule: String(row.rule_id),
          level: String(row.rule_level),
          src: row.srcip,
        })),
      ]
        .sort((a, b) => new Date(b.event_time).getTime() - new Date(a.event_time).getTime())
        .slice(0, limit);
      return jsonMetric(merged, hours, {
        error: firstError(suricata.error, wazuh.error),
      });
    }
    case "ml-scores-recent": {
      if (!(await tableExists("ml_scores"))) {
        return jsonMetric([], hours, { table_missing: true });
      }
      const result = await clickhouseQuery(ML_SCORES_RECENT_QUERY, { hours, limit });
      return jsonMetric(result.data, hours, undefined, result.error);
    }
    case "response-live": {
      const banExists = await tableExists("ban_audit");
      const soarExists = await tableExists("soar_cases");
      const emptyBan = { data: [] as Array<{ event_time: string; src: string; action: string; detail: string }>, error: undefined as string | undefined };
      const emptySoar = { data: [] as Array<{ event_time: string; src: string; action: string; detail: string }>, error: undefined as string | undefined };
      const [bans, soar] = await Promise.all([
        banExists
          ? clickhouseQuery<{
              event_time: string;
              src: string;
              action: string;
              detail: string;
            }>(RESPONSE_LIVE_BAN_QUERY, { hours, limit })
          : Promise.resolve(emptyBan),
        soarExists
          ? clickhouseQuery<{
              event_time: string;
              src: string;
              action: string;
              detail: string;
            }>(RESPONSE_LIVE_SOAR_QUERY, { hours, limit })
          : Promise.resolve(emptySoar),
      ]);
      type ResponseRow = {
        event_time: string;
        source: string;
        src: string;
        action: string;
        detail: string;
      };
      const merged: ResponseRow[] = [
        ...(bans.data ?? []).map((row) => ({
          event_time: row.event_time,
          source: "ban_audit",
          src: row.src,
          action: row.action,
          detail: row.detail,
        })),
        ...(soar.data ?? []).map((row) => ({
          event_time: row.event_time,
          source: "soar_cases",
          src: row.src,
          action: row.action,
          detail: row.detail,
        })),
      ]
        .sort((a, b) => new Date(b.event_time).getTime() - new Date(a.event_time).getTime())
        .slice(0, limit);
      return jsonMetric(merged, hours, {
        error: firstError(bans.error, soar.error),
      });
    }
    case "top-sources": {
      if (!(await tableExists("ban_audit"))) {
        const fallback = await clickhouseQuery(
          `WITH sources AS (
            SELECT replaceOne(toString(src_ip), '::ffff:', '') AS src_ip, count() AS event_count
            FROM sip_events WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR GROUP BY src_ip
            UNION ALL
            SELECT src_ip, count() FROM suricata_alerts
            WHERE event_time >= now() - INTERVAL {hours:UInt32} HOUR GROUP BY src_ip
          )
          SELECT src_ip, sum(event_count) AS total, 0 AS is_labeled_attack,
            '' AS mitre_technique, '' AS attack_id, 0 AS ban_count
          FROM sources GROUP BY src_ip ORDER BY total DESC LIMIT {limit:UInt32}`,
          { hours, limit },
        );
        return jsonMetric(fallback.data, hours, { note: "ban_audit table absent" }, fallback.error);
      }
      const result = await clickhouseQuery(TOP_SOURCES_QUERY, { hours, limit });
      return jsonMetric(result.data, hours, undefined, result.error);
    }
    case "cdr": {
      const groupBy = parseGroupBy(searchParams.get("groupBy"));
      const query = groupBy === "response_code" ? CDR_BY_RESPONSE_QUERY : CDR_BY_SRC_IP_QUERY;
      const result = await clickhouseQuery(query, { hours, limit });
      return jsonMetric(result.data, hours, {
        groupBy,
        qos_available: false,
        qos_note: "MOS/Loss/Delay require HEPlify RTCP ingest (not yet wired)",
      }, result.error);
    }
    case "register": {
      const result = await clickhouseQuery(REGISTER_TIMESERIES_QUERY, { hours });
      return jsonMetric(result.data, hours, undefined, result.error);
    }
    case "suricata": {
      const result = await clickhouseQuery(SURICATA_RATE_QUERY, { hours });
      return jsonMetric(result.data, hours, undefined, result.error);
    }
    case "wazuh": {
      const [rules, series, agent, mitre, recent] = await Promise.all([
        clickhouseQuery(WAZUH_SIP_QUERY, { hours }),
        clickhouseQuery(WAZUH_TIMESERIES_QUERY, { hours }),
        clickhouseQuery<{
          agent_id: string;
          agent_name: string;
          alert_count: number;
        }>(WAZUH_AGENT_SUMMARY_QUERY, { hours }),
        clickhouseQuery<{ mitre_id: string; hit_count: number }>(WAZUH_MITRE_QUERY, { hours }),
        clickhouseQuery(WAZUH_RECENT_QUERY, { hours, limit }),
      ]);
      return jsonMetric(rules.data, hours, {
        timeseries: series.data ?? [],
        agent: agent.data?.[0] ?? null,
        mitre: mitre.data ?? [],
        recent: recent.data ?? [],
        error: firstError(rules.error, series.error, agent.error, mitre.error, recent.error),
      });
    }
    case "ml-scores": {
      if (!(await tableExists("ml_scores"))) {
        return jsonMetric([], hours, { table_missing: true });
      }
      const [series, summary] = await Promise.all([
        clickhouseQuery(ML_SCORES_TIMESERIES_QUERY, { hours }),
        clickhouseQuery(ML_SCORES_SUMMARY_QUERY, { hours }),
      ]);
      return jsonMetric(series.data, hours, {
        summary: summary.data,
        error: series.error ?? summary.error,
      });
    }
    case "llm-verdicts-recent": {
      if (!(await tableExists("llm_verdicts"))) {
        return jsonMetric([], hours, { table_missing: true });
      }
      const result = await clickhouseQuery(LLM_VERDICTS_RECENT_QUERY, { hours, limit });
      return jsonMetric(result.data, hours, undefined, result.error);
    }
    case "llm-verdicts": {
      if (!(await tableExists("llm_verdicts"))) {
        return jsonMetric([], hours, { table_missing: true });
      }
      const [series, summary, recent] = await Promise.all([
        clickhouseQuery(LLM_VERDICTS_TIMESERIES_QUERY, { hours }),
        clickhouseQuery(LLM_VERDICTS_SUMMARY_QUERY, { hours }),
        clickhouseQuery(LLM_VERDICTS_RECENT_QUERY, { hours, limit }),
      ]);
      return jsonMetric(series.data, hours, {
        summary: summary.data ?? [],
        recent: recent.data ?? [],
        error: firstError(series.error, summary.error, recent.error),
      });
    }
    case "ban-audit": {
      if (!(await tableExists("ban_audit"))) {
        return jsonMetric([], hours, { table_missing: true });
      }
      const [summary, recent] = await Promise.all([
        clickhouseQuery(BAN_AUDIT_SUMMARY_QUERY, { hours }),
        clickhouseQuery(BAN_AUDIT_RECENT_QUERY, { hours, limit }),
      ]);
      return jsonMetric(summary.data, hours, {
        recent: recent.data,
        error: summary.error ?? recent.error,
      });
    }
    case "soar-cases": {
      if (!(await tableExists("soar_cases"))) {
        return jsonMetric([], hours, { table_missing: true });
      }
      const [summary, recent] = await Promise.all([
        clickhouseQuery(SOAR_CASES_SUMMARY_QUERY, { hours }),
        clickhouseQuery(SOAR_CASES_RECENT_QUERY, { hours, limit }),
      ]);
      return jsonMetric(summary.data, hours, {
        recent: recent.data,
        error: summary.error ?? recent.error,
      });
    }
    case "attack-timeline": {
      if (!(await tableExists("ban_audit"))) {
        const labels = await clickhouseQuery(
          `SELECT label_time AS event_time, replaceOne(toString(src_ip), '::ffff:', '') AS src_ip,
            'attack_label' AS event_type, mitre_technique AS detail, phase AS severity
           FROM attack_labels WHERE label_time >= now() - INTERVAL {hours:UInt32} HOUR
           ORDER BY event_time DESC LIMIT {limit:UInt32}`,
          { hours, limit },
        );
        return jsonMetric(labels.data, hours, { ban_audit_missing: true }, labels.error);
      }
      const result = await clickhouseQuery(ATTACK_TIMELINE_QUERY, { hours, limit });
      return jsonMetric(result.data, hours, undefined, result.error);
    }
    case "stack-health": {
      async function tableFreshness(
        table: string,
        timeColumn: string,
        where = "",
      ): Promise<{ row_count: number; latest_event: string | null }> {
        if (!(await tableExists(table))) {
          return { row_count: 0, latest_event: null };
        }
        const filterClause = where.replace(/^AND\s+/i, "").trim();
        const windowFilter = filterClause
          ? `${timeColumn} >= now() - INTERVAL {hours:UInt32} HOUR AND ${filterClause}`
          : `${timeColumn} >= now() - INTERVAL {hours:UInt32} HOUR`;
        const tableFilter = filterClause ? `WHERE ${filterClause}` : "";

        const result = await clickhouseQuery<{
          row_count: number;
          latest_event: string | null;
        }>(
          `SELECT
             countIf(${windowFilter}) AS row_count,
             max(${timeColumn}) AS latest_event
           FROM ${table}
           ${tableFilter}`,
          { hours },
        );
        return result.data[0] ?? { row_count: 0, latest_event: null };
      }

      function sipPlaneRow(
        component: string,
        role: string,
        fresh: { row_count: number; latest_event: string | null },
        signal: string,
      ): ServiceHealthRow {
        const status = sipPlaneStatus(fresh.latest_event, hours, fresh.row_count);
        const detail =
          status === "healthy" && fresh.latest_event
            ? `${signal}: latest ${fresh.latest_event}`
            : `${signal}: no recent rows in ${hours}h window`;
        return {
          component,
          role,
          status,
          detail,
          row_count: fresh.row_count,
          latest_event: fresh.latest_event,
        };
      }

      const [sipFresh, suricataFresh, httpProbes] = await Promise.all([
        tableFreshness("sip_events", "event_time"),
        tableFreshness("suricata_alerts", "event_time"),
        Promise.all([
          probeHttp(
            "http://keycloak:8080/realms/master",
            (res) => res.status === 200,
          ),
          probeHttp("http://ollama:11434/api/tags", (res) => res.status === 200),
          probeHttp(
            "http://clickhouse:8123/ping",
            (res, body) => res.status === 200 && body.trim().replace(/\.$/, "") === "Ok",
          ),
          probeHttp(
            "http://prometheus:9090/-/healthy",
            (res) => res.status === 200,
          ),
          probeHttp("http://grafana:3000/api/health", (res) => res.status === 200),
          probeHttp(
            "http://shuffle-backend:5001/api/v1/health",
            (res) => res.ok,
            { treatRefusedAsNotDeployed: true, reachableIsHealthy: true },
          ),
        ]),
      ]);

      const [keycloakProbe, ollamaProbe, clickhouseProbe, prometheusProbe, grafanaProbe, shuffleProbe] =
        httpProbes;

      const services: ServiceHealthRow[] = [
        sipPlaneRow("kamailio", "SIP proxy / SBC", sipFresh, "sip_events"),
        sipPlaneRow("asterisk", "Media server", sipFresh, "sip_events"),
        sipPlaneRow("rtpengine", "Media relay", sipFresh, "sip_events"),
        sipPlaneRow("suricata", "IDS / SIP capture", suricataFresh, "suricata_alerts"),
        sipPlaneRow("vector", "Log shipper", sipFresh, "sip_events"),
        {
          component: "clickhouse",
          role: "Analytics store",
          status: clickhouseProbe.status,
          detail: clickhouseProbe.detail,
          row_count: sipFresh.row_count + suricataFresh.row_count,
          latest_event: sipFresh.latest_event ?? suricataFresh.latest_event,
        },
        {
          component: "prometheus",
          role: "Metrics TSDB",
          status: prometheusProbe.status,
          detail: prometheusProbe.detail,
          row_count: 0,
          latest_event: null,
        },
        {
          component: "grafana",
          role: "Observability UI",
          status: grafanaProbe.status,
          detail: grafanaProbe.detail,
          row_count: 0,
          latest_event: null,
        },
        {
          component: "keycloak",
          role: "OIDC IdP",
          status: keycloakProbe.status,
          detail: keycloakProbe.detail,
          row_count: 0,
          latest_event: null,
        },
        {
          component: "ollama",
          role: "LLM runtime",
          status: ollamaProbe.status,
          detail: ollamaProbe.detail,
          row_count: 0,
          latest_event: null,
        },
        {
          component: "shuffle",
          role: "SOAR orchestrator",
          status: shuffleProbe.status,
          detail: shuffleProbe.detail,
          row_count: 0,
          latest_event: null,
        },
      ];

      const rows: StackHealthRow[] = services.map((row) => ({
        ...toStackHealthRow(row),
        detail: row.detail,
      }));

      return jsonMetric(rows, hours, {
        probe_timeout_ms: 1500,
        sip_plane_signal: "sip_events and suricata_alerts recency for core compose services",
      });
    }
    case "demo-timeline": {
      const result = await fetchDemoTimeline(hours, limit);
      return jsonMetric(result.events, hours, {
        src_ip: result.src_ip,
        attack_id: result.attack_id,
        mitre_technique: result.mitre_technique,
        phase: result.phase,
        summary: result.summary,
        stage_highlights: result.stage_highlights,
        demo_hours: result.demo_hours,
        error: result.error,
      });
    }
    case "pipeline-summary": {
      async function countInWindow(
        table: string,
        timeColumn: string,
        where = "",
      ): Promise<number> {
        if (!(await tableExists(table))) return 0;
        const filterClause = where.replace(/^AND\s+/i, "").trim();
        const windowFilter = filterClause
          ? `${timeColumn} >= now() - INTERVAL {hours:UInt32} HOUR AND ${filterClause}`
          : `${timeColumn} >= now() - INTERVAL {hours:UInt32} HOUR`;
        const result = await clickhouseQuery<{ count: number }>(
          `SELECT countIf(${windowFilter}) AS count FROM ${table}`,
          { hours },
        );
        return result.data[0]?.count ?? 0;
      }

      const [
        sipEvents,
        suricataAlerts,
        wazuhSip,
        mlScores,
        llmVerdicts,
        banActions,
        soarCases,
        attackLabels,
      ] = await Promise.all([
        countInWindow("sip_events", "event_time"),
        countInWindow("suricata_alerts", "event_time"),
        countInWindow("wazuh_alerts", "alert_time", "AND rule_id BETWEEN 100100 AND 100199"),
        tableExists("ml_scores").then((exists) =>
          exists ? countInWindow("ml_scores", "scored_at") : 0,
        ),
        tableExists("llm_verdicts").then((exists) =>
          exists ? countInWindow("llm_verdicts", "verdict_time") : 0,
        ),
        tableExists("ban_audit").then((exists) =>
          exists ? countInWindow("ban_audit", "event_time") : 0,
        ),
        tableExists("soar_cases").then((exists) =>
          exists ? countInWindow("soar_cases", "case_time") : 0,
        ),
        tableExists("attack_labels").then((exists) =>
          exists ? countInWindow("attack_labels", "label_time") : 0,
        ),
      ]);

      return jsonMetric([], hours, {
        sip_events: sipEvents,
        suricata_alerts: suricataAlerts,
        wazuh_sip: wazuhSip,
        ml_scores: mlScores,
        llm_verdicts: llmVerdicts,
        ban_audit: banActions,
        soar_cases: soarCases,
        attack_labels: attackLabels,
      });
    }
    default:
      return NextResponse.json({ error: "Unknown metric" }, { status: 400 });
  }
}
