"use client";

import { Fragment } from "react";
import type { PipelineStageId } from "@/lib/pipeline-stages";
import { cn } from "@/lib/utils";

export type DiagramStageId = PipelineStageId | "observe";

/**
 * Pure CSS column layout. Each pipeline stage is a flex column; flow moves
 * strictly left to right with one chevron per lane boundary. Because the
 * browser lays nodes out with flexbox, boxes and connectors can never overlap
 * at any width (narrow screens scroll horizontally instead of colliding).
 */

type LaneTone = "external" | "ingress" | "detect" | "decide" | "respond" | "observe";

interface NodeDef {
  id: string;
  label: string;
  sub: string;
}

interface LaneDef {
  id: LaneTone;
  label: string;
  caption: string;
  nodes: NodeDef[];
}

const LANES: LaneDef[] = [
  {
    id: "external",
    label: "External",
    caption: "Attack surface",
    nodes: [
      { id: "internet", label: "Internet actors", sub: "bots · UAs" },
      { id: "scanners", label: "SIP scanners", sub: "sippts probes" },
      { id: "pstn", label: "PSTN / trunk", sub: "carrier SIP" },
      { id: "frontdoor", label: "Public SIP edge", sub: "5060 · 5061 · RTP" },
    ],
  },
  {
    id: "ingress",
    label: "Ingress",
    caption: "SBC",
    nodes: [{ id: "kamailio", label: "Kamailio SBC", sub: "NGN-SEC · PIKE" }],
  },
  {
    id: "detect",
    label: "Detect",
    caption: "Signature + SIEM",
    nodes: [
      { id: "suricata", label: "Suricata IDS", sub: "sip_events" },
      { id: "wazuh", label: "Wazuh SIEM", sub: "rules 100100-199" },
    ],
  },
  {
    id: "decide",
    label: "Decide",
    caption: "ML + LLM",
    nodes: [
      { id: "stage1", label: "Stage 1 ML", sub: "XGBoost + IsoForest" },
      { id: "stage2", label: "Stage 2 LLM", sub: "Ollama advisory" },
    ],
  },
  {
    id: "respond",
    label: "Respond",
    caption: "Enforce",
    nodes: [
      { id: "autoban", label: "autoban", sub: "ban_audit" },
      { id: "soar", label: "Shuffle SOAR", sub: "soar_cases" },
    ],
  },
  {
    id: "observe",
    label: "Observe",
    caption: "Evidence",
    nodes: [
      { id: "clickhouse", label: "ClickHouse", sub: "ngn_sip.*" },
      { id: "grafana", label: "Grafana", sub: "D1-D7" },
      { id: "dashboard", label: "Dashboard", sub: "this UI" },
      { id: "keycloak", label: "Keycloak", sub: "OIDC SSO" },
    ],
  },
];

const STAGE_TO_LANE: Record<DiagramStageId, LaneTone> = {
  attack: "external",
  sbc: "ingress",
  detect: "detect",
  stage1: "decide",
  stage2: "decide",
  respond: "respond",
  observe: "observe",
};

const STAGE_ACTIVE_NODES: Record<DiagramStageId, string[]> = {
  attack: ["internet", "scanners", "pstn", "frontdoor"],
  sbc: ["kamailio"],
  detect: ["suricata", "wazuh"],
  stage1: ["stage1"],
  stage2: ["stage2"],
  respond: ["autoban", "soar"],
  observe: ["clickhouse", "grafana", "dashboard", "keycloak"],
};

interface ToneStyle {
  dot: string;
  laneRing: string;
  nodeActive: string;
  label: string;
}

const TONE_STYLES: Record<LaneTone, ToneStyle> = {
  external: {
    dot: "bg-accent-muted",
    laneRing: "border-accent-muted/50 bg-accent-muted/[0.07]",
    nodeActive: "border-accent-muted/70 bg-accent-muted/10 ring-1 ring-accent-muted/30",
    label: "text-accent-muted",
  },
  ingress: {
    dot: "bg-accent",
    laneRing: "border-accent/50 bg-accent/[0.07]",
    nodeActive: "border-accent/70 bg-accent/10 ring-1 ring-accent/30",
    label: "text-accent",
  },
  detect: {
    dot: "bg-accent-amber",
    laneRing: "border-accent-amber/50 bg-accent-amber/[0.07]",
    nodeActive: "border-accent-amber/70 bg-accent-amber/10 ring-1 ring-accent-amber/30",
    label: "text-accent-amber",
  },
  decide: {
    dot: "bg-accent-purple",
    laneRing: "border-accent-purple/50 bg-accent-purple/[0.07]",
    nodeActive: "border-accent-purple/70 bg-accent-purple/10 ring-1 ring-accent-purple/30",
    label: "text-accent-purple",
  },
  respond: {
    dot: "bg-accent-red",
    laneRing: "border-accent-red/50 bg-accent-red/[0.07]",
    nodeActive: "border-accent-red/70 bg-accent-red/10 ring-1 ring-accent-red/30",
    label: "text-accent-red",
  },
  observe: {
    dot: "bg-accent-green",
    laneRing: "border-accent-green/50 bg-accent-green/[0.07]",
    nodeActive: "border-accent-green/70 bg-accent-green/10 ring-1 ring-accent-green/30",
    label: "text-accent-green",
  },
};

export function ArchitectureDiagram({
  activeStage,
  animate = false,
}: {
  activeStage?: DiagramStageId;
  animate?: boolean;
}) {
  const activeLane = activeStage ? STAGE_TO_LANE[activeStage] : null;
  const activeNodes = new Set(activeStage ? STAGE_ACTIVE_NODES[activeStage] : []);
  const highlightMode = activeNodes.size > 0;

  return (
    <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-4 shadow-card sm:p-5">
      <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold text-text-primary">Pipeline architecture</h3>
          <p className="mt-0.5 text-xs text-text-muted">
            External ingress through layered detection, decision, response, and observability sinks
          </p>
        </div>
        <p className="text-[10px] text-text-muted">
          SIP_BIND_IP gates exposure · loopback management plane
        </p>
      </div>

      <div className="overflow-x-auto pb-2">
        <div className="flex min-w-[840px] items-stretch">
          {LANES.map((lane, index) => {
            const tone = TONE_STYLES[lane.id];
            const isActiveLane = activeLane === lane.id;
            const isDimmed = highlightMode && !isActiveLane;
            return (
              <Fragment key={lane.id}>
                <div
                  className={cn(
                    "flex flex-1 flex-col rounded-xl border p-2.5 transition-all duration-300",
                    isActiveLane
                      ? cn(tone.laneRing, animate && "motion-safe:animate-pulse")
                      : "border-surface-border/70 bg-surface/40",
                    isDimmed && "opacity-40",
                  )}
                >
                  <div className="mb-2 flex items-center gap-1.5 px-0.5">
                    <span className={cn("h-2 w-2 shrink-0 rounded-full", tone.dot)} aria-hidden />
                    <span
                      className={cn(
                        "text-[10px] font-semibold uppercase tracking-[0.12em]",
                        isActiveLane ? tone.label : "text-text-muted",
                      )}
                    >
                      {lane.label}
                    </span>
                  </div>
                  <p className="mb-2 px-0.5 text-[9px] uppercase tracking-wider text-text-muted/70">
                    {lane.caption}
                  </p>
                  <div className="flex flex-1 flex-col justify-center gap-2">
                    {lane.nodes.map((node) => {
                      const isActiveNode = activeNodes.has(node.id);
                      return (
                        <div
                          key={node.id}
                          className={cn(
                            "rounded-lg border px-2.5 py-2 text-center transition-all duration-300",
                            isActiveNode
                              ? cn(tone.nodeActive, "shadow-card")
                              : "border-surface-border bg-surface-raised/80",
                          )}
                        >
                          <p
                            className={cn(
                              "truncate text-[11px] font-semibold",
                              isActiveNode ? "text-text-primary" : "text-text-secondary",
                            )}
                          >
                            {node.label}
                          </p>
                          <p className="mt-0.5 truncate font-mono text-[9px] text-text-muted">
                            {node.sub}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {index < LANES.length - 1 ? (
                  <LaneChevron active={isActiveLane || activeLane === LANES[index + 1].id} />
                ) : null}
              </Fragment>
            );
          })}
        </div>
      </div>

      <FlowLegend />
    </div>
  );
}

function LaneChevron({ active }: { active: boolean }) {
  return (
    <div className="flex w-6 shrink-0 items-center justify-center sm:w-8" aria-hidden>
      <svg
        viewBox="0 0 16 16"
        className={cn(
          "h-4 w-4 transition-colors duration-300",
          active ? "text-accent" : "text-text-muted/50",
        )}
        fill="none"
      >
        <path
          d="M5 3l5 5-5 5"
          stroke="currentColor"
          strokeWidth="1.75"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </div>
  );
}

function FlowLegend() {
  return (
    <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1.5 border-t border-surface-border/60 pt-3 text-[10px] text-text-muted">
      <span className="flex items-center gap-1.5">
        <span className="inline-block h-1.5 w-1.5 rounded-full bg-accent" aria-hidden />
        Forward flow: signaling and alerts move left to right through each stage
      </span>
      <span className="flex items-center gap-1.5">
        <span className="inline-block h-1.5 w-1.5 rounded-full bg-accent-red" aria-hidden />
        Response loops back: autoban edge drop and SOAR analyst notify
      </span>
      <span className="flex items-center gap-1.5">
        <span className="inline-block h-1.5 w-1.5 rounded-full bg-accent-green" aria-hidden />
        Telemetry from every stage lands in ClickHouse
      </span>
    </div>
  );
}
