"use client";

import { SectionHeader } from "@/components/SectionHeader";
import { SectionPanelGrid } from "@/components/SectionPanelGrid";
import { SectionNote } from "@/components/ui/SectionNote";
import { KpiStrip } from "@/components/KpiStrip";
import { ArchitectureDiagram } from "@/components/how-it-works/ArchitectureDiagram";
import { LlmExplainer } from "@/components/how-it-works/LlmExplainer";
import { MlExplainer } from "@/components/how-it-works/MlExplainer";
import { Stage1EvalSection } from "@/components/ml/Stage1EvalSection";
import { DetectionRulesExplainer } from "@/components/panels/DetectionRulesExplainer";
import { GrafanaObservabilitySection } from "@/components/panels/GrafanaObservabilitySection";
import { ResponseArmsSection } from "@/components/panels/ResponseArmsSection";
import { ShuffleSoarSection } from "@/components/panels/ShuffleSoarSection";
import { SourcesReferencesSection } from "@/components/panels/SourcesReferencesSection";
import { RelatedWorkSection } from "@/components/panels/RelatedWorkSection";
import {
  PipelineStatusBadges,
  PipelineStepper,
} from "@/components/how-it-works/PipelineStepper";
import { ComponentLegend } from "@/components/how-it-works/ComponentLegend";
import { DemoSection } from "@/components/demo/DemoSection";
import { LiveEventsLog } from "@/components/panels/LiveEventsLog";
import { SipTrafficBreakdown } from "@/components/panels/SipTrafficBreakdown";
import type { DashboardSection } from "@/lib/sections";

// Course project credit. Edit these strings to update the Overview attribution.
const PROJECT_CREDIT = {
  author: "Sergio Mancinas",
  course: "Next Generation Networks (NGN)",
  programme: "MSc Next Generation Networks, TH Köln",
} as const;

function ProjectCredit() {
  return (
    <div className="panel-card flex flex-wrap items-center justify-between gap-x-6 gap-y-2 px-5 py-4">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-1.5 text-xs">
        <div>
          <span className="text-text-muted">Author </span>
          <span className="font-medium text-text-secondary">{PROJECT_CREDIT.author}</span>
        </div>
        <div>
          <span className="text-text-muted">Course </span>
          <span className="font-medium text-text-secondary">{PROJECT_CREDIT.course}</span>
        </div>
      </div>
      <p className="text-[10px] uppercase tracking-[0.14em] text-text-muted">
        {PROJECT_CREDIT.programme}
      </p>
    </div>
  );
}

function OverviewHero() {
  const pillars = [
    {
      label: "Ingress",
      detail: "Kamailio SBC, rtpengine, labeled sippts campaigns",
    },
    {
      label: "Detect",
      detail: "Suricata, Wazuh 100100-199, Stage 1 ML, Stage 2 LLM",
    },
    {
      label: "Respond",
      detail: "kamailio-autoban, Shuffle SOAR, ban_audit trail",
    },
    {
      label: "Observe",
      detail: "ClickHouse evidence store, Grafana D1-D7, this dashboard",
    },
  ];

  return (
    <div className="panel-card panel-card-accent overflow-hidden">
      <div className="grid gap-6 p-6 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)] lg:p-8">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="relative flex h-2 w-2" aria-hidden>
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent-green/70" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-accent-green" />
            </span>
            <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-accent">
              NGN course lab · TH Köln · Live
            </p>
          </div>
          <h3 className="mt-2.5 text-display-md text-text-primary">
            SIP attack-detect-defend operations view
          </h3>
          <p className="mt-3 max-w-2xl text-sm leading-relaxed text-text-secondary">
            A reproducible campus VM testbed. Labeled recon traffic flows through layered detection,
            Stage 1 ML scoring, advisory Stage 2 LLM triage, and deterministic response. ClickHouse
            holds the evidence and this dashboard reads it server-side.
          </p>
        </div>
        <div className="grid grid-cols-2 gap-3">
          {pillars.map((pillar, index) => (
            <div
              key={pillar.label}
              className="group relative overflow-hidden rounded-lg border border-surface-border/80 bg-surface/40 p-3 transition-all duration-300 hover:-translate-y-0.5 hover:border-accent/30 hover:bg-surface-overlay/30"
            >
              <div className="flex items-center justify-between">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-accent">
                  {pillar.label}
                </p>
                <span className="font-mono text-[10px] tabular-nums text-text-muted/70">
                  {String(index + 1).padStart(2, "0")}
                </span>
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-text-muted">{pillar.detail}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function C3Callout() {
  return (
    <div className="panel-card p-5">
      <h3 className="text-sm font-semibold text-text-primary">C3 detector comparison (June 2026)</h3>
      <div className="mt-3 grid gap-3 text-sm md:grid-cols-3">
        <div className="rounded-lg border border-surface-border bg-surface-raised/60 p-3">
          <p className="text-[10px] font-medium uppercase text-text-muted">Suricata + Wazuh IOC</p>
          <p className="mt-1 text-text-secondary">Recall ~0.71, FP 1.00 on benign arm</p>
        </div>
        <div className="rounded-lg border border-surface-border bg-surface-raised/60 p-3">
          <p className="text-[10px] font-medium uppercase text-text-muted">Wazuh PIKE (100103)</p>
          <p className="mt-1 text-text-secondary">Recall ~0.14, FP 0.00</p>
        </div>
        <div className="rounded-lg border border-surface-border bg-surface-raised/60 p-3">
          <p className="text-[10px] font-medium uppercase text-text-muted">Behavioural ML</p>
          <p className="mt-1 text-text-secondary">F1 0.75 [0.68, 0.81], adds specificity</p>
        </div>
      </div>
      <p className="mt-3 text-xs leading-relaxed text-text-muted">
        Source-IP level results from the C3 campaign. The full three-arm table and 95% CI are in the
        C3 detector comparison panel above.
      </p>
    </div>
  );
}

export function SectionView({
  section,
  hours,
  refreshMs,
}: {
  section: DashboardSection;
  hours: number;
  refreshMs: number;
}) {
  switch (section.id) {
    case "overview":
      return (
        <div className="section-stack">
          <OverviewHero />
          <SectionHeader
            title={section.title}
            subtitle={section.subtitle}
            description={section.description}
          />
          <KpiStrip hours={hours} refreshMs={refreshMs} />
          <ArchitectureDiagram />
          <SectionNote
            shows="The full topology, from the public SIP edge to the response and observability sinks."
            implements="Static diagram aligned to the Docker Compose services on the campus VM. The KPIs above read ClickHouse via /api/metrics."
          />
          <div className="panel-card p-5 sm:p-6">
            <h3 className="text-sm font-semibold text-text-primary">Project summary</h3>
            <p className="mt-2 text-sm leading-relaxed text-text-secondary">
              The lab runs 18 containers on the campus VM. Management ports bind to loopback and SIP
              exposure is gated by SIP_BIND_IP. Every detection and response stage is measured
              against the labeled sippts campaigns.
            </p>
          </div>
          <ProjectCredit />
        </div>
      );

    case "demo":
      return <DemoSection hours={hours} />;

    case "sip":
      return (
        <div className="space-y-5">
          <SectionHeader
            title={section.title}
            subtitle={section.subtitle}
            description={section.description}
          />
          <SipTrafficBreakdown hours={hours} refreshMs={refreshMs} />
          <SectionPanelGrid panelIds={section.panelIds} hours={hours} refreshMs={refreshMs} />
          <LiveEventsLog<{
            event_time: string;
            src_ip: string;
            method: string;
            response: string;
          }>
            metric="sip-events-recent"
            title="Live events"
            caption="Recent sip_events (newest first)"
            hours={hours}
            columns={[
              { key: "event_time", label: "Time" },
              { key: "src_ip", label: "Source" },
              { key: "method", label: "Method" },
              { key: "response", label: "Response" },
            ]}
          />
          <SectionNote
            shows="Signaling volume, response mix, REGISTER behaviour, and CDR-style aggregates from the Kamailio path."
            implements="All panels query ngn_sip.sip_events (and attack_labels / ban_audit joins) server-side; QoS columns await HEP RTCP ingest."
          />
        </div>
      );

    case "detection":
      return (
        <div className="space-y-5">
          <SectionHeader
            title={section.title}
            subtitle={section.subtitle}
            description={section.description}
          />
          <DetectionRulesExplainer />
          <SectionPanelGrid panelIds={section.panelIds} hours={hours} refreshMs={refreshMs} />
          <LiveEventsLog<{
            event_time: string;
            source: string;
            rule: string;
            level: string;
            src: string;
          }>
            metric="detection-live"
            title="Live events"
            caption="Recent suricata_alerts and wazuh_alerts (newest first)"
            hours={hours}
            columns={[
              { key: "event_time", label: "Time" },
              {
                key: "source",
                label: "Source",
                render: (row) => (
                  <span className="uppercase text-text-muted">{row.source}</span>
                ),
              },
              { key: "rule", label: "Rule" },
              { key: "level", label: "Level", className: "numeric" },
              { key: "src", label: "Src IP" },
            ]}
          />
          <C3Callout />
          <SectionNote
            shows="Signature IDS alert rate and Wazuh SIP rule hits for the selected window."
            implements="suricata_alerts and Wazuh-mirrored alerts in ClickHouse. C3 numbers come from the June 2026 grouped eval protocol."
          />
        </div>
      );

    case "ml":
      return (
        <div className="space-y-5">
          <SectionHeader
            title={section.title}
            subtitle={section.subtitle}
            description={section.description}
          />
          <MlExplainer />
          <Stage1EvalSection />
          <SectionPanelGrid panelIds={section.panelIds} hours={hours} refreshMs={refreshMs} />
          <LiveEventsLog<{
            event_time: string;
            src_ip: string;
            predicted_class: string;
            proba: number;
          }>
            metric="ml-scores-recent"
            title="Live events"
            caption="Recent ml_scores (newest first)"
            hours={hours}
            columns={[
              { key: "event_time", label: "Time" },
              { key: "src_ip", label: "Source" },
              { key: "predicted_class", label: "Class" },
              {
                key: "proba",
                label: "Proba",
                className: "numeric",
                render: (row) => row.proba.toFixed(3),
              },
            ]}
            emptyMessage="No ml_scores in window (Stage 1 scorer may be idle)."
          />
          <SectionNote
            shows="Static grouped-CV evaluation (June 2026) plus live scorer output from ml_scores for the selected window."
            implements="Eval metrics are baked from docs/results/stage1_metrics_grouped_2026-06-10.json; live charts poll /api/metrics?metric=ml-scores."
          />
        </div>
      );

    case "llm":
      return (
        <div className="space-y-5">
          <SectionHeader
            title={section.title}
            subtitle={section.subtitle}
            description={section.description}
          />
          <LlmExplainer />
          <SectionPanelGrid panelIds={section.panelIds} hours={hours} refreshMs={refreshMs} />
          <LiveEventsLog<{
            verdict_time: string;
            src_ip: string;
            verdict: string;
            confidence: number;
          }>
            metric="llm-verdicts-recent"
            title="Live events"
            caption="Recent llm_verdicts (newest first)"
            hours={hours}
            columns={[
              { key: "verdict_time", label: "Time" },
              { key: "src_ip", label: "Source" },
              { key: "verdict", label: "Verdict" },
              {
                key: "confidence",
                label: "Conf.",
                className: "numeric",
                render: (row) => row.confidence.toFixed(3),
              },
            ]}
            emptyMessage="No llm_verdicts in window (Stage 2 runs on high-severity Wazuh alerts)."
          />
          <SectionNote
            shows="Advisory verdict confidence over time for the selected window."
            implements="Stage 2 worker (ml/stage2/worker.py) writes llm_verdicts after Ollama JSON validation and guardrails."
          />
        </div>
      );

    case "response":
      return (
        <div className="space-y-5">
          <SectionHeader
            title={section.title}
            subtitle={section.subtitle}
            description={section.description}
          />
          <ResponseArmsSection hours={hours} refreshMs={refreshMs} />
          <SectionPanelGrid
            panelIds={section.panelIds.filter((id) => id !== "ban-audit" && id !== "soar-cases")}
            hours={hours}
            refreshMs={refreshMs}
          />
          <LiveEventsLog<{
            event_time: string;
            source: string;
            src: string;
            action: string;
            detail: string;
          }>
            metric="response-live"
            title="Live events"
            caption="Recent ban_audit and soar_cases (newest first)"
            hours={hours}
            columns={[
              { key: "event_time", label: "Time" },
              {
                key: "source",
                label: "Table",
                render: (row) => (
                  <span className="text-text-muted">{row.source.replace("_", " ")}</span>
                ),
              },
              { key: "src", label: "Source" },
              { key: "action", label: "Action" },
              { key: "detail", label: "Detail" },
            ]}
          />
          <SectionNote
            shows="Deterministic autoban actions, SOAR orchestration outcomes, and attack_labels timeline against enforcement."
            implements="ban_audit from kamailio-autoban (rule_level >= 10); soar_cases when Shuffle Stage 3 is deployed; timeline unions labels and bans."
          />
        </div>
      );

    case "shuffle":
      return (
        <div className="space-y-5">
          <SectionHeader
            title={section.title}
            subtitle={section.subtitle}
            description={section.description}
          />
          <ShuffleSoarSection hours={hours} refreshMs={refreshMs} />
          <SectionNote
            shows="The Shuffle SOAR layer in depth: the webhook-to-case playbook, graded_action distribution, and recent soar_cases with their Wazuh, Stage-2, and Stage-1 evidence."
            implements="Reads the soar-cases metric (SOAR_CASES_SUMMARY_QUERY and SOAR_CASES_RECENT_QUERY) from ClickHouse; shows a not-deployed state when the soar_cases table is absent."
          />
        </div>
      );

    case "how-it-works":
      return (
        <div className="space-y-5">
          <SectionHeader
            title={section.title}
            subtitle={section.subtitle}
            description={section.description}
          />
          <div className="flex flex-wrap items-center justify-end gap-2">
            <PipelineStatusBadges hours={hours} refreshMs={refreshMs} />
          </div>
          <PipelineStepper hours={hours} refreshMs={refreshMs} />
          <ComponentLegend />
          <SectionNote
            shows="Interactive pipeline walkthrough with live row counts per stage and architecture legend."
            implements="PipelineStepper polls /api/metrics via lib/pipeline-counts.ts; ArchitectureDiagram highlights active nodes per stage."
          />
        </div>
      );

    case "sources":
      return (
        <div className="section-stack">
          <SectionHeader
            title={section.title}
            subtitle={section.subtitle}
            description={section.description}
          />
          <RelatedWorkSection />
          <SourcesReferencesSection />
          <SectionNote
            shows="Prior work and the tools each stage depends on, grouped by type."
            implements="Reference cards; links open public documentation in a new tab."
          />
        </div>
      );

    default:
      return (
        <div className="space-y-5">
          <SectionHeader
            title={section.title}
            subtitle={section.subtitle}
            description={section.description}
          />
          {section.id === "stack-health" ? (
            <GrafanaObservabilitySection
              panelIds={["system-health"]}
              title="Grafana stack health"
              description="D5 System Health panel for ClickHouse table freshness alongside the in-app health grid."
            />
          ) : null}
          <SectionPanelGrid panelIds={section.panelIds} hours={hours} refreshMs={refreshMs} />
        </div>
      );
  }
}
