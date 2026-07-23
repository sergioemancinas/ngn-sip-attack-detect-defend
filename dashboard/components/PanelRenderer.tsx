"use client";

import type { PanelId } from "@/types/layout";
import { SipResponsesPanel } from "@/components/panels/SipResponsesPanel";
import { TopSourcesPanel } from "@/components/panels/TopSourcesPanel";
import { CdrPanel } from "@/components/panels/CdrPanel";
import { RegisterPanel } from "@/components/panels/RegisterPanel";
import { SuricataPanel } from "@/components/panels/SuricataPanel";
import { WazuhPanel } from "@/components/panels/WazuhPanel";
import { MlScoresPanel } from "@/components/panels/MlScoresPanel";
import { LlmVerdictsPanel } from "@/components/panels/LlmVerdictsPanel";
import { BanAuditPanel } from "@/components/panels/BanAuditPanel";
import { SoarCasesPanel } from "@/components/panels/SoarCasesPanel";
import { AttackTimelinePanel } from "@/components/panels/AttackTimelinePanel";
import { StackHealthPanel } from "@/components/panels/StackHealthPanel";
import { C3SummaryPanel } from "@/components/panels/C3SummaryPanel";

export function PanelRenderer({
  panelId,
  hours,
  refreshMs,
}: {
  panelId: PanelId;
  hours: number;
  refreshMs: number;
}) {
  switch (panelId) {
    case "sip-responses":
      return <SipResponsesPanel hours={hours} refreshMs={refreshMs} />;
    case "top-sources":
      return <TopSourcesPanel hours={hours} refreshMs={refreshMs} />;
    case "cdr-grid":
      return <CdrPanel hours={hours} refreshMs={refreshMs} />;
    case "register-chart":
      return <RegisterPanel hours={hours} refreshMs={refreshMs} />;
    case "suricata-rate":
      return <SuricataPanel hours={hours} refreshMs={refreshMs} />;
    case "wazuh-sip":
      return <WazuhPanel hours={hours} refreshMs={refreshMs} />;
    case "ml-scores":
      return <MlScoresPanel hours={hours} refreshMs={refreshMs} />;
    case "llm-verdicts":
      return <LlmVerdictsPanel hours={hours} refreshMs={refreshMs} />;
    case "ban-audit":
      return <BanAuditPanel hours={hours} refreshMs={refreshMs} />;
    case "soar-cases":
      return <SoarCasesPanel hours={hours} refreshMs={refreshMs} />;
    case "attack-timeline":
      return <AttackTimelinePanel hours={hours} refreshMs={refreshMs} />;
    case "stack-health":
      return <StackHealthPanel hours={hours} refreshMs={refreshMs} />;
    case "c3-summary":
      return <C3SummaryPanel />;
    default:
      return null;
  }
}
