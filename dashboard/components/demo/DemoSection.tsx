"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { SectionHeader } from "@/components/SectionHeader";
import { SectionNote } from "@/components/ui/SectionNote";
import {
  DemoNarrativeHeader,
  DemoPipelineSummary,
  DemoRunCard,
  type DemoRunResult,
} from "@/components/demo/DemoCards";
import { DemoTimelinePanel, parseSummary } from "@/components/demo/DemoTimeline";
import { LiveEventsLog } from "@/components/panels/LiveEventsLog";
import { HoneypotAttackersPanel } from "@/components/panels/HoneypotAttackersPanel";
import { useMetric } from "@/components/hooks/useMetric";
import type { DemoTimelineEvent } from "@/types/layout";

const DEMO_REFRESH_MS = 5000;
const DEMO_BOOST_REFRESH_MS = 2000;
const DEMO_BOOST_DURATION_MS = 60_000;

export function DemoSection({ hours }: { hours: number }) {
  const [running, setRunning] = useState(false);
  const [runResult, setRunResult] = useState<DemoRunResult | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [boostUntil, setBoostUntil] = useState<number | null>(null);
  const [refetchNonce, setRefetchNonce] = useState(0);
  const [now, setNow] = useState(() => Date.now());

  const boostActive = boostUntil !== null && now < boostUntil;
  const refreshMs = boostActive ? DEMO_BOOST_REFRESH_MS : DEMO_REFRESH_MS;

  useEffect(() => {
    if (!boostUntil) return;
    if (Date.now() >= boostUntil) {
      setBoostUntil(null);
      return;
    }
    const tick = window.setInterval(() => setNow(Date.now()), 1000);
    const end = window.setTimeout(() => {
      setBoostUntil(null);
      setNow(Date.now());
    }, boostUntil - Date.now());
    return () => {
      window.clearInterval(tick);
      window.clearTimeout(end);
    };
  }, [boostUntil]);

  const { meta } = useMetric<DemoTimelineEvent>(
    "demo-timeline",
    hours,
    refreshMs,
    { limit: "80" },
    refetchNonce,
  );

  const srcIp = typeof meta?.src_ip === "string" ? meta.src_ip : null;
  const mitre = typeof meta?.mitre_technique === "string" ? meta.mitre_technique : "";
  const phase = typeof meta?.phase === "string" ? meta.phase : "";
  const attackId = typeof meta?.attack_id === "string" ? meta.attack_id : "";
  const summary = parseSummary(meta);
  const live = Object.values(summary).some((count) => (count ?? 0) > 0);

  const handleRunDemo = useCallback(async () => {
    setRunning(true);
    setRunError(null);
    setRunResult(null);

    try {
      const res = await fetch("/api/demo/run", { method: "POST", cache: "no-store" });
      const json = (await res.json()) as DemoRunResult & { error?: string };

      if (!res.ok) {
        setRunError(
          json.detail ??
            json.error ??
            "Demo runner unavailable. Ensure the demo-runner service is running on the lab network.",
        );
        return;
      }

      setRunResult({
        run_id: json.run_id,
        status: json.status,
        detail: json.detail,
      });
      setBoostUntil(Date.now() + DEMO_BOOST_DURATION_MS);
      setRefetchNonce((value) => value + 1);
    } catch {
      setRunError(
        "Could not reach the demo runner. Check network connectivity to the lab demo-runner service.",
      );
    } finally {
      setRunning(false);
    }
  }, []);

  const boostRemainingSec = useMemo(() => {
    if (!boostActive || boostUntil === null) return 0;
    return Math.max(0, Math.ceil((boostUntil - now) / 1000));
  }, [boostActive, boostUntil, now]);

  return (
    <div className="section-stack">
      <SectionHeader
        title="Live threats and honeypot intelligence"
        subtitle="Real internet attackers captured on the exposed SIP edge"
        description="The SIP edge is publicly exposed, so this shows the real attackers hitting it in real time: who they are, what they are doing, why each was flagged, and how the pipeline responds. Security Insights aggregates open-source threat intelligence across every captured source."
      />

      <HoneypotAttackersPanel hours={hours} refreshMs={refreshMs} />

      <DemoNarrativeHeader
        srcIp={srcIp}
        mitre={mitre}
        phase={phase}
        attackId={attackId}
        live={live}
        boostActive={boostActive}
      />

      <div className="grid gap-5 xl:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
        <div className="section-stack-compact">
          <DemoTimelinePanel
            hours={hours}
            refreshMs={refreshMs}
            refetchNonce={refetchNonce}
          />
          <DemoPipelineSummary summary={summary} srcIp={srcIp} hours={hours} />
          {boostActive ? (
            <LiveEventsLog<{
              event_time: string;
              src_ip: string;
              method: string;
              response: string;
            }>
              metric="sip-events-recent"
              title="Live SIP events"
              caption={`Fast refresh during demo (${boostRemainingSec}s remaining)`}
              hours={hours}
              refreshMs={refreshMs}
              limit={12}
              columns={[
                { key: "event_time", label: "Time" },
                { key: "src_ip", label: "Source" },
                { key: "method", label: "Method" },
                { key: "response", label: "Response" },
              ]}
            />
          ) : null}
        </div>
        <DemoRunCard
          onRunDemo={handleRunDemo}
          running={running}
          runResult={runResult}
          runError={runError}
          boostActive={boostActive}
          boostRemainingSec={boostRemainingSec}
        />
      </div>

      <SectionNote
        shows="Single-source correlated timeline across SIP, Suricata, Wazuh, ML, LLM, and autoban stages with live auto-refresh."
        implements="Server-side /api/metrics?metric=demo-timeline picks the best recent attacker (most pipeline stage hits, 7-day correlation window) and unions stage events from ClickHouse. Run live demo POSTs to /api/demo/run, which forwards to demo-runner."
      />
    </div>
  );
}
