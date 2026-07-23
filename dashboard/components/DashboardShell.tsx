"use client";

import { useCallback, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { AppShell } from "@/components/AppShell";
import { SectionView } from "@/components/SectionView";
import { useMetric } from "@/components/hooks/useMetric";
import { DEMO_REFRESH_MS } from "@/components/demo/DemoTimeline";
import { SECTION_MAP, resolveSectionId } from "@/lib/sections";
import { parseHours } from "@/lib/hours";
import type { AuthMode } from "@/lib/auth";
import type { DemoTimelineEvent } from "@/types/layout";
import type { StackHealthRow } from "@/types/layout";

const DEFAULT_REFRESH_MS = Number(process.env.NEXT_PUBLIC_DASHBOARD_REFRESH_MS ?? 15000);

function parseHideChrome(value: string | null): boolean {
  return value === "1" || value === "true";
}

function useDashboardLastUpdated(
  hours: number,
  refreshMs: number,
  sectionId: ReturnType<typeof resolveSectionId>,
): Date | null {
  const stack = useMetric<StackHealthRow>("stack-health", hours, refreshMs);
  const demo = useMetric<DemoTimelineEvent>("demo-timeline", hours, DEMO_REFRESH_MS, { limit: "80" });

  if (sectionId === "demo") {
    return demo.lastUpdated ?? stack.lastUpdated ?? null;
  }
  return stack.lastUpdated ?? null;
}

export function DashboardShell({
  authEnabled,
  authMode,
}: {
  authEnabled: boolean;
  authMode: AuthMode;
}) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const sectionParam = searchParams.get("section");
  const hideChrome = parseHideChrome(searchParams.get("hide-chrome"));

  const sectionId = resolveSectionId(sectionParam);
  const section = SECTION_MAP[sectionId];
  const [hours, setHours] = useState(() => parseHours(searchParams.get("hours")));
  const lastUpdated = useDashboardLastUpdated(hours, DEFAULT_REFRESH_MS, sectionId);

  const pageTitle = useMemo(() => section.title, [section.title]);
  const pageSubtitle = useMemo(() => section.subtitle, [section.subtitle]);

  const handleHoursChange = useCallback(
    (nextHours: number) => {
      setHours(nextHours);
      const params = new URLSearchParams(searchParams.toString());
      params.set("hours", String(nextHours));
      if (!params.get("section")) {
        params.set("section", sectionId);
      }
      router.replace(`/?${params.toString()}`);
    },
    [router, searchParams, sectionId],
  );

  return (
    <AppShell
      title={pageTitle}
      subtitle={pageSubtitle}
      hours={hours}
      onHoursChange={handleHoursChange}
      hideChrome={hideChrome}
      authEnabled={authEnabled}
      authMode={authMode}
      refreshMs={sectionId === "demo" ? DEMO_REFRESH_MS : DEFAULT_REFRESH_MS}
      lastUpdated={lastUpdated}
      activeSection={sectionId}
    >
      <SectionView section={section} hours={hours} refreshMs={DEFAULT_REFRESH_MS} />
    </AppShell>
  );
}
