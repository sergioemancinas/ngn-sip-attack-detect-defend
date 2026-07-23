"use client";

import { PanelWrapper } from "@/components/PanelWrapper";
import { FULL_WIDTH_PANELS } from "@/lib/sections";
import { cn } from "@/lib/utils";
import type { PanelId } from "@/types/layout";

export function SectionPanelGrid({
  panelIds,
  hours,
  refreshMs,
}: {
  panelIds: PanelId[];
  hours: number;
  refreshMs: number;
}) {
  if (panelIds.length === 0) return null;

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {panelIds.map((panelId, index) => (
        <div
          key={panelId}
          className={cn(
            "card-mount min-h-[280px]",
            FULL_WIDTH_PANELS.has(panelId) && "md:col-span-2",
          )}
          style={{ "--mount-index": index } as React.CSSProperties}
        >
          <PanelWrapper panelId={panelId} hours={hours} refreshMs={refreshMs} />
        </div>
      ))}
    </div>
  );
}
