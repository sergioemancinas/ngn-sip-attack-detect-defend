"use client";

import { Card, CardBody, CardHeader } from "@/components/ui/Card";
import { PanelNote } from "@/components/ui/SectionNote";
import { PANEL_MAP } from "@/lib/panels";
import { PANEL_NOTES } from "@/lib/panel-notes";
import { PanelRenderer } from "@/components/PanelRenderer";
import type { PanelId } from "@/types/layout";

export function PanelWrapper({
  panelId,
  hours,
  refreshMs,
}: {
  panelId: PanelId;
  hours: number;
  refreshMs: number;
}) {
  const def = PANEL_MAP[panelId];
  const note = PANEL_NOTES[panelId];

  return (
    <Card>
      <CardHeader title={def.title} subtitle={def.description} />
      <CardBody>
        <PanelRenderer panelId={panelId} hours={hours} refreshMs={refreshMs} />
        {note ? <PanelNote shows={note.shows} implements={note.implements} /> : null}
      </CardBody>
    </Card>
  );
}
