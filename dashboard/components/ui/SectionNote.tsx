export function SectionNote({
  title = "What this shows",
  shows,
  implements: implementation,
}: {
  title?: string;
  shows: string;
  implements: string;
}) {
  return (
    <div className="rounded-xl border border-surface-border/80 bg-surface/30 px-4 py-3 text-xs leading-relaxed">
      <p className="font-semibold text-text-secondary">{title}</p>
      <p className="mt-1 text-text-muted">{shows}</p>
      <p className="mt-2">
        <span className="font-medium text-text-secondary">Implementation: </span>
        <span className="text-text-muted">{implementation}</span>
      </p>
    </div>
  );
}

export function PanelNote({ shows, implements: implementation }: { shows: string; implements: string }) {
  return (
    <div className="mt-3 border-t border-surface-border/60 pt-3 text-[11px] leading-relaxed text-text-muted">
      <p>
        <span className="font-medium text-text-secondary">Shows: </span>
        {shows}
      </p>
      <p className="mt-1">
        <span className="font-medium text-text-secondary">Source: </span>
        {implementation}
      </p>
    </div>
  );
}
