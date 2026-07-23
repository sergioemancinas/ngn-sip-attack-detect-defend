export function EmptyState({ message }: { message?: string }) {
  return (
    <div className="flex h-full min-h-[140px] flex-col items-center justify-center rounded-xl border border-dashed border-surface-border/80 bg-surface/30 px-6 py-8 text-center">
      <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-surface-overlay text-text-muted">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M4 7h16M4 12h10M4 17h14" strokeLinecap="round" />
        </svg>
      </div>
      <p className="text-sm font-medium text-text-secondary">
        {message ?? "No data in window"}
      </p>
      <p className="mt-1 text-xs text-text-muted">Try widening the time range or check ingest health</p>
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex h-full min-h-[120px] flex-col items-center justify-center rounded-xl border border-accent-red/30 bg-accent-red/5 px-4 py-6 text-center">
      <div className="mb-2 flex h-8 w-8 items-center justify-center rounded-full bg-accent-red/15 text-accent-red">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <path d="M12 8v5M12 16h.01" strokeLinecap="round" />
        </svg>
      </div>
      <p className="text-sm font-medium text-accent-red">Unable to load panel data</p>
      <p className="mt-1 max-w-sm text-xs text-text-muted">{message}</p>
    </div>
  );
}

export function LoadingSpinner() {
  return (
    <div className="flex h-full min-h-[140px] flex-col gap-3 p-2" aria-busy="true" aria-label="Loading">
      <div className="shimmer h-3.5 w-2/5 rounded-md" />
      <div className="shimmer h-28 w-full rounded-lg" />
      <div className="grid grid-cols-3 gap-2">
        <div className="shimmer h-12 rounded-md" />
        <div className="shimmer h-12 rounded-md" />
        <div className="shimmer h-12 rounded-md" />
      </div>
      <div className="mt-1 space-y-2">
        <div className="shimmer h-8 w-full rounded-md" />
        <div className="shimmer h-8 w-11/12 rounded-md" />
        <div className="shimmer h-8 w-4/5 rounded-md" />
      </div>
    </div>
  );
}

export function PanelSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-2" aria-busy="true" aria-label="Loading panel">
      {Array.from({ length: rows }).map((_, index) => (
        <div
          key={index}
          className="shimmer h-10 rounded-lg"
          style={{ animationDelay: `${index * 80}ms` }}
        />
      ))}
    </div>
  );
}

export function KpiSkeleton() {
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
      {Array.from({ length: 5 }).map((_, index) => (
        <div
          key={index}
          className="stat-card shimmer h-[92px]"
          style={{ animationDelay: `${index * 60}ms` }}
        />
      ))}
    </div>
  );
}
