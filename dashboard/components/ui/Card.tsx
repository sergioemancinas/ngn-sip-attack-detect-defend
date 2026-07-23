import { cn } from "@/lib/utils";

export function Card({
  className,
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "flex h-full flex-col overflow-hidden rounded-xl border border-surface-border/90 bg-surface-raised/85 shadow-card backdrop-blur transition-all duration-300 hover:border-surface-border hover:shadow-card-hover",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex shrink-0 items-start gap-3 border-b border-surface-border/80 px-4 py-3">
      <div className="min-w-0 flex-1 select-text">
        <h3 className="truncate text-sm font-semibold text-text-primary">{title}</h3>
        {subtitle ? (
          <p className="mt-0.5 line-clamp-1 text-xs text-text-muted">{subtitle}</p>
        ) : null}
      </div>
      {action}
    </div>
  );
}

export function CardBody({
  className,
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={cn("min-h-0 flex-1 overflow-auto p-4", className)}>
      {children}
    </div>
  );
}
