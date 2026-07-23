import { cn } from "@/lib/utils";

const variants = {
  default: "bg-surface-overlay text-text-secondary",
  healthy: "bg-accent-green/15 text-accent-green ring-1 ring-accent-green/20",
  stale: "bg-accent-amber/15 text-accent-amber ring-1 ring-accent-amber/20",
  not_deployed: "bg-surface-overlay text-text-muted ring-1 ring-surface-border",
  attack: "bg-accent-red/15 text-accent-red ring-1 ring-accent-red/20",
  malicious: "bg-accent-red/15 text-accent-red ring-1 ring-accent-red/20",
  suspicious: "bg-accent-amber/15 text-accent-amber ring-1 ring-accent-amber/20",
  benign: "bg-accent-green/15 text-accent-green ring-1 ring-accent-green/20",
  ban: "bg-accent-purple/15 text-accent-purple ring-1 ring-accent-purple/20",
  info: "bg-accent/15 text-accent ring-1 ring-accent/20",
  critical: "bg-accent-red/20 text-accent-red ring-1 ring-accent-red/30",
  high: "bg-accent-amber/15 text-accent-amber ring-1 ring-accent-amber/20",
  medium: "bg-accent/15 text-accent ring-1 ring-accent/20",
  low: "bg-surface-overlay text-text-muted ring-1 ring-surface-border",
};

export function Badge({
  children,
  variant = "default",
  className,
}: {
  children: React.ReactNode;
  variant?: keyof typeof variants;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
        variants[variant],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function severityVariant(level: string | number): keyof typeof variants {
  const numeric = typeof level === "number" ? level : Number.parseInt(String(level), 10);
  if (!Number.isNaN(numeric)) {
    if (numeric >= 12) return "critical";
    if (numeric >= 8) return "high";
    if (numeric >= 5) return "medium";
    return "low";
  }
  const normalized = String(level).toLowerCase();
  if (normalized.includes("critical") || normalized.includes("attack")) return "critical";
  if (normalized.includes("high") || normalized.includes("malicious")) return "high";
  if (normalized.includes("suspicious") || normalized.includes("medium")) return "suspicious";
  if (normalized.includes("needs_review")) return "info";
  return "default";
}
