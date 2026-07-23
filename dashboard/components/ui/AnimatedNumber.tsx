"use client";

import { useCountUp } from "@/components/hooks/useMotion";
import { coerceCount, formatInteger } from "@/lib/chart-utils";
import { cn } from "@/lib/utils";

/**
 * Renders an integer that animates toward its target value with tabular figures
 * so the digits do not jitter horizontally during the transition.
 */
export function AnimatedNumber({
  value,
  durationMs,
  className,
}: {
  value: unknown;
  durationMs?: number;
  className?: string;
}) {
  const target = coerceCount(value);
  const animated = useCountUp(target, durationMs);
  return <span className={cn("tabular-nums", className)}>{formatInteger(animated)}</span>;
}
