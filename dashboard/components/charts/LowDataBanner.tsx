import { formatInteger } from "@/lib/chart-utils";

export function LowDataBanner({
  count,
  unit,
  detail,
}: {
  count: unknown;
  unit: string;
  detail?: string;
}) {
  return (
    <div className="mb-3 rounded-lg border border-accent-amber/30 bg-accent-amber/5 px-3 py-2 text-xs text-accent-amber">
      <span className="font-medium">Limited data in window:</span>{" "}
      {formatInteger(count)} {unit}
      {detail ? <span className="text-accent-amber/80"> · {detail}</span> : null}
    </div>
  );
}
