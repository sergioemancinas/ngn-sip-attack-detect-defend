import type { ReactElement } from "react";
import { ResponsiveContainer } from "recharts";

export function ChartContainer({
  height = 220,
  children,
}: {
  height?: number;
  children: ReactElement;
}) {
  return (
    <div className="w-full" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        {children}
      </ResponsiveContainer>
    </div>
  );
}
