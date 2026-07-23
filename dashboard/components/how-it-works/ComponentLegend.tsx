import { COMPONENT_LEGEND } from "@/lib/nav";

export function ComponentLegend() {
  return (
    <div className="rounded-xl border border-surface-border bg-surface-raised/60 shadow-card">
      <div className="border-b border-surface-border/80 px-5 py-4">
        <h3 className="text-base font-semibold text-text-primary">Component legend</h3>
        <p className="mt-1 text-xs text-text-muted">
          Map each pipeline box to its ClickHouse table and Docker container
        </p>
      </div>
      <div className="grid gap-4 p-5 md:grid-cols-2">
        {COMPONENT_LEGEND.map((group) => (
          <div key={group.group}>
            <p className="text-[10px] font-semibold uppercase tracking-widest text-accent">
              {group.group}
            </p>
            <table className="data-table mt-2">
              <thead>
                <tr>
                  <th>Component</th>
                  <th>ClickHouse</th>
                  <th>Container</th>
                </tr>
              </thead>
              <tbody>
                {group.items.map((item) => (
                  <tr key={item.name}>
                    <td className="font-medium text-text-primary">{item.name}</td>
                    <td className="mono">{item.table ?? "n/a"}</td>
                    <td className="text-text-muted">{item.container}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </div>
    </div>
  );
}
