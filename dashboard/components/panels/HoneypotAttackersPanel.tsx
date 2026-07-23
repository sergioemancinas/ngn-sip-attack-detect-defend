"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useMetric } from "@/components/hooks/useMetric";
import { Badge } from "@/components/ui/Badge";
import { EmptyState, ErrorState, LoadingSpinner } from "@/components/ui/States";
import { classifyUserAgent, isLikelyAutomated, type IpEnrichment } from "@/lib/enrich";

interface AttackerRow {
  ip: string;
  events: number;
  methods: string;
  user_agents: string;
  first_seen: string;
  last_seen: string;
  banned: number;
}

function flagEmoji(cc: string): string {
  if (!cc || cc.length !== 2) return "";
  const up = cc.toUpperCase();
  if (!/^[A-Z]{2}$/.test(up)) return "";
  return String.fromCodePoint(0x1f1e6 + (up.charCodeAt(0) - 65), 0x1f1e6 + (up.charCodeAt(1) - 65));
}

function classifyMethods(methods: string): string[] {
  const m = (methods || "").toUpperCase();
  const out: string[] = [];
  if (m.includes("OPTIONS")) out.push("OPTIONS: reconnaissance / SIP scanning");
  if (m.includes("REGISTER")) out.push("REGISTER: account enumeration or brute-force");
  if (m.includes("INVITE")) out.push("INVITE: call setup or toll-fraud probing");
  if (m.includes("SUBSCRIBE")) out.push("SUBSCRIBE: presence probing");
  return out;
}

function uaList(user_agents: string): string[] {
  return (user_agents || "").split(" | ").map((s) => s.trim()).filter(Boolean);
}

function scannerTools(user_agents: string): string[] {
  const tools = new Set<string>();
  for (const ua of uaList(user_agents)) {
    const c = classifyUserAgent(ua);
    if (c.isScanner) tools.add(c.tool);
  }
  return [...tools];
}

function fmt(t: string): string {
  const d = new Date(t);
  if (Number.isNaN(d.getTime())) return t;
  return d.toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function topN(counts: Record<string, number>, n: number): [string, number][] {
  return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, n);
}

interface Insights {
  total: number;
  enriched: number;
  hosting: number;
  proxy: number;
  withShodan: number;
  ports: Record<string, number>;
  cves: Record<string, number>;
  tools: Record<string, number>;
  countries: Record<string, number>;
  asns: Record<string, number>;
}

function computeInsights(rows: AttackerRow[], enriched: Record<string, IpEnrichment | null>): Insights {
  const ins: Insights = {
    total: rows.length, enriched: 0, hosting: 0, proxy: 0, withShodan: 0,
    ports: {}, cves: {}, tools: {}, countries: {}, asns: {},
  };
  const bump = (o: Record<string, number>, k: string) => { if (k) o[k] = (o[k] ?? 0) + 1; };
  for (const row of rows) {
    for (const t of scannerTools(row.user_agents)) bump(ins.tools, t);
    const e = enriched[row.ip];
    if (!e) continue;
    ins.enriched++;
    if (e.hosting) ins.hosting++;
    if (e.proxy) ins.proxy++;
    bump(ins.countries, e.country || "Unknown");
    bump(ins.asns, e.asname || e.as || "Unknown");
    if (e.shodan) {
      ins.withShodan++;
      for (const p of e.shodan.ports) bump(ins.ports, String(p));
      for (const v of e.shodan.vulns) bump(ins.cves, v);
    }
  }
  return ins;
}

const PORT_LABELS: Record<string, string> = {
  "22": "SSH", "80": "HTTP", "443": "HTTPS", "5060": "SIP", "21": "FTP",
  "23": "Telnet", "3389": "RDP", "8080": "HTTP-alt", "25": "SMTP", "53": "DNS",
};

function SecurityInsights({ insights }: { insights: Insights }) {
  const ports = topN(insights.ports, 6);
  const cves = topN(insights.cves, 6);
  const tools = topN(insights.tools, 6);
  const countries = topN(insights.countries, 5);
  const asns = topN(insights.asns, 4);
  const dcPct = insights.enriched > 0 ? Math.round((insights.hosting / insights.enriched) * 100) : 0;

  return (
    <div className="panel-card panel-card-accent p-5">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-widest text-accent">
            Security insights
          </p>
          <h3 className="mt-1 text-sm font-semibold text-text-primary">
            Who is attacking, and what we know about them
          </h3>
          <p className="mt-0.5 text-xs leading-relaxed text-text-muted">
            Open-source intelligence on every source hitting the honeypot. We fingerprint the SIP tool
            from its user-agent (legitimate phones never run scanners) and look up each attacker&apos;s own
            internet-facing host with Shodan to see what it exposes and how exposed it is.
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <Badge variant="attack">{insights.total} sources</Badge>
          {insights.enriched > 0 ? <Badge variant="suspicious">{dcPct}% datacenter</Badge> : null}
        </div>
      </div>

      <div className="mt-4 grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-surface-border/80 bg-surface/40 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-text-muted">Scanner tools fingerprinted</p>
          {tools.length === 0 ? (
            <p className="mt-1 text-[11px] text-text-muted">None identified yet (UAs not matched to known tools).</p>
          ) : (
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {tools.map(([t, c]) => (
                <span key={t} className="rounded-md border border-accent-red/25 bg-accent-red/[0.07] px-2 py-0.5 text-[11px] text-text-secondary">
                  {t} <span className="text-text-muted">×{c}</span>
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="rounded-lg border border-surface-border/80 bg-surface/40 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-text-muted">Exposed services on attacker infra (Shodan)</p>
          {ports.length === 0 ? (
            <p className="mt-1 text-[11px] text-text-muted">No Shodan data for these sources yet.</p>
          ) : (
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {ports.map(([p, c]) => (
                <span key={p} className="rounded-md border border-surface-border bg-surface px-2 py-0.5 font-mono text-[11px] text-text-secondary">
                  {p}{PORT_LABELS[p] ? `/${PORT_LABELS[p]}` : ""} <span className="text-text-muted">×{c}</span>
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="rounded-lg border border-surface-border/80 bg-surface/40 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-text-muted">Vulnerabilities on the attacker&apos;s own host</p>
          <p className="mt-0.5 text-[10px] leading-relaxed text-text-muted">CVEs on the attacking IP&apos;s exposed services (e.g. its SSH). A vulnerable, internet-exposed attacker is usually a compromised box in a botnet, not a targeted operator.</p>
          {cves.length === 0 ? (
            <p className="mt-1 text-[11px] text-text-muted">No CVE data yet.</p>
          ) : (
            <div className="mt-1.5 flex flex-wrap gap-1.5">
              {cves.map(([v, c]) => (
                <a key={v} href={`https://nvd.nist.gov/vuln/detail/${v}`} target="_blank" rel="noopener noreferrer"
                   className="rounded-md border border-accent-amber/25 bg-accent-amber/[0.07] px-2 py-0.5 font-mono text-[10px] text-text-secondary hover:text-accent">
                  {v} <span className="text-text-muted">×{c}</span>
                </a>
              ))}
            </div>
          )}
        </div>

        <div className="rounded-lg border border-surface-border/80 bg-surface/40 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-text-muted">Origin networks</p>
          <div className="mt-1.5 space-y-1 text-[11px] text-text-secondary">
            {countries.length > 0 ? (
              <p><span className="text-text-muted">Countries </span>{countries.map(([c, n]) => `${c} (${n})`).join(", ")}</p>
            ) : <p className="text-text-muted">Resolving...</p>}
            {asns.length > 0 ? (
              <p><span className="text-text-muted">Networks </span>{asns.map(([a, n]) => `${a} (${n})`).join(", ")}</p>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}

function AttackerCard({ row, enrichment }: { row: AttackerRow; enrichment: IpEnrichment | null | undefined }) {
  const e = enrichment ?? null;
  const automated = e ? isLikelyAutomated(e) : false;
  const classes = classifyMethods(row.methods);
  const tools = scannerTools(row.user_agents);
  const sh = e?.shodan ?? null;

  return (
    <div className="rounded-lg border border-surface-border/80 bg-surface/40 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm text-text-primary">{row.ip}</span>
            {e?.countryCode ? <span className="text-base" aria-hidden>{flagEmoji(e.countryCode)}</span> : null}
          </div>
          <p className="mt-0.5 text-xs text-text-muted">
            {e ? [e.city, e.regionName, e.country].filter(Boolean).join(", ") || "Location unknown"
              : enrichment === undefined ? "Resolving..." : "Location unavailable"}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {tools.length > 0 ? <Badge variant="attack">{tools[0]}</Badge> : null}
          {e?.hosting ? <Badge variant="attack">datacenter</Badge> : null}
          {e?.proxy ? <Badge variant="suspicious">proxy</Badge> : null}
          {row.banned ? <Badge variant="attack">banned</Badge> : <Badge variant="suspicious">observed</Badge>}
        </div>
      </div>

      {e && (e.as || e.isp) ? (
        <p className="mt-2 text-[11px] leading-relaxed text-text-secondary">
          <span className="text-text-muted">Network </span>{[e.as || e.asname, e.isp, e.org].filter(Boolean).join(" · ")}
        </p>
      ) : null}
      {e?.reverse ? <p className="mt-0.5 font-mono text-[10px] text-text-muted">{e.reverse}</p> : null}

      {sh && (sh.ports.length > 0 || sh.vulns.length > 0) ? (
        <div className="mt-2 rounded-md border border-surface-border/60 bg-surface/30 px-2.5 py-1.5">
          <p className="text-[10px] font-semibold uppercase tracking-wide text-text-muted">Shodan: attacker infrastructure</p>
          <p className="mt-0.5 text-[11px] text-text-secondary">
            {sh.ports.length > 0 ? <>Open ports: <span className="font-mono">{sh.ports.join(", ")}</span>. </> : null}
            {sh.vulns.length > 0 ? <span className="text-accent-amber">{sh.vulns.length} known CVE{sh.vulns.length === 1 ? "" : "s"} ({sh.vulns.slice(0, 2).join(", ")}{sh.vulns.length > 2 ? "…" : ""})</span> : null}
          </p>
        </div>
      ) : null}

      <div className="mt-2.5">
        <p className="text-[10px] font-semibold uppercase tracking-wide text-text-muted">Activity</p>
        <p className="mt-0.5 text-[11px] text-text-secondary">
          {row.events} event{row.events === 1 ? "" : "s"} · {row.methods || "n/a"} · {fmt(row.first_seen)} to {fmt(row.last_seen)}
        </p>
        {classes.map((c) => <p key={c} className="text-[10px] text-text-muted">{c}</p>)}
      </div>

      <div className={`mt-2.5 rounded-md border px-2.5 py-1.5 text-[11px] leading-relaxed ${automated || tools.length > 0 ? "border-accent-red/25 bg-accent-red/[0.06] text-text-secondary" : "border-surface-border/80 bg-surface/40 text-text-muted"}`}>
        <span className="font-semibold text-text-primary">Assessment </span>
        {tools.length > 0
          ? `User-agent matches a known SIP attack tool (${tools[0]}) from a ${e?.hosting ? "datacenter" : "remote"} source. Treat as hostile scanner traffic.`
          : e
            ? automated
              ? "Datacenter or proxy source sending unsolicited SIP probes. Automated scanner, not a legitimate endpoint."
              : "Residential or mobile source. Review the activity before acting."
            : "Enrichment pending; classify from the activity above."}
      </div>
    </div>
  );
}

export function HoneypotAttackersPanel({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { data, loading, error } = useMetric<AttackerRow>("external-attackers", hours, refreshMs, { limit: "12" });
  const rows = data ?? [];
  const [enriched, setEnriched] = useState<Record<string, IpEnrichment | null>>({});
  const fetchedRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    let cancelled = false;
    const toFetch = rows.map((r) => r.ip).filter((ip) => ip && !fetchedRef.current.has(ip));
    if (toFetch.length === 0) return;
    (async () => {
      for (const ip of toFetch) {
        fetchedRef.current.add(ip);
        try {
          const res = await fetch(`/api/enrich?ip=${encodeURIComponent(ip)}`, { cache: "no-store" });
          const j = res.ok ? ((await res.json()) as IpEnrichment) : null;
          if (!cancelled) setEnriched((prev) => ({ ...prev, [ip]: j }));
        } catch {
          if (!cancelled) setEnriched((prev) => ({ ...prev, [ip]: null }));
        }
      }
    })();
    return () => { cancelled = true; };
  }, [rows]);

  const insights = useMemo(() => computeInsights(rows, enriched), [rows, enriched]);

  const showLoading = loading && rows.length === 0;
  const showError = Boolean(error) && rows.length === 0;

  return (
    <div className="space-y-4">
      {rows.length > 0 ? <SecurityInsights insights={insights} /> : null}

      <div className="panel-card p-5">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-widest text-accent-red">Live honeypot</p>
            <h3 className="mt-1 text-sm font-semibold text-text-primary">Real external sources on the public SIP edge</h3>
            <p className="mt-0.5 text-xs text-text-muted">
              Captured from the internet-exposed edge, enriched with geolocation, network attribution, and Shodan.
            </p>
          </div>
          <span className="inline-flex items-center gap-1.5 font-mono text-[10px] text-text-muted">
            <span className="h-1.5 w-1.5 rounded-full bg-accent-red" aria-hidden />sip_events
          </span>
        </div>

        <div className="mt-4">
          {showLoading ? <LoadingSpinner />
            : showError ? <ErrorState message={error ?? "Request failed"} />
            : rows.length === 0 ? <EmptyState message="No external sources in the selected window yet. The public edge captures real internet scanners over time." />
            : (
              <div className="grid gap-3 lg:grid-cols-2">
                {rows.map((row) => <AttackerCard key={row.ip} row={row} enrichment={enriched[row.ip]} />)}
              </div>
            )}
        </div>
      </div>
    </div>
  );
}
