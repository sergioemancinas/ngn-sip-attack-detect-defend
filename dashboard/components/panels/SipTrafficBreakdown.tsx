"use client";

import { MetricFrame, useMetric } from "@/components/hooks/useMetric";
import { formatInteger, coerceCount } from "@/lib/chart-utils";
import { cn } from "@/lib/utils";

interface MixRow {
  label: string;
  count: number;
  pct: number;
}

interface ResponseCodeRow {
  code: number;
  phrase: string;
  count: number;
}

const METHOD_LABEL: Record<string, string> = {
  OTHER: "Responses (no method)",
};

const RESPONSE_CLASS_LABEL: Record<string, string> = {
  requests: "Requests (have a method)",
};

// Short human meaning per SIP status code. Falls back to a per-class summary.
const RESPONSE_CODE_MEANING: Record<number, string> = {
  100: "Trying",
  180: "Ringing",
  183: "Session progress",
  200: "OK (success)",
  202: "Accepted",
  401: "Auth challenge (registrar)",
  403: "Forbidden",
  404: "Not found (user / URI)",
  407: "Proxy auth challenge",
  408: "Request timeout",
  480: "Temporarily unavailable",
  481: "Call/transaction unknown",
  486: "Busy here",
  487: "Request cancelled",
  488: "Not acceptable here",
  500: "Server internal error",
  503: "Service unavailable",
};

function responseCodeMeaning(code: number): string {
  if (RESPONSE_CODE_MEANING[code]) return RESPONSE_CODE_MEANING[code];
  if (code === 401 || code === 407) return "Auth challenge";
  if (code >= 100 && code < 200) return "Provisional";
  if (code >= 200 && code < 300) return "Success";
  if (code >= 300 && code < 400) return "Redirection";
  if (code >= 400 && code < 500) return "Client error";
  if (code >= 500 && code < 600) return "Server error";
  if (code >= 600) return "Global failure";
  return "Response";
}

const CODE_CLASS_LEGEND: { label: string; meaning: string; tone: string }[] = [
  { label: "2xx", meaning: "Success (OK / Accepted)", tone: "text-accent-green" },
  { label: "401 / 407", meaning: "Auth challenge (expected on REGISTER)", tone: "text-accent-amber" },
  { label: "403", meaning: "Forbidden (rejected)", tone: "text-accent-amber" },
  { label: "404", meaning: "Not found (unknown user)", tone: "text-accent-amber" },
  { label: "486", meaning: "Busy here", tone: "text-accent-amber" },
  { label: "487", meaning: "Request cancelled", tone: "text-text-secondary" },
  { label: "5xx", meaning: "Server error", tone: "text-accent-red" },
];

function formatMethodLabel(raw: string): string {
  return METHOD_LABEL[raw] ?? raw;
}

function formatClassLabel(raw: string): string {
  return RESPONSE_CLASS_LABEL[raw] ?? raw;
}

function parseMixRows(
  rows: Array<{ method?: string; response_class?: string; cnt?: number }> | undefined,
  labelKey: "method" | "response_class",
): MixRow[] {
  const parsed = (rows ?? [])
    .map((row) => {
      const raw = String(row[labelKey] ?? "unknown");
      const label = labelKey === "method" ? formatMethodLabel(raw) : formatClassLabel(raw);
      return {
        label,
        count: coerceCount(row.cnt),
      };
    })
    .filter((row) => row.count > 0);
  const total = parsed.reduce((sum, row) => sum + row.count, 0);
  return parsed.map((row) => ({
    ...row,
    pct: total > 0 ? Math.round((row.count / total) * 100) : 0,
  }));
}

function parseResponseCodeRows(
  rows: Array<{ response_code?: number; response_phrase?: string; cnt?: number }> | undefined,
): ResponseCodeRow[] {
  return (rows ?? [])
    .map((row) => ({
      code: coerceCount(row.response_code),
      phrase: String(row.response_phrase ?? "").trim() || "response",
      count: coerceCount(row.cnt),
    }))
    .filter((row) => row.code > 0 && row.count > 0)
    .sort((a, b) => b.count - a.count);
}

function MixTable({
  title,
  hint,
  rows,
  barTone,
}: {
  title: string;
  hint?: string;
  rows: MixRow[];
  barTone: string;
}) {
  const total = rows.reduce((sum, row) => sum + row.count, 0);
  return (
    <div className="rounded-lg border border-surface-border bg-surface/50 p-4">
      <p className="text-xs font-semibold text-text-primary">{title}</p>
      {hint ? <p className="mt-1 text-[10px] leading-relaxed text-text-muted">{hint}</p> : null}
      {rows.length === 0 ? (
        <p className="mt-3 font-mono text-xs text-text-muted">No rows in window.</p>
      ) : (
        <div className="mt-3 space-y-2">
          {rows.map((row) => (
            <div key={row.label}>
              <div className="flex items-center justify-between gap-2 text-xs">
                <span className="font-mono text-text-primary">{row.label}</span>
                <span className="tabular-nums text-text-muted">
                  {formatInteger(row.count)} ({row.pct}%)
                </span>
              </div>
              <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-overlay">
                <div
                  className={cn("h-full rounded-full transition-all", barTone)}
                  style={{ width: `${Math.max(row.pct, 2)}%` }}
                />
              </div>
            </div>
          ))}
          <p className="pt-1 text-[10px] text-text-muted">{formatInteger(total)} total events</p>
        </div>
      )}
    </div>
  );
}

function ResponseCodesBlock({ rows }: { rows: ResponseCodeRow[] }) {
  const total = rows.reduce((sum, row) => sum + row.count, 0);
  const maxCount = rows.reduce((max, row) => Math.max(max, row.count), 0);

  return (
    <div className="rounded-lg border border-accent-amber/30 bg-accent-amber/5 p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className="text-xs font-semibold text-text-primary">SIP response status codes</p>
        {rows.length > 0 ? (
          <p className="text-[10px] tabular-nums text-text-muted">
            {formatInteger(total)} responses in window
          </p>
        ) : null}
      </div>
      <p className="mt-1 text-[10px] leading-relaxed text-text-muted">
        Server replies grouped by numeric status code. These flow in live via HEP capture (for
        example, 401 auth challenges on REGISTER).
      </p>

      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 rounded-md border border-surface-border/60 bg-surface/40 px-3 py-2 text-[10px]">
        {CODE_CLASS_LEGEND.map((item) => (
          <span key={item.label} className="flex items-center gap-1.5">
            <span className={cn("font-mono font-semibold", item.tone)}>{item.label}</span>
            <span className="text-text-muted">{item.meaning}</span>
          </span>
        ))}
      </div>

      {rows.length === 0 ? (
        <p className="mt-3 text-[11px] leading-relaxed text-text-muted">
          No SIP response status codes in this window yet. Once the registrar replies (or scanners
          probe), 401 / 403 / 404 codes will appear here from the HEP-captured response stream.
        </p>
      ) : (
        <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {rows.map((row) => {
            const pct = maxCount > 0 ? Math.round((row.count / maxCount) * 100) : 0;
            return (
              <div
                key={`${row.code}-${row.phrase}`}
                className="rounded-lg border border-surface-border/80 bg-surface/60 px-3 py-2.5"
              >
                <div className="flex items-baseline justify-between gap-2">
                  <p className="font-mono text-sm font-semibold text-text-primary">{row.code}</p>
                  <p className="shrink-0 text-sm font-semibold tabular-nums text-accent-amber">
                    {formatInteger(row.count)}
                  </p>
                </div>
                <p className="mt-0.5 truncate text-[10px] text-text-secondary">
                  {responseCodeMeaning(row.code)}
                </p>
                <div className="mt-2 h-1 overflow-hidden rounded-full bg-surface-overlay">
                  <div
                    className="h-full rounded-full bg-accent-amber/80"
                    style={{ width: `${Math.max(pct, 4)}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function SipTrafficBreakdown({ hours, refreshMs }: { hours: number; refreshMs: number }) {
  const { loading, error, empty, meta } = useMetric<never>("sip-breakdown", hours, refreshMs);

  const {
    data: responseCodes,
    loading: codesLoading,
    error: codesError,
  } = useMetric<{ response_code: number; response_phrase: string; cnt: number }>(
    "sip-response-codes",
    hours,
    refreshMs,
  );

  const methodRows = parseMixRows(
    meta?.method_mix as Array<{ method?: string; cnt?: number }> | undefined,
    "method",
  );
  const classRows = parseMixRows(
    meta?.response_classes as Array<{ response_class?: string; cnt?: number }> | undefined,
    "response_class",
  );
  const codeRows = parseResponseCodeRows(responseCodes ?? undefined);
  const hasData = methodRows.length > 0 || classRows.length > 0 || codeRows.length > 0;
  const combinedError = error || codesError;
  const combinedLoading = loading || codesLoading;

  return (
    <div className="rounded-xl border border-surface-border bg-surface-raised/60 p-5 shadow-card">
      <h3 className="text-sm font-semibold text-text-primary">SIP traffic profile</h3>
      <p className="mt-1 text-xs text-text-muted">
        How requests and responses are counted across ngn_sip.sip_events
      </p>

      <div className="mt-3 rounded-lg border border-accent/20 bg-accent/5 px-4 py-3 text-[11px] leading-relaxed text-text-secondary">
        SIP has two message kinds. <span className="font-semibold text-text-primary">Requests</span>{" "}
        carry a method (REGISTER, INVITE, OPTIONS, ...), so the{" "}
        <span className="font-semibold text-text-primary">method mix</span> below counts requests by
        method. <span className="font-semibold text-text-primary">Responses</span> carry a numeric
        status code instead of a method, so they are summarised separately by status code.
      </div>

      <MetricFrame loading={combinedLoading} error={combinedError} empty={empty && !hasData}>
        <div className="mt-4 grid gap-4 lg:grid-cols-2">
          <MixTable
            title="Request method mix"
            hint='SIP requests grouped by method. "Responses (no method)" are status-code messages, broken out by code below.'
            rows={methodRows}
            barTone="bg-accent"
          />
          <MixTable
            title="Message classes"
            hint="All sip_events split into requests vs response classes (2xx success, 4xx client, 5xx server)."
            rows={classRows}
            barTone="bg-accent-amber"
          />
        </div>

        <div className="mt-4">
          <ResponseCodesBlock rows={codeRows} />
        </div>

        <div className="mt-4 grid gap-3 text-xs leading-relaxed md:grid-cols-2">
          <div className="rounded-lg border border-accent-green/25 bg-accent-green/5 p-3">
            <p className="font-semibold text-accent-green">What healthy looks like</p>
            <p className="mt-1 text-text-muted">
              Balanced REGISTER and INVITE requests, mostly 2xx responses, a normal level of 401
              auth challenges from known endpoints, stable User-Agents, and moderate request rates
              per source.
            </p>
          </div>
          <div className="rounded-lg border border-accent-red/25 bg-accent-red/5 p-3">
            <p className="font-semibold text-accent-red">What attack-shaped looks like</p>
            <p className="mt-1 text-text-muted">
              High REGISTER or OPTIONS volume, scanner User-Agents (sippts, sipvicious), clusters of
              401 / 403 / 404 responses with little 2xx success, and PIKE or flood signatures from a
              single source IP.
            </p>
          </div>
        </div>
      </MetricFrame>
    </div>
  );
}
