import type { StackHealthRow } from "@/types/layout";

export type ServiceHealthStatus = "healthy" | "idle" | "down" | "not_deployed";

export interface ServiceHealthRow {
  component: string;
  role: string;
  status: ServiceHealthStatus;
  detail: string;
  row_count: number;
  latest_event: string | null;
}

const PROBE_TIMEOUT_MS = 1500;

function isConnRefused(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const err = error as { cause?: { code?: string }; code?: string };
  const code = err.cause?.code ?? err.code;
  return code === "ECONNREFUSED" || code === "ENOTFOUND";
}

async function fetchWithTimeout(url: string): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
  try {
    return await fetch(url, { signal: controller.signal, cache: "no-store" });
  } finally {
    clearTimeout(timer);
  }
}

type ProbeOutcome = Pick<ServiceHealthRow, "status" | "detail">;

export async function probeHttp(
  url: string,
  validate: (res: Response, body: string) => boolean,
  options?: { treatRefusedAsNotDeployed?: boolean; reachableIsHealthy?: boolean },
): Promise<ProbeOutcome> {
  const treatRefused = options?.treatRefusedAsNotDeployed ?? false;
  const reachableIsHealthy = options?.reachableIsHealthy ?? false;

  try {
    const res = await fetchWithTimeout(url);
    const body = await res.text();
    if (validate(res, body)) {
      return { status: "healthy", detail: `HTTP ${res.status} OK` };
    }
    if (reachableIsHealthy) {
      return { status: "healthy", detail: `Reachable (HTTP ${res.status})` };
    }
    return { status: "down", detail: `Unexpected response (HTTP ${res.status})` };
  } catch (error) {
    if (treatRefused && isConnRefused(error)) {
      return { status: "not_deployed", detail: "Not reachable on docker network" };
    }
    if (error instanceof Error && error.name === "AbortError") {
      return { status: "down", detail: "Probe timed out (1.5s)" };
    }
    const message = error instanceof Error ? error.message : "Probe failed";
    return { status: "down", detail: message };
  }
}

export function sipPlaneStatus(
  latest: string | null,
  hours: number,
  rowCount: number,
): ServiceHealthStatus {
  if (rowCount > 0 && latest) {
    const ageMs = Date.now() - new Date(latest).getTime();
    const windowMs = hours * 3600 * 1000;
    if (ageMs <= windowMs * 0.25) return "healthy";
  }
  return "idle";
}

export function toStackHealthRow(row: ServiceHealthRow): StackHealthRow {
  return {
    component: row.component,
    description: row.role,
    row_count: row.row_count,
    latest_event: row.latest_event,
    status: row.status as StackHealthRow["status"],
  };
}

export function parseServiceHealthRow(row: StackHealthRow & { detail?: string }): ServiceHealthRow {
  const rawStatus = row.status as ServiceHealthStatus | "stale";
  const status: ServiceHealthStatus =
    rawStatus === "stale"
      ? "idle"
      : rawStatus === "healthy" || rawStatus === "idle" || rawStatus === "down" || rawStatus === "not_deployed"
        ? rawStatus
        : "idle";
  return {
    component: row.component,
    role: row.description,
    status,
    detail: row.detail ?? defaultDetail(row),
    row_count: row.row_count,
    latest_event: row.latest_event,
  };
}

function defaultDetail(row: StackHealthRow): string {
  if (row.latest_event) {
    return `Latest event ${new Date(row.latest_event).toLocaleString()}`;
  }
  if (row.row_count > 0) {
    return `${row.row_count.toLocaleString()} rows in window`;
  }
  return "No recent activity";
}
