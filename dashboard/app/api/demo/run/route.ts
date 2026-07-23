import { NextResponse } from "next/server";
import { requireApiSession } from "@/lib/api-auth";

const DEFAULT_RUNNER_URL = "http://demo-runner:8088/run";

interface DemoRunResponse {
  run_id?: string;
  status?: string;
  detail?: string;
  error?: string;
}

export async function POST() {
  const authError = await requireApiSession();
  if (authError) return authError;

  const runnerUrl = process.env.DEMO_RUNNER_URL ?? DEFAULT_RUNNER_URL;

  try {
    const res = await fetch(runnerUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
      signal: AbortSignal.timeout(30_000),
    });

    let payload: DemoRunResponse;
    try {
      payload = (await res.json()) as DemoRunResponse;
    } catch {
      payload = { status: "error", detail: "Demo runner returned a non-JSON response" };
    }

    if (!res.ok) {
      return NextResponse.json(
        {
          status: payload.status ?? "error",
          detail:
            payload.detail ??
            payload.error ??
            "Demo runner returned an error. The bounded demo may already be in progress.",
          run_id: payload.run_id,
        },
        { status: res.status >= 400 && res.status < 600 ? res.status : 502 },
      );
    }

    return NextResponse.json({
      run_id: payload.run_id,
      status: payload.status ?? "started",
      detail: payload.detail ?? "Bounded SIP recon and REGISTER burst initiated.",
    });
  } catch {
    return NextResponse.json(
      {
        status: "unreachable",
        detail:
          "Demo runner is not reachable. Ensure the demo-runner service is running on the lab network.",
      },
      { status: 503 },
    );
  }
}
