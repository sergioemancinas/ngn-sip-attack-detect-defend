import { NextResponse } from "next/server";
import { requireApiSession } from "@/lib/api-auth";
import { enrichIp, normalizeIp } from "@/lib/enrich";

// GET /api/enrich?ip=<literal> -> geolocation + network attribution for one source.
// Auth-gated and SSRF-guarded: the ip param is validated to a bare IP literal before
// any upstream lookup, and the upstream host is fixed in lib/enrich.ts.
export async function GET(request: Request) {
  const denied = await requireApiSession();
  if (denied) return denied;

  const { searchParams } = new URL(request.url);
  const raw = searchParams.get("ip");
  if (!raw) return NextResponse.json({ error: "missing ip" }, { status: 400 });

  const ip = normalizeIp(raw);
  if (!ip) return NextResponse.json({ error: "invalid ip" }, { status: 400 });

  const data = await enrichIp(ip);
  if (!data) return NextResponse.json({ error: "enrichment unavailable" }, { status: 404 });

  return NextResponse.json(data);
}
