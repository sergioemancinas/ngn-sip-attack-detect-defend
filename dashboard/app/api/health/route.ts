import { NextResponse } from "next/server";
import { clickhousePing, tableExists } from "@/lib/clickhouse";
import { isAuthEnabled } from "@/lib/auth";

export async function GET() {
  const clickhouse = await clickhousePing();
  const sipEvents = await tableExists("sip_events");

  return NextResponse.json({
    status: clickhouse ? "ok" : "degraded",
    clickhouse,
    sip_events_table: sipEvents,
    auth_mode: isAuthEnabled() ? "keycloak" : "local-open",
    timestamp: new Date().toISOString(),
  });
}
