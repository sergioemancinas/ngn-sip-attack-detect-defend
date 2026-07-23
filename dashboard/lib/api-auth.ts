import { getServerSession } from "next-auth";
import { NextResponse } from "next/server";
import { authOptions, getAuthMode } from "@/lib/auth";

export async function requireApiSession(): Promise<NextResponse | null> {
  const mode = getAuthMode();
  if (mode === "insecure-dev") return null;
  if (mode === "blocked") {
    return NextResponse.json({ error: "Authentication not configured" }, { status: 401 });
  }
  const session = await getServerSession(authOptions);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  return null;
}
