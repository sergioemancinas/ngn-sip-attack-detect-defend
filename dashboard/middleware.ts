import { withAuth } from "next-auth/middleware";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getAuthMode } from "@/lib/auth";

const authMode = getAuthMode();

export default authMode === "configured"
  ? withAuth({
      pages: {
        signIn: "/login",
      },
    })
  : authMode === "insecure-dev"
    ? function middleware() {
        // explicit local dev opt-in only
      }
    : function middleware(_req: NextRequest) {
        return NextResponse.json(
          { error: "Authentication not configured" },
          { status: 401 },
        );
      };

export const config = {
  matcher: [
    "/((?!api/auth|api/health|login|_next/static|_next/image|favicon.ico).*)",
  ],
};
