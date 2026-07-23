import type { NextAuthOptions } from "next-auth";
import KeycloakProvider from "next-auth/providers/keycloak";

export type AuthMode = "configured" | "insecure-dev" | "blocked";

const DEFAULT_SECRETS = new Set(["change-me-local-only"]);

function hasValidIssuer(): boolean {
  return Boolean(process.env.KEYCLOAK_ISSUER?.trim());
}

function hasValidSecret(): boolean {
  const secret = process.env.NEXTAUTH_SECRET?.trim();
  return secret !== undefined && secret !== "" && !DEFAULT_SECRETS.has(secret);
}

export function getAuthMode(): AuthMode {
  if (process.env.DASHBOARD_ALLOW_INSECURE === "true") {
    return "insecure-dev";
  }
  if (hasValidIssuer() && hasValidSecret()) {
    return "configured";
  }
  return "blocked";
}

export function isAuthEnabled(): boolean {
  return getAuthMode() === "configured";
}

function keycloakBrowserAuthUrl(): string {
  const browserUrl = process.env.KEYCLOAK_BROWSER_AUTH_URL?.trim();
  if (browserUrl) {
    return browserUrl;
  }
  const issuer = process.env.KEYCLOAK_ISSUER?.trim() ?? "";
  return `${issuer}/protocol/openid-connect/auth`;
}

// Split-horizon discovery: the issuer (KEYCLOAK_ISSUER) is the browser-facing
// frontend URL (localhost:8080) used to validate the id_token `iss` claim, but
// the dashboard server cannot reach localhost:8080. KEYCLOAK_WELL_KNOWN_URL points
// discovery at the in-cluster URL (keycloak:8080); with Keycloak's
// KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true the discovered token/userinfo/jwks endpoints
// resolve to keycloak:8080 (server-reachable) while issuer + auth stay frontend-facing.
function keycloakWellKnownUrl(): string | undefined {
  const wk = process.env.KEYCLOAK_WELL_KNOWN_URL?.trim();
  return wk && wk.length > 0 ? wk : undefined;
}

export const authOptions: NextAuthOptions = {
  providers:
    getAuthMode() === "configured"
      ? [
          KeycloakProvider({
            clientId: process.env.KEYCLOAK_CLIENT_ID ?? "ngn-sip-dashboard",
            clientSecret: process.env.KEYCLOAK_CLIENT_SECRET ?? "",
            issuer: process.env.KEYCLOAK_ISSUER,
            ...(keycloakWellKnownUrl() ? { wellKnown: keycloakWellKnownUrl() } : {}),
            authorization: {
              url: keycloakBrowserAuthUrl(),
              params: {
                scope: "openid email profile",
              },
            },
          }),
        ]
      : [],
  session: {
    strategy: "jwt",
    maxAge: 8 * 60 * 60,
  },
  pages: {
    signIn: "/login",
  },
  callbacks: {
    async jwt({ token, account, profile }) {
      if (account) {
        token.accessToken = account.access_token;
      }
      if (profile && "roles" in profile) {
        token.roles = (profile as { roles?: string[] }).roles;
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.roles = (token.roles as string[]) ?? [];
      }
      return session;
    },
  },
  secret: process.env.NEXTAUTH_SECRET,
};

declare module "next-auth" {
  interface Session {
    user: {
      name?: string | null;
      email?: string | null;
      image?: string | null;
      roles?: string[];
    };
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    accessToken?: string;
    roles?: string[];
  }
}
