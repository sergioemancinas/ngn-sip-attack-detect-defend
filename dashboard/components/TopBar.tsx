"use client";

import { useEffect, useRef, useState } from "react";
import { signIn, signOut, useSession } from "next-auth/react";
import { Badge } from "@/components/ui/Badge";
import type { AuthMode } from "@/lib/auth";
import { cn } from "@/lib/utils";

function formatRefreshTime(date: Date | null): string {
  if (!date) return "Waiting for first sync";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function AuthControls({ authMode }: { authMode: AuthMode }) {
  const { data: session, status } = useSession();

  if (authMode === "insecure-dev") {
    return (
      <div
        className="flex shrink-0 items-center rounded-lg border border-accent/30 bg-accent/10 px-2.5 py-1.5"
        title="Authentication disabled for local development"
      >
        <Badge variant="info" className="border-0 bg-transparent px-0 py-0 text-[10px] uppercase tracking-wide">
          Dev mode · no auth
        </Badge>
      </div>
    );
  }

  if (authMode !== "configured") {
    return null;
  }

  if (status === "loading") {
    return (
      <span className="text-xs text-text-muted" aria-live="polite">
        Checking session...
      </span>
    );
  }

  if (status === "authenticated" && session?.user) {
    const email = session.user.email ?? session.user.name ?? "Signed in";

    return (
      <div className="flex max-w-full shrink-0 items-center gap-2 rounded-lg border border-surface-border bg-surface-raised px-2.5 py-1.5">
        <span
          aria-hidden
          className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-accent/15 text-[10px] font-semibold uppercase text-accent"
        >
          {email.charAt(0)}
        </span>
        <span
          className="max-w-[120px] truncate text-xs text-text-secondary sm:max-w-[180px] md:max-w-[220px]"
          title={email}
        >
          {email}
        </span>
        <button
          type="button"
          onClick={() => signOut()}
          className="shrink-0 rounded-md border border-surface-border bg-surface px-2.5 py-1 text-xs font-medium text-text-primary transition hover:border-accent/50 hover:bg-surface-overlay focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        >
          Logout
        </button>
      </div>
    );
  }

  return (
    <button
      type="button"
      onClick={() => signIn("keycloak")}
      className="rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent-muted focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
    >
      Sign in
    </button>
  );
}

export function TopBar({
  title = "SIP Stack Dashboard",
  subtitle = "Real-time visibility across SIP ingest, detection, and response",
  hours,
  onHoursChange,
  hideChrome,
  authEnabled,
  authMode,
  refreshMs,
  lastUpdated,
}: {
  title?: string;
  subtitle?: string;
  hours: number;
  onHoursChange: (hours: number) => void;
  hideChrome?: boolean;
  authEnabled: boolean;
  authMode: AuthMode;
  refreshMs: number;
  lastUpdated: Date | null;
}) {
  if (hideChrome) {
    return (
      <div className="fixed right-3 top-3 z-50 rounded-lg border border-surface-border bg-surface-raised/95 px-3 py-2 text-xs text-text-muted backdrop-blur">
        Window {hours}h
      </div>
    );
  }

  return (
    <header className="sticky top-0 z-40 border-b border-surface-border bg-surface/85 backdrop-blur-md">
      <div className="flex flex-wrap items-center justify-between gap-4 px-4 py-3 lg:px-6">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-lg font-semibold text-text-primary">{title}</h2>
            <Badge variant="healthy">Live</Badge>
          </div>
          <p className="mt-0.5 text-xs text-text-muted">{subtitle}</p>
        </div>

        <div className="flex min-w-0 flex-wrap items-center justify-end gap-3">
          <label className="flex items-center gap-2 text-xs text-text-muted">
            <span className="hidden sm:inline">Time range</span>
            <select
              value={hours}
              onChange={(e) => onHoursChange(Number(e.target.value))}
              aria-label="Time range"
              className="rounded-lg border border-surface-border bg-surface-raised px-3 py-1.5 text-sm text-text-primary focus:border-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
            >
              {[1, 6, 12, 24, 48, 168].map((value) => (
                <option key={value} value={value}>
                  Last {value}h
                </option>
              ))}
            </select>
          </label>

          <div
            className="hidden items-center gap-2 rounded-lg border border-surface-border bg-surface-raised/70 px-3 py-1.5 text-xs text-text-muted md:flex"
            aria-live="polite"
          >
            <span
              className={cn(
                "h-2 w-2 rounded-full",
                lastUpdated ? "animate-pulse bg-accent-green" : "bg-surface-border",
              )}
              aria-hidden
            />
            <span>
              Refresh {Math.round(refreshMs / 1000)}s
              {lastUpdated ? ` · Updated ${formatRefreshTime(lastUpdated)}` : ""}
            </span>
          </div>

          <div className="flex shrink-0 items-center">
            {authEnabled || authMode === "insecure-dev" ? (
              <AuthControls authMode={authMode} />
            ) : null}
          </div>
        </div>
      </div>
    </header>
  );
}
