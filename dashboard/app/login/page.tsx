"use client";

import { signIn } from "next-auth/react";

export default function LoginPage() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-surface px-4">
      <div className="w-full max-w-md rounded-xl border border-surface-border bg-surface-raised p-8 shadow-card">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-accent">NGN SIP Lab</p>
        <h1 className="mt-2 text-2xl font-semibold text-text-primary">Security Operations Dashboard</h1>
        <p className="mt-3 text-sm text-text-muted">
          Sign in with Keycloak to access SIP QoS and security pipeline panels.
        </p>
        <button
          type="button"
          onClick={() => signIn("keycloak", { callbackUrl: "/" })}
          className="mt-8 w-full rounded-lg bg-accent px-4 py-2.5 text-sm font-medium text-white transition hover:bg-accent-muted"
        >
          Continue with Keycloak
        </button>
      </div>
    </div>
  );
}
