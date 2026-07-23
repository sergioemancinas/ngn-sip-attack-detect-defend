import { Suspense } from "react";
import { DashboardShell } from "@/components/DashboardShell";
import { LoadingSpinner } from "@/components/ui/States";
import { getAuthMode, isAuthEnabled } from "@/lib/auth";

export default function HomePage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-surface p-6">
          <LoadingSpinner />
        </div>
      }
    >
      <DashboardShell authEnabled={isAuthEnabled()} authMode={getAuthMode()} />
    </Suspense>
  );
}
