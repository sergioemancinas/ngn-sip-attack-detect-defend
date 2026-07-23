"use client";

import { Sidebar } from "@/components/Sidebar";
import { TopBar } from "@/components/TopBar";
import type { AuthMode } from "@/lib/auth";
import type { SectionId } from "@/lib/sections";

export function AppShell({
  children,
  title,
  subtitle,
  hours,
  onHoursChange,
  hideChrome,
  authEnabled,
  authMode,
  refreshMs,
  lastUpdated,
  activeSection,
}: {
  children: React.ReactNode;
  title: string;
  subtitle?: string;
  hours: number;
  onHoursChange: (hours: number) => void;
  hideChrome?: boolean;
  authEnabled: boolean;
  authMode: AuthMode;
  refreshMs: number;
  lastUpdated: Date | null;
  activeSection?: SectionId;
}) {
  return (
    <div className="min-h-screen bg-surface">
      <Sidebar activeSection={activeSection} collapsed={hideChrome} authMode={authMode} />
      <div className="flex min-h-screen min-w-0 flex-col lg:pl-64">
        <TopBar
          title={title}
          subtitle={subtitle}
          hours={hours}
          onHoursChange={onHoursChange}
          hideChrome={hideChrome}
          authEnabled={authEnabled}
          authMode={authMode}
          refreshMs={refreshMs}
          lastUpdated={lastUpdated}
        />
        <main className="flex-1 overflow-auto p-4 lg:p-6 xl:p-8">
          <div key={activeSection} className="content-shell section-enter">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
