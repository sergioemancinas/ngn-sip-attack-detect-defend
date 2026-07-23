"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { cn } from "@/lib/utils";
import { NAV_GROUPS } from "@/lib/nav";
import type { NavGroup, NavItem } from "@/lib/nav";
import { resolveSectionId } from "@/lib/sections";
import type { SectionId } from "@/lib/sections";
import type { AuthMode } from "@/lib/auth";

type StepState = "done" | "active" | "upcoming";

function PlainNavList({
  group,
  currentSection,
  onHome,
}: {
  group: NavGroup;
  currentSection: SectionId;
  onHome: boolean;
}) {
  return (
    <ul className="mt-1.5 space-y-0.5" role="list">
      {group.items.map((item) => {
        const active = onHome && currentSection === item.section;
        return (
          <li key={item.section}>
            <Link
              href={item.href}
              aria-current={active ? "page" : undefined}
              className={cn(
                "flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent",
                active
                  ? "bg-accent/15 font-medium text-accent"
                  : "text-text-muted hover:bg-surface-overlay/60 hover:text-text-secondary",
              )}
            >
              <span
                className={cn(
                  "h-1.5 w-1.5 shrink-0 rounded-full",
                  active ? "bg-accent" : "bg-surface-border",
                )}
                aria-hidden
              />
              {item.label}
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

function PipelineStep({
  item,
  index,
  total,
  state,
  active,
}: {
  item: NavItem;
  index: number;
  total: number;
  state: StepState;
  active: boolean;
}) {
  const isFirst = index === 0;
  const isLast = index === total - 1;
  // The rail fills below the active step once it is reached, so the nav reads as
  // progress through the pipeline.
  const topFilled = state === "done" || state === "active";
  const bottomFilled = state === "done";

  return (
    <li>
      <Link
        href={item.href}
        aria-current={active ? "page" : undefined}
        className={cn(
          "group relative flex min-h-[44px] items-center gap-3 rounded-lg pl-2 pr-3 text-sm transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent",
          active ? "bg-accent/10" : "hover:bg-surface-overlay/60",
        )}
      >
        <span className="relative flex w-7 shrink-0 items-center justify-center self-stretch">
          {!isFirst ? (
            <span
              aria-hidden
              className={cn(
                "absolute left-1/2 top-0 h-1/2 w-px -translate-x-1/2",
                topFilled ? "bg-accent/55" : "bg-surface-border",
              )}
            />
          ) : null}
          {!isLast ? (
            <span
              aria-hidden
              className={cn(
                "absolute bottom-0 left-1/2 h-1/2 w-px -translate-x-1/2",
                bottomFilled ? "bg-accent/55" : "bg-surface-border",
              )}
            />
          ) : null}
          <span
            className={cn(
              "relative z-10 flex h-6 w-6 items-center justify-center rounded-full border text-[11px] font-semibold tabular-nums transition",
              state === "active" &&
                "border-accent bg-accent text-white ring-2 ring-accent/25",
              state === "done" && "border-accent/40 bg-accent/15 text-accent",
              state === "upcoming" &&
                "border-surface-border bg-surface-raised text-text-muted group-hover:border-surface-muted group-hover:text-text-secondary",
            )}
          >
            {index + 1}
          </span>
        </span>

        <span className="flex min-w-0 flex-1 items-center justify-between gap-2">
          <span
            className={cn(
              "truncate",
              state === "active"
                ? "font-medium text-accent"
                : state === "done"
                  ? "text-text-secondary group-hover:text-text-primary"
                  : "text-text-muted group-hover:text-text-secondary",
            )}
          >
            {item.label}
          </span>
          {item.hint ? (
            <span
              className={cn(
                "shrink-0 rounded-md px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide",
                state === "active"
                  ? "bg-accent/15 text-accent"
                  : "bg-surface-overlay/70 text-text-muted",
              )}
            >
              {item.hint}
            </span>
          ) : null}
        </span>
      </Link>
    </li>
  );
}

function PipelineNavList({
  group,
  currentSection,
  onHome,
}: {
  group: NavGroup;
  currentSection: SectionId;
  onHome: boolean;
}) {
  const activeIndex = onHome
    ? group.items.findIndex((item) => item.section === currentSection)
    : -1;

  return (
    <ol className="relative mt-1.5" role="list">
      {group.items.map((item, index) => {
        const active = onHome && currentSection === item.section;
        const state: StepState =
          activeIndex < 0
            ? "upcoming"
            : index < activeIndex
              ? "done"
              : index === activeIndex
                ? "active"
                : "upcoming";

        return (
          <PipelineStep
            key={item.section}
            item={item}
            index={index}
            total={group.items.length}
            state={state}
            active={active}
          />
        );
      })}
    </ol>
  );
}

export function Sidebar({
  activeSection,
  collapsed,
  authMode,
}: {
  activeSection?: SectionId;
  collapsed?: boolean;
  authMode?: AuthMode;
}) {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const currentSection = activeSection ?? resolveSectionId(searchParams.get("section"));
  const onHome = pathname === "/";

  if (collapsed) return null;

  return (
    <aside className="fixed inset-y-0 left-0 z-50 hidden w-64 flex-col border-r border-surface-border bg-surface-raised/95 backdrop-blur lg:flex">
      <div className="border-b border-surface-border px-5 py-5">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent/15 text-accent">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
              <path d="M12 3l8 4v10l-8 4-8-4V7l8-4z" strokeLinejoin="round" />
              <path d="M12 7v14M4 7l8 4 8-4" strokeLinejoin="round" />
            </svg>
          </div>
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-widest text-accent">NGN SIP Lab</p>
            <h1 className="text-base font-semibold text-text-primary">Security Operations</h1>
          </div>
        </div>
        <p className="mt-2 text-xs text-text-muted">SIP attack-detect-defend monitoring</p>
      </div>

      <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4" aria-label="Dashboard sections">
        {NAV_GROUPS.map((group) => (
          <div key={group.id}>
            <div className="px-2">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-text-muted">
                {group.label}
              </p>
              {group.caption ? (
                <p className="mt-0.5 text-[10px] text-text-muted/70">{group.caption}</p>
              ) : null}
            </div>
            {group.kind === "pipeline" ? (
              <PipelineNavList group={group} currentSection={currentSection} onHome={onHome} />
            ) : (
              <PlainNavList group={group} currentSection={currentSection} onHome={onHome} />
            )}
          </div>
        ))}
      </nav>

      <div className="border-t border-surface-border px-4 py-3">
        {authMode === "insecure-dev" ? (
          <p className="mb-2 text-[10px] leading-relaxed text-text-muted">
            Development mode: authentication disabled.
          </p>
        ) : null}
        <p className="text-[10px] leading-relaxed text-text-muted">
          NGN course lab · TH Köln
        </p>
      </div>
    </aside>
  );
}
