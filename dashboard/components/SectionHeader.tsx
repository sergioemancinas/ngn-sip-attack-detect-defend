export function SectionHeader({
  title,
  subtitle,
  description,
}: {
  title: string;
  subtitle?: string;
  description: string;
}) {
  return (
    <header className="panel-card relative overflow-hidden px-5 py-5 pl-6 sm:px-6 sm:py-6 sm:pl-7">
      <span
        aria-hidden
        className="absolute inset-y-4 left-0 w-1 rounded-full bg-gradient-to-b from-accent via-accent/60 to-transparent"
      />
      {subtitle ? (
        <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-accent">{subtitle}</p>
      ) : null}
      <h2 className="mt-1 text-display-md text-text-primary">{title}</h2>
      <p className="mt-3 max-w-4xl text-sm leading-relaxed text-text-secondary">{description}</p>
    </header>
  );
}
