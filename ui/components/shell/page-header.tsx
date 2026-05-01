/**
 * Page header. Title left, optional kicker (small monospace label above),
 * optional action slot right. Hand-tuned spacing — not framework-default.
 */
export function PageHeader({
  kicker,
  title,
  description,
  action,
}: {
  kicker?: string;
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <header className="mb-8 flex items-end justify-between gap-4 border-[var(--color-line)] border-b pb-5">
      <div>
        {kicker && (
          <p className="mb-1.5 font-mono text-[10.5px] text-[var(--color-fg-subtle)] uppercase tracking-[0.08em]">
            {kicker}
          </p>
        )}
        <h1 className="font-medium text-[20px] text-[var(--color-fg)] tracking-tight">{title}</h1>
        {description && (
          <p className="mt-1 max-w-xl text-[13.5px] text-[var(--color-fg-muted)] leading-relaxed">
            {description}
          </p>
        )}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </header>
  );
}
