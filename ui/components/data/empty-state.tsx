import { CodeBlock } from "./code";

// Empty state with a concrete next command. Every empty state shows
// what to type next instead of generic copy.
export function EmptyState({
  title,
  hint,
  command,
}: {
  title: string;
  hint?: string;
  command?: string;
}) {
  return (
    <div className="flex flex-col items-start gap-3 rounded-[6px] border border-dashed border-[var(--color-line)] bg-[var(--color-bg-raised)]/50 p-6">
      <div>
        <p className="font-medium text-[var(--color-fg)] text-sm">{title}</p>
        {hint && <p className="mt-1 text-[13px] text-[var(--color-fg-muted)]">{hint}</p>}
      </div>
      {command && <CodeBlock value={command} className="w-full max-w-2xl" />}
    </div>
  );
}
