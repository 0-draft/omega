import { cn } from "@/lib/cn";

export function Kbd({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <kbd
      className={cn(
        "inline-flex h-5 min-w-5 items-center justify-center rounded border border-[var(--color-line)] bg-[var(--color-bg-muted)] px-1.5 font-mono text-[11px] text-[var(--color-fg-muted)]",
        className,
      )}
    >
      {children}
    </kbd>
  );
}
