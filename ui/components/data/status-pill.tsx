import { cn } from "@/lib/cn";

type Tone = "ok" | "warn" | "err" | "neutral";

const tones: Record<Tone, string> = {
  ok: "text-[var(--color-ok)] border-[color-mix(in_oklch,var(--color-ok)_30%,var(--color-line))]",
  warn: "text-[var(--color-warn)] border-[color-mix(in_oklch,var(--color-warn)_30%,var(--color-line))]",
  err: "text-[var(--color-err)] border-[color-mix(in_oklch,var(--color-err)_40%,var(--color-line))]",
  neutral: "text-[var(--color-fg-muted)] border-[var(--color-line)]",
};

export function StatusPill({
  tone = "neutral",
  children,
}: {
  tone?: Tone;
  children: React.ReactNode;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 font-mono text-[11px]",
        tones[tone],
      )}
    >
      <span
        className={cn("h-1.5 w-1.5 rounded-full bg-current", tone === "neutral" && "opacity-60")}
      />
      {children}
    </span>
  );
}
