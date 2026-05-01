/**
 * Global keyboard map. Linear/Vim convention: prefix with `g` for "go to".
 *
 * Bound at the layout level via a single keydown listener so we don't lose
 * focus context — pages don't have to wire up their own.
 */

import { useEffect } from "react";

export type ShortcutHandler = () => void;

export function useGlobalShortcuts(handlers: Record<string, ShortcutHandler>) {
  useEffect(() => {
    let prefix = "";
    let prefixTimeout: ReturnType<typeof setTimeout> | null = null;

    function onKey(e: KeyboardEvent) {
      const target = e.target as HTMLElement | null;
      if (target?.matches("input, textarea, [contenteditable=true]")) return;

      if (e.metaKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        handlers["mod+k"]?.();
        return;
      }
      if (e.ctrlKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        handlers["mod+k"]?.();
        return;
      }

      if (e.key === "g" && !prefix) {
        prefix = "g";
        prefixTimeout = setTimeout(() => {
          prefix = "";
        }, 800);
        return;
      }
      if (prefix === "g") {
        const combo = `g ${e.key.toLowerCase()}`;
        if (handlers[combo]) {
          e.preventDefault();
          handlers[combo]();
        }
        prefix = "";
        if (prefixTimeout) clearTimeout(prefixTimeout);
      }
    }

    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      if (prefixTimeout) clearTimeout(prefixTimeout);
    };
  }, [handlers]);
}
