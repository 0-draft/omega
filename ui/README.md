# Omega UI

Read-only admin dashboard for the Omega control plane.
Next.js 15 (App Router) + Tailwind CSS v4 + shadcn-style primitives,
hand-tuned to the Linear/Vercel design language. Lives in its own tree
on purpose - Omega's "one binary" promise applies to `server` / `agent` /
CLI, not the UI.

## Run locally

```bash
# 1. start the control plane (in the repo root)
make run-server

# 2. in another shell, the UI
cd ui
pnpm install
pnpm dev
# -> http://localhost:3000
```

The UI talks to the control plane via the Next rewrite at
`/api/omega/*` → `OMEGA_API` (default `http://127.0.0.1:8080`). Set
`OMEGA_API` in `ui/.env.local` to point elsewhere.

## Stack

| Layer       | Choice                              |
| ----------- | ----------------------------------- |
| Framework   | Next.js 15 (App Router, Turbopack)  |
| Styling     | Tailwind CSS v4 + CSS-first config  |
| Primitives  | Radix UI + cmdk + lucide-react      |
| Data        | @tanstack/react-query               |
| Validation  | zod                                 |
| Type system | TypeScript strict                   |
| Lint/format | Biome                               |
| Fonts       | Geist Sans + Geist Mono (OFL)       |

## Pages

| Route       | Surface                                              |
| ----------- | ---------------------------------------------------- |
| `/`         | Overview: counts, audit head, demo `curl`            |
| `/domains`  | SPIFFE namespace list                                |
| `/svid`     | Recent X.509 / JWT SVIDs (audit-derived)             |
| `/policy`   | AuthZEN evaluations (audit-derived)                  |
| `/audit`    | Full chain + verify badge                            |
| `/bundle`   | Download X.509 / JWKS bundles                        |

## Keyboard

- `⌘K` / `Ctrl+K` - command palette
- `g h` `g d` `g s` `g p` `g a` `g b` - jump to page

## Design rules

The UI is built against a 10-rule AI-slop avoidance list. Short
version:

- One accent color, no gradients, no `rounded-2xl shadow-md` cards.
- Geist Sans + Geist Mono. Inter is forbidden.
- Mono for SPIFFE IDs / hashes / kids - never truncated.
- Empty states show the next CLI command, not a button.
- No emoji. No "Welcome back!" copy.

## Status

Read-only. Mutation flows (create domain, issue SVID via UI) are a
planned follow-up.
