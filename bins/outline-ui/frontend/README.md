# outline-ui frontend

Svelte 5 + TypeScript SPA for both `outline-ui` dashboards (`/ws` and `/ss`),
built with Vite and Tailwind. How it plugs into the Rust binary (proxying,
`embed-assets`, deployment) is described in [`../README.md`](../README.md).

Requirements: Node 22 and pnpm 9 (the versions the `frontend` job in
`.github/workflows/ci.yml` uses).

## Commands

Run from `bins/outline-ui/frontend`:

| Command | What it does |
|---|---|
| `pnpm install --frozen-lockfile` | Installs dependencies from `pnpm-lock.yaml` |
| `pnpm dev` | Dev server on `http://localhost:5173`; proxies `/ss/dashboard/api` and `/ws/dashboard/api` to `127.0.0.1:9500` |
| `pnpm build` | Production build into `dist/`, assets under `/ui-assets/` |
| `pnpm check` | `svelte-check --tsconfig ./tsconfig.app.json` plus `tsc -p tsconfig.node.json` |
| `pnpm exec vitest run` | Unit tests (`src/lib/*.test.ts`) |

`pnpm dev` needs a running `outline-ui` backend on `127.0.0.1:9500`; see
"Running locally" in [`../README.md`](../README.md).

## Layout

| Path | Contents |
|---|---|
| `src/App.svelte`, `src/main.ts` | Entry point and top-level view switch |
| `src/lib/router.svelte.ts` | Client-side routing: `/ss*` → server dashboard, `/ws*` → client dashboard, anything else → landing |
| `src/lib/api.ts`, `src/lib/types.ts` | Calls to `/ws/dashboard/api` and `/ss/dashboard/api`, response types |
| `src/lib/*Form.ts` | Form models of users, uplinks, routes and groups |
| `src/features/ss/` | Server dashboard pages: users, cluster, server settings |
| `src/features/ws/` | Client dashboard pages: topology, uplinks, routing, groups, settings |
| `src/features/landing/` | Index page linking both dashboards |
| `src/components/layout/` | Top bar, sidebar, instance selector, error banner, toasts |
