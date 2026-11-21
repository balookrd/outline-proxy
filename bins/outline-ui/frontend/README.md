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
| `pnpm test` | Unit and component UI tests (`vitest run`, `happy-dom` + `@testing-library/svelte`) |
| `pnpm test:watch` | Runs Vitest in watch mode |
| `pnpm test:e2e` | Browser E2E tests in headless Chromium (`playwright test`) against built `dist/` (run `pnpm build` first) |

`pnpm dev` needs a running `outline-ui` backend on `127.0.0.1:9500`; see
"Running locally" in [`../README.md`](../README.md).

## Testing layers

1. **Unit & component UI tests (Vitest, `src/**/*.test.ts`)**: run in `happy-dom` with `@testing-library/svelte` and mocked `fetch` (`src/test/mockApi.ts`), verifying pure helpers (`src/lib/*.test.ts`), routing/shell/theme, drawers, forms, native `<dialog>` modals, and dashboard API payloads.
2. **Browser E2E tests (Playwright, `e2e/*.spec.ts`)**: run in headless Chromium against the built `dist/` bundle served by `e2e/static-server.mjs` with the same CSP and security headers as `bins/outline-ui/src/main.rs`. API calls are intercepted via `page.route()` (`e2e/mock-api.ts`); guards fail the test on any `console.error`, `pageerror`, CSP violation, broken `/ui-assets/*`, or mobile/desktop horizontal overflow.

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
| `src/test/` | Vitest DOM setup/polyfills, typed API fixtures, and `fetch` mock helpers |
| `e2e/` | Static production server (`static-server.mjs`), Playwright API mocks, and browser specs |
