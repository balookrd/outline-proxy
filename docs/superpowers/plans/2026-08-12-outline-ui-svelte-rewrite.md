# План реализации: переписывание `outline-ui` на Svelte 5

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Заменить три вшитых `include_str!` HTML-дашборда одним Svelte 5 SPA, сохранив backend `outline-ui`, его гейты и весь API-контракт `…/dashboard/api/*` 1:1.

**Architecture:** Единый Vite+Svelte 5 бандл монтируется под `/`, `/ss`, `/ws`; клиентский роутер на `location.pathname`. Backend не меняется по контракту — только `assets.rs` начинает отдавать embedded `frontend/dist` (через `rust-embed` за feature `embed-assets`) плюс SPA-fallback. Фронт разрабатывается против dev-proxy к живому Axum, поэтому старый UI работает до задачи cutover.

**Tech Stack:** Svelte 5 (runes) · TypeScript · Vite · Tailwind CSS (`^3`) · TanStack Table `^8` (только Users) · vitest · pnpm. UI-примитивы (дровер, чипы, таблица, тумблер, toast) и **иконки — свои inline SVG**, по [прототипу](../specs/2026-08-12-outline-ui-svelte-rewrite-prototype.html) на Tailwind + CSS-токенах; `shadcn-svelte` и `lucide-svelte` НЕ тащим (прототип их не использует — YAGNI). Backend: Rust edition 2024, Axum, `rust-embed`.

## Global Constraints

Требования проекта, действующие на КАЖДУЮ задачу (значения — verbatim):

- **Rust edition 2024**, `rustfmt.toml` = 100 колонок. Тесты — в `<dir>/tests/<basename>.rs`, без inline `#[cfg(test)] mod tests {}`.
- **CI Rust-гейт** (гнать перед коммитом, в этом порядке):
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
    -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
    -p outline-tun -p outline-uplink -p outline-wire \
    -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  ```
- **Инварианты безопасности (не нарушать):** два гейта (`origin` inner + `auth` outer) до маршрутизации; per-instance токены только server-side; `control_url` браузеру не раскрывать; `list_instances` отдаёт лишь имена; процесс stateless; единый musl-бинарь на `scratch` — фронт **вшит** в бинарь, не отдаётся с диска.
- **API-контракт `…/dashboard/api/*` не менять** — существующие Rust-тесты остаются зелёными.
- **Bounded resources:** поллер имеет интервал + паузу по `visibilitychange`; никаких неограниченных таймеров.
- **Дизайн-токены** — из [спеки](../specs/2026-08-12-outline-ui-svelte-rewrite-design.md) и [прототипа](../specs/2026-08-12-outline-ui-svelte-rewrite-prototype.html). Тёмная тема по умолчанию; один акцент; Fira Sans/Code **вшиты** в бандл (woff2-subset, OFL) — не Google CDN.
- **Документация EN/RU** обновляется в одном изменении; спеки/планы — по-русски.
- **Коммиты/пуши — только по явной команде владельца.** Commit-шаги ниже исполнитель выполняет в рамках санкционированного прогона; `git push` — никогда без отдельной команды.
- **Стек-версии:** `pnpm`, Svelte `^5`, Vite `^5`, Tailwind `^3`, TanStack Table `^8` (`@tanstack/svelte-table`), `rust-embed = "8"`. Иконки — inline SVG (как прототип), без `lucide-svelte`/`shadcn-svelte`.
- **Фронт-тесты** — vitest, co-located `*.test.ts` рядом с модулем (конвенция vitest; правило «тесты в `tests/`» — только для Rust-крейтов). UI-компоненты (Task 5–10) проверяются `svelte-check` + паритет-чеком против backend, без unit-тестов на разметку.

## Файловая структура

```
bins/outline-ui/
├── Cargo.toml                     # +[features] embed-assets, +rust-embed (optional)
├── Dockerfile                     # → multi-stage: node → rust(zigbuild) → scratch
├── .gitignore                     # frontend/dist, frontend/node_modules
├── frontend/                      # НОВЫЙ Vite+Svelte проект
│   ├── package.json, pnpm-lock.yaml, vite.config.ts, svelte.config.js
│   ├── tsconfig.json, tailwind.config.ts, postcss.config.js
│   ├── index.html                 # single SPA entry
│   ├── fonts/                      # Fira Sans/Code woff2 (вшиваются)
│   └── src/
│       ├── main.ts, app.css        # токены + вшитые @font-face
│       ├── App.svelte              # Shell + router outlet
│       ├── lib/{router.svelte.ts,api.ts,poll.svelte.ts,types.ts,format.ts,theme.svelte.ts}
│       ├── components/{ui/*, layout/{Sidebar,Topbar,InstanceSelector,StatusDot,ErrorBanner}.svelte}
│       └── features/
│           ├── landing/Landing.svelte
│           ├── ss/{Users.svelte,UsersTable.svelte,UserDrawer.svelte}
│           └── ws/{Topology.svelte,GroupTable.svelte,WireChain.svelte,Uplinks.svelte}
└── src/
    ├── assets.rs                  # → embedded dist (feature) / stub; render() удаляется
    ├── main.rs                    # +asset-роут, +SPA-fallback
    ├── ss/mod.rs, ws/mod.rs       # dashboard/uplinks HTML-роуты удаляются
    └── … (auth/origin/backend/config/*api.rs — без изменений)
```

---

## Task 1: Scaffold фронт-проекта + dev-proxy

**Files:**
- Create: `bins/outline-ui/frontend/` (Vite+Svelte+TS scaffold), `bins/outline-ui/frontend/vite.config.ts`, `bins/outline-ui/frontend/tailwind.config.ts`, `bins/outline-ui/.gitignore`

**Interfaces:**
- Produces: рабочий `pnpm dev` на `:5173` с proxy `/ss`,`/ws`,`/ui-assets` → `127.0.0.1:9500` (локальный Axum); Vite `base: '/ui-assets/'`.

- [ ] **Step 1: Scaffold**

Run:
```bash
cd bins/outline-ui
pnpm create vite@latest frontend -- --template svelte-ts
cd frontend && pnpm install
pnpm add -D tailwindcss@^3 postcss autoprefixer
pnpm dlx tailwindcss@^3 init -p
```
(TanStack Table ставится в Task 6, где впервые нужен; иконки — inline SVG, без Lucide.)

- [ ] **Step 2: `vite.config.ts` — base + dev-proxy**

```ts
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  base: '/ui-assets/',            // assets served from an absolute prefix, outside /ss|/ws
  build: { outDir: 'dist', assetsDir: '.', emptyOutDir: true },
  server: {
    port: 5173,
    proxy: {
      '/ss/dashboard/api': 'http://127.0.0.1:9500',
      '/ws/dashboard/api': 'http://127.0.0.1:9500',
    },
  },
});
```

- [ ] **Step 3: `.gitignore`**

Create `bins/outline-ui/.gitignore`:
```
frontend/node_modules
frontend/dist
frontend/.svelte-kit
```

- [ ] **Step 4: Проверка**

Run: `cd bins/outline-ui/frontend && pnpm exec svelte-check --tsconfig ./tsconfig.json`
Expected: `0 errors`.
Run: `pnpm build` → Expected: `dist/index.html` + `dist/*.js` созданы.

- [ ] **Step 5: Commit**

```bash
git add bins/outline-ui/frontend bins/outline-ui/.gitignore
git commit -m "build(ui): scaffold svelte5 + vite frontend with dev proxy"
```

---

## Task 2: `lib/format.ts` — форматтеры (TDD)

**Files:**
- Create: `bins/outline-ui/frontend/src/lib/format.ts`, `bins/outline-ui/frontend/src/lib/format.test.ts`

**Interfaces:**
- Produces: `formatRtt(ms: number|null): string`, `formatLossPct(loss: number|null): string`, `parseAliases(text: string): string[]|null`, `initials(id: string): string`.

- [ ] **Step 1: Failing tests**

`format.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { formatRtt, formatLossPct, parseAliases, initials } from './format';

describe('format', () => {
  it('rtt', () => { expect(formatRtt(42)).toBe('42ms'); expect(formatRtt(null)).toBe('—'); });
  it('loss', () => {
    expect(formatLossPct(0)).toBe('0%');
    expect(formatLossPct(2.4)).toBe('2.4%');
    expect(formatLossPct(null)).toBe('—');
  });
  it('aliases split on comma/space, empty → null', () => {
    expect(parseAliases('a, b  c')).toEqual(['a', 'b', 'c']);
    expect(parseAliases('   ')).toBeNull();
  });
  it('initials', () => { expect(initials('iphone')).toBe('IP'); });
});
```

- [ ] **Step 2: Run — FAIL**

Run: `pnpm add -D vitest && pnpm exec vitest run src/lib/format.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `format.ts`**

```ts
export function formatRtt(ms: number | null): string {
  return ms == null ? '—' : `${Math.round(ms)}ms`;
}
export function formatLossPct(loss: number | null): string {
  if (loss == null) return '—';
  return loss === 0 ? '0%' : `${loss.toFixed(1)}%`;
}
export function parseAliases(text: string): string[] | null {
  const parts = text.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
  return parts.length ? parts : null;
}
export function initials(id: string): string {
  return id.slice(0, 2).toUpperCase();
}
```

- [ ] **Step 4: Run — PASS**

Run: `pnpm exec vitest run src/lib/format.test.ts` → Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add bins/outline-ui/frontend/src/lib/format.ts bins/outline-ui/frontend/src/lib/format.test.ts bins/outline-ui/frontend/package.json
git commit -m "feat(ui): add formatting helpers with tests"
```

---

## Task 3: `lib/types.ts` + `lib/api.ts` — типизированный REST-клиент (TDD на построение URL)

**Files:**
- Create: `bins/outline-ui/frontend/src/lib/types.ts`, `bins/outline-ui/frontend/src/lib/api.ts`, `bins/outline-ui/frontend/src/lib/api.test.ts`

**Interfaces (contracts — verbatim из `ss/api.rs`/`ws/api.rs`):**
- Consumes: backend `…/dashboard/api/*`.
- Produces:
  - `listInstances(base): Promise<InstancesResponse>` (`{instances:{name}[], refresh_interval_secs}`)
  - SS: `listUsers(instance)`, `createUser(instance, NewUser)`, `updateUser(instance, id, PatchUser)`, `deleteUser(instance, id)`, `blockUser(instance, id)`, `unblockUser(instance, id)`
  - WS: `topology(instance)`, `activate(ActivateBody)`, `reselect({instance,group,soft})`, `setEnabled({instance,group,uplink,enabled})`, `uplinks*` CRUD, `apply(instance)`

**Модель данных (эталон паритета — `ss/dashboard.html` payload(), `ws/dashboard.html` applyInstanceView; поля расширяются по мере переноса):**

- [ ] **Step 1: `types.ts`**

```ts
export interface Instance { name: string; }
export interface InstancesResponse { instances: Instance[]; refresh_interval_secs: number; }

// SS — fields mirror ss/dashboard.html payload(); server may add more (index signature keeps them).
export interface User {
  id: string; enabled: boolean;
  password?: string | null; vless_id?: string | null; method?: string | null;
  fwmark?: number | null; ws_path_tcp?: string | null; ws_path_udp?: string | null;
  ws_path_vless?: string | null; aliases?: string[] | null;
  created?: string; access_url?: string;
  [k: string]: unknown;
}
export type NewUser = Partial<User> & { id: string; enabled: boolean };
export type PatchUser = Partial<User>;

// WS — topology envelope from ws/api.rs InstanceView.
export interface TopologyResponse {
  name: string; ok: boolean; error?: string | null;
  topology?: { instance?: { groups?: Group[] } } | null;
}
export interface Group { name: string; uplinks?: Uplink[]; [k: string]: unknown; }
export interface Uplink {
  name: string; admin_disabled?: boolean; last_error?: string | null;
  [k: string]: unknown; // wire chains / rtt / loss / weight / role — see ws/dashboard.html renderer
}
export interface ActivateTarget { instance: string; group: string; uplink: string; }
export interface ActivateBody { targets: ActivateTarget[]; transport?: 'tcp'|'udp'|'both'; soft?: boolean; }
```

- [ ] **Step 2: Failing test (URL building)**

`api.test.ts`:
```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as api from './api';

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response('{"users":[]}', { status: 200 })));
});

describe('api urls', () => {
  it('listUsers passes instance in query', async () => {
    await api.listUsers('beelink102');
    expect((fetch as any).mock.calls[0][0]).toBe('/ss/dashboard/api/users?instance=beelink102');
  });
  it('updateUser encodes id in path', async () => {
    await api.updateUser('beelink102', 'a/b', { enabled: false });
    expect((fetch as any).mock.calls[0][0]).toBe('/ss/dashboard/api/users/a%2Fb?instance=beelink102');
  });
});
```

- [ ] **Step 3: Run — FAIL**

Run: `pnpm exec vitest run src/lib/api.test.ts` → Expected: FAIL.

- [ ] **Step 4: Implement `api.ts`**

```ts
import type { InstancesResponse, User, NewUser, PatchUser, TopologyResponse, ActivateBody } from './types';

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { cache: 'no-store', ...init });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((body as any)?.error || `HTTP ${res.status}`);
  return body as T;
}
const q = (instance: string) => `instance=${encodeURIComponent(instance)}`;
const seg = (id: string) => encodeURIComponent(id);
const post = (body: unknown): RequestInit =>
  ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

export const listInstances = (base: '/ss'|'/ws') => json<InstancesResponse>(`${base}/dashboard/api/instances`);

// SS
export const listUsers   = (i: string) => json<{ users: User[] }>(`/ss/dashboard/api/users?${q(i)}`).then(r => r.users);
export const createUser  = (i: string, u: NewUser)  => json<User>(`/ss/dashboard/api/users?${q(i)}`, post(u));
export const updateUser  = (i: string, id: string, p: PatchUser) =>
  json<User>(`/ss/dashboard/api/users/${seg(id)}?${q(i)}`, { ...post(p), method: 'PATCH' });
export const deleteUser  = (i: string, id: string) =>
  json<unknown>(`/ss/dashboard/api/users/${seg(id)}?${q(i)}`, { method: 'DELETE' });
export const blockUser   = (i: string, id: string) => json<User>(`/ss/dashboard/api/users/${seg(id)}/block?${q(i)}`, post({}));
export const unblockUser = (i: string, id: string) => json<User>(`/ss/dashboard/api/users/${seg(id)}/unblock?${q(i)}`, post({}));

// WS
export const topology  = (i: string) => json<TopologyResponse>(`/ws/dashboard/api/topology?${q(i)}`);
export const activate  = (b: ActivateBody) => json<{ results: unknown[] }>(`/ws/dashboard/api/activate`, post(b));
export const reselect  = (b: { instance: string; group: string; soft: boolean }) =>
  json<{ ok: boolean }>(`/ws/dashboard/api/reselect`, post(b));
export const setEnabled = (b: { instance: string; group: string; uplink: string; enabled: boolean }) =>
  json<{ ok: boolean }>(`/ws/dashboard/api/set_enabled`, post(b));
export const apply = (instance: string) => json<unknown>(`/ws/dashboard/api/apply`, post({ instance }));
```

- [ ] **Step 5: Run — PASS**, затем **Commit**

Run: `pnpm exec vitest run src/lib/api.test.ts` → PASS.
```bash
git add bins/outline-ui/frontend/src/lib/types.ts bins/outline-ui/frontend/src/lib/api.ts bins/outline-ui/frontend/src/lib/api.test.ts
git commit -m "feat(ui): typed REST client + domain types with url tests"
```

---

## Task 4: `lib/poll.svelte.ts` — runes-поллер с паузой по visibility (TDD)

**Files:**
- Create: `bins/outline-ui/frontend/src/lib/poll.svelte.ts`, `bins/outline-ui/frontend/src/lib/poll.test.ts`

**Interfaces:**
- Produces: `createPoll<T>(fn: () => Promise<T>, intervalMs: () => number)` → `{ data, error, loading, start(), stop() }` (runes-состояние); опрос ставится на паузу при `document.hidden`.

- [ ] **Step 1: Failing test (fake timers)**

`poll.test.ts`:
```ts
import { describe, it, expect, vi } from 'vitest';
import { createPoll } from './poll.svelte';

describe('poll', () => {
  it('runs immediately then on interval; stop() halts', async () => {
    vi.useFakeTimers();
    const fn = vi.fn(async () => 1);
    const p = createPoll(fn, () => 5000);
    p.start();
    await Promise.resolve();
    expect(fn).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(5000);
    expect(fn).toHaveBeenCalledTimes(2);
    p.stop();
    await vi.advanceTimersByTimeAsync(10000);
    expect(fn).toHaveBeenCalledTimes(2);
    vi.useRealTimers();
  });
});
```

- [ ] **Step 2: Run — FAIL** → `pnpm exec vitest run src/lib/poll.test.ts`

- [ ] **Step 3: Implement `poll.svelte.ts`**

```ts
export function createPoll<T>(fn: () => Promise<T>, intervalMs: () => number) {
  const s = $state<{ data: T | null; error: string | null; loading: boolean }>({
    data: null, error: null, loading: false,
  });
  let timer: ReturnType<typeof setTimeout> | null = null;
  let alive = false;

  async function tick() {
    if (typeof document !== 'undefined' && document.hidden) return schedule();
    s.loading = true;
    try { s.data = await fn(); s.error = null; }
    catch (e) { s.error = e instanceof Error ? e.message : String(e); }
    finally { s.loading = false; if (alive) schedule(); }
  }
  function schedule() { if (timer) clearTimeout(timer); timer = setTimeout(tick, Math.max(1000, intervalMs())); }

  return {
    get data() { return s.data; }, get error() { return s.error; }, get loading() { return s.loading; },
    start() { alive = true; tick(); }, stop() { alive = false; if (timer) clearTimeout(timer); timer = null; },
  };
}
```

- [ ] **Step 4: Run — PASS** → **Commit**
```bash
git add bins/outline-ui/frontend/src/lib/poll.svelte.ts bins/outline-ui/frontend/src/lib/poll.test.ts
git commit -m "feat(ui): visibility-aware polling primitive on runes"
```

---

## Task 5: Дизайн-токены, тема, роутер, Shell, лендинг

**Files:**
- Create: `frontend/src/app.css`, `frontend/fonts/*` (Fira woff2), `frontend/src/lib/theme.svelte.ts`, `frontend/src/lib/router.svelte.ts`, `frontend/src/App.svelte`, `frontend/src/components/layout/{Sidebar,Topbar}.svelte`, `frontend/src/features/landing/Landing.svelte`
- Reference (эталон стиля, скопировать токены/разметку): `docs/superpowers/specs/2026-08-12-outline-ui-svelte-rewrite-prototype.html`

**Interfaces:**
- Produces: `theme` store (`toggle()`, применяет `data-theme`), `route` store (`path`, `go(path)`), Shell с outlet.

- [ ] **Step 1: `app.css`** — перенести `:root`/`:root[data-theme=light]` токены и `@font-face` (Fira Sans/Code woff2 из `frontend/fonts/`) из прототипа (блок `<style>` … `--topo-cols`). Tailwind directives сверху (`@tailwind base/components/utilities`).

- [ ] **Step 2: `router.svelte.ts`** (минимальный, `location.pathname`)
```ts
export const route = $state({ path: typeof location !== 'undefined' ? location.pathname : '/' });
export function go(path: string) { history.pushState({}, '', path); route.path = path; }
if (typeof window !== 'undefined') window.addEventListener('popstate', () => { route.path = location.pathname; });
export function section(path = route.path): 'ss'|'ws'|'landing' {
  if (path.startsWith('/ss')) return 'ss';
  if (path.startsWith('/ws')) return 'ws';
  return 'landing';
}
```

- [ ] **Step 3: `theme.svelte.ts`**
```ts
export const theme = $state({ mode: (localStorage.getItem('theme') ?? 'dark') as 'dark'|'light' });
export function applyTheme() { document.documentElement.dataset.theme = theme.mode; }
export function toggleTheme() { theme.mode = theme.mode === 'dark' ? 'light' : 'dark'; localStorage.setItem('theme', theme.mode); applyTheme(); }
```

- [ ] **Step 4: `App.svelte`** — Shell (Topbar + Sidebar + `<main>`), выбор view по `section()`: `landing`→Landing, `ss`→Users, `ws` + `/ws/uplinks`→Uplinks иначе Topology. Разметку взять из прототипа (`.app`, `.topbar`, `.sidebar`, `.main`).

- [ ] **Step 5: `Landing.svelte`** — две capability-карточки (Server/Client), клик `go('/ss')`/`go('/ws')`. Разметка — блок `#view-landing` прототипа. Карточка показывается, только если соответствующий `listInstances` вернул непустой список.

- [ ] **Step 6: Проверка**

Run: `pnpm exec svelte-check` → `0 errors`.
Ручной паритет-чек (dev-proxy): `pnpm dev`, открыть `:5173/` — лендинг, переходы `/ss`↔`/ws`, переключатель темы меняет `data-theme`, `prefers-color-scheme` уважается.

- [ ] **Step 7: Commit**
```bash
git add bins/outline-ui/frontend/src
git commit -m "feat(ui): design tokens, theme, router, shell, landing"
```

---

## Task 6: SS Users — таблица (read-only паритет)

**Files:**
- Create: `frontend/src/components/layout/InstanceSelector.svelte`, `frontend/src/features/ss/Users.svelte`, `frontend/src/features/ss/UsersTable.svelte`
- Reference: `bins/outline-ui/src/ss/dashboard.html:1040-1100` (рендер строк/статус-чипа), прототип `#view-users`.

**Interfaces:**
- Consumes: `api.listInstances('/ss')`, `api.listUsers`, `createPoll`, TanStack `@tanstack/svelte-table`.
- Produces: `Users.svelte` (выбранный инстанс + автолист юзеров).

- [ ] **Step 1:** `InstanceSelector.svelte` — `<select>` из `listInstances('/ss'|'/ws')`, biнд выбранного имени; хранит `refresh_interval_secs`.
- [ ] **Step 2:** Установить таблицу: `pnpm add @tanstack/svelte-table` (если Svelte-адаптер несовместим с Svelte 5 — использовать `@tanstack/table-core` напрямую с runes; сообщить как DONE_WITH_CONCERNS). `UsersTable.svelte` — TanStack Table (columns: id+avatar, status-chip `active/blocked`, method-chip, access (copy-кнопка), created, actions-slot). Включить `getSortedRowModel` + глобальный фильтр по `id`/`method`. Виртуализацию НЕ подключать.
- [ ] **Step 3:** `Users.svelte` — `createPoll(() => listUsers(instance), () => refreshMs)`; toolbar (InstanceSelector, search, «New user» slot); `ErrorBanner` при `poll.error`; empty-state.
- [ ] **Step 4: Проверка** — `svelte-check` `0 errors`; против dev-proxy: список юзеров реального инстанса рисуется, сортировка/фильтр работают, «один мёртвый инстанс» показывает баннер, не пустую страницу.
- [ ] **Step 5: Commit**
```bash
git add bins/outline-ui/frontend/src
git commit -m "feat(ui): SS users table with instance selector and polling"
```

---

## Task 7: SS Users — CRUD-паритет (дровер, block/unblock, delete)

**Files:**
- Create: `frontend/src/features/ss/UserDrawer.svelte`
- Modify: `frontend/src/features/ss/Users.svelte`
- Reference: `bins/outline-ui/src/ss/dashboard.html:1105-1210` (payload(), saveUser, mutate), прототип drawer.

**Interfaces:**
- Consumes: `api.createUser/updateUser/deleteUser/blockUser/unblockUser`, `parseAliases`.

- [ ] **Step 1:** `UserDrawer.svelte` — поля из `payload()`: `id` (только create, disabled при edit), `password`, `vless_id`, `method`, `fwmark`(number), `ws_path_tcp/udp/vless`, `aliases`(→`parseAliases`), `enabled`(switch). При edit пустые `method/fwmark/ws_path_*` шлём `null` (reset), как в оригинале.
- [ ] **Step 2:** Валидация create: `password || vless_id` обязателен → toast-ошибка, не отправлять.
- [ ] **Step 3:** Проводка в `Users.svelte`: create/edit → `createPoll` рефетч; block/unblock/delete (delete с confirm) → рефетч; toasts на успех/ошибку.
- [ ] **Step 4: Проверка (паритет-чек против backend):** создать юзера, отредактировать, заблокировать, разблокировать, удалить — все отражаются после рефетча; `svelte-check` `0 errors`.
- [ ] **Step 5: Commit**
```bash
git add bins/outline-ui/frontend/src
git commit -m "feat(ui): SS user CRUD parity — drawer, block, delete"
```

---

## Task 8: WS Uplinks — CRUD + apply

**Files:**
- Create: `frontend/src/features/ws/Uplinks.svelte`, `frontend/src/lib/api.ts` (добавить `uplinksList/uplinksMutate`)
- Reference: `bins/outline-ui/src/ws/uplinks.html` (весь), прототип `#view-uplinks`.

**Interfaces:**
- Produces (в `api.ts`): `uplinksList(instance, filters?)` (GET passthrough), `uplinksMutate(method, instance, body)` (POST/PATCH/DELETE envelope `{instance, body}`), уже есть `apply(instance)`.

- [ ] **Step 1:** Добавить в `api.ts`:
```ts
export const uplinksList = (i: string, filters: Record<string,string> = {}) =>
  json<any>(`/ws/dashboard/api/uplinks?${new URLSearchParams({ instance: i, ...filters })}`);
export const uplinksMutate = (method: 'POST'|'PATCH'|'DELETE', i: string, body: unknown) =>
  json<any>(`/ws/dashboard/api/uplinks`, { ...post({ instance: i, body }), method });
```
- [ ] **Step 2:** `Uplinks.svelte` — таблица определений (name/endpoint/carrier/weight/probe) + apply-bar с pending-состоянием + Add/Edit/Delete (форма-дровер) + «Apply now»→`apply(instance)`. Поведение и поля — паритет из `uplinks.html`.
- [ ] **Step 3: Проверка** — `svelte-check` `0 errors`; против backend: список аплинков грузится, правка/apply проходят.
- [ ] **Step 4: Commit**
```bash
git add bins/outline-ui/frontend/src
git commit -m "feat(ui): WS uplinks CRUD with hot-apply"
```

---

## Task 9: WS Topology — read-view (grid, wire-chains, статусы)

**Files:**
- Create: `frontend/src/features/ws/Topology.svelte`, `frontend/src/features/ws/GroupTable.svelte`, `frontend/src/features/ws/WireChain.svelte`
- Reference: `bins/outline-ui/src/ws/dashboard.html:1196-1420` (applyInstanceView, renderInstanceBody, isActive/healthy, wire-chain), прототип `#view-topology` + `--topo-cols` (жёсткий grid).

**Interfaces:**
- Consumes: `api.topology` (на инстанс), `createPoll`, `formatRtt/formatLossPct`.
- Produces: `Topology.svelte` (карточки инстансов), `GroupTable.svelte` (grid строк аплинков), `WireChain.svelte` (пилюли сегментов с подсветкой активного).

- [ ] **Step 1:** `WireChain.svelte` — props `{ segments: string[], activeIdx: number }`, рендер моно-пилюль `h3/h2/ws/xhttp/direct` со стрелками, подсветка `activeIdx` (класс `.active-seg`). CSS — из прототипа (`.wire/.seg.*`).
- [ ] **Step 2:** `GroupTable.svelte` — заголовок группы (имя, cfg-чипы, «N active», «Reselect») + `colhead-row` + строки `uprow` через `var(--topo-cols)`. Извлечение полей uplink (role/status/wire chains/rtt/loss/weight) — по логике `ws/dashboard.html` (isActive, healthy, admin_disabled, last_error). Статусы: `Active/Ready/Down/Disabled`.
- [ ] **Step 3:** `Topology.svelte` — по одному `createPoll(() => topology(name))` на инстанс; карточка с `StatusDot`, временем `↻`, обработкой `ok:false` (баннер узла, не бланк страницы).
- [ ] **Step 4: Проверка** — `svelte-check` `0 errors`; против backend: топология реального инстанса рисуется, колонки заголовка и строк выровнены (жёсткий grid), активный wire-сегмент подсвечен, деградированный аплинк (`last_error`) виден.
- [ ] **Step 5: Commit**
```bash
git add bins/outline-ui/frontend/src
git commit -m "feat(ui): WS topology read view — groups, wire chains, statuses"
```

---

## Task 10: WS Topology — операции (activate/soft/reselect/enable)

**Files:**
- Modify: `frontend/src/features/ws/{Topology,GroupTable}.svelte`
- Reference: `bins/outline-ui/src/ws/dashboard.html:1300-1530` (activateEntries, reselectGroup, set_enabled).

**Interfaces:**
- Consumes: `api.activate` (`{targets:[{instance,group,uplink:uplink.name}], soft}`), `api.reselect`, `api.setEnabled`.

- [ ] **Step 1:** Кнопки строк по состоянию (как в оригинале): active→`Reselect`; ready→`Activate`(hard)+`Soft switch`+`Disable`; disabled→`Enable`. `Reselect` в шапке группы → `reselect({instance,group,soft:true})`.
- [ ] **Step 2:** Обработчики: `activate({ targets:[{instance,group,uplink:u.name}], soft })`; `setEnabled({instance,group,uplink:u.name,enabled})`. После действия — немедленный рефетч соответствующего инстанс-поллера; toast с результатом (`results[].ok` / `ok`).
- [ ] **Step 3: Проверка (паритет действий против backend/стенда):** activate (hard) переключает активный; soft — на кластерной группе; reselect; power on/off. `svelte-check` `0 errors`.
- [ ] **Step 4: Commit**
```bash
git add bins/outline-ui/frontend/src
git commit -m "feat(ui): WS topology operations — activate, soft, reselect, enable"
```

---

## Task 11: Rust — embed бандла за feature + asset-роут + SPA-fallback

**Files:**
- Modify: `bins/outline-ui/Cargo.toml`, `bins/outline-ui/src/assets.rs`, `bins/outline-ui/src/main.rs`
- Create: `bins/outline-ui/src/tests/assets.rs` дополнить (или новый кейс), fixture `frontend/dist/index.html` для теста с фичей.

**Interfaces:**
- Produces: `assets::spa_index() -> Response`, `assets::asset(path) -> Response`; при feature `embed-assets` — из embedded `../frontend/dist`, иначе — заглушка.

- [ ] **Step 1: `Cargo.toml`**
```toml
[features]
default = []
embed-assets = ["dep:rust-embed"]

[dependencies]
rust-embed = { version = "8", optional = true, features = ["mime-guess"] }
```

- [ ] **Step 2: Failing Rust test (без фичи — заглушка не паникует)**

В `src/tests/routing.rs` добавить:
```rust
#[tokio::test]
async fn spa_index_served_without_embed_feature_does_not_panic() {
    let cfg = /* минимальный UiConfig с token + listen, как в существующих тестах */;
    let app = build_app(&cfg);
    let res = app.oneshot(Request::get("/").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
```

- [ ] **Step 3: Run — FAIL** → `cargo test -p outline-ui spa_index_served_without_embed_feature_does_not_panic`

- [ ] **Step 4: Implement `assets.rs`**

```rust
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

#[cfg(feature = "embed-assets")]
mod embedded {
    use rust_embed::RustEmbed;
    #[derive(RustEmbed)]
    #[folder = "frontend/dist"]
    pub struct Assets;
}

/// SPA entry: index.html for every non-API, non-asset route.
pub fn spa_index() -> Response {
    #[cfg(feature = "embed-assets")]
    if let Some(f) = embedded::Assets::get("index.html") {
        return ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], f.data.into_owned()).into_response();
    }
    // stub keeps the default (node-less) build and its Rust gate green.
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")],
     "<!doctype html><title>outline-ui</title><p>assets not embedded (build with --features embed-assets)")
        .into_response()
}

/// One embedded asset (js/css/font/img) under the /ui-assets prefix.
pub fn asset(path: &str) -> Response {
    #[cfg(feature = "embed-assets")]
    if let Some(f) = embedded::Assets::get(path) {
        let mime = f.metadata.mimetype();
        return ([(header::CONTENT_TYPE, mime)], f.data.into_owned()).into_response();
    }
    #[cfg(not(feature = "embed-assets"))]
    let _ = path;
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

pub fn json_response(status: StatusCode, value: &serde_json::Value) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], value.to_string()).into_response()
}
pub fn json_error(status: StatusCode, message: &str) -> Response {
    json_response(status, &serde_json::json!({ "error": message }))
}
```
(Удалить `render()`, `INDEX_TEMPLATE`, `LOGO`, `html()`, `index()`, `logo()`, `not_found()` — заменяются на `spa_index`/`asset`; `json_*` сохранить.)

- [ ] **Step 5: `main.rs` — роуты**

```rust
.route("/ui-assets/{*path}", get(|axum::extract::Path(p): axum::extract::Path<String>| async move { assets::asset(&p) }))
.route("/", get(|| async { assets::spa_index() }))
.nest("/ws", ws::router(ws_state))
.nest("/ss", ss::router(ss_state))
.fallback(|| async { assets::spa_index() })   // client routes → SPA
```
Во вложенных `ss/mod.rs`/`ws/mod.rs` заменить `.fallback(not_found)` на `.fallback(|| async { crate::assets::spa_index() })`, чтобы перезагрузка `/ss/...`,`/ws/...` отдавала SPA (эти правки едут в Task 12 вместе с удалением HTML-роутов).

- [ ] **Step 6: PASS + test с фичей**

Run без фичи: `cargo test -p outline-ui` → PASS.
Run с фичей (нужен fixture `frontend/dist/index.html`):
```bash
mkdir -p bins/outline-ui/frontend/dist && printf '<!doctype html><title>t</title>' > bins/outline-ui/frontend/dist/index.html
cargo test -p outline-ui --features embed-assets
```
Добавить тест `asset_and_index_served_with_embed_feature` (GET `/` → 200 содержит `<!doctype`, GET `/ui-assets/missing.js` → 404).

- [ ] **Step 7: Гейт + Commit**

Run: `cargo fmt -p outline-ui && cargo clippy -p outline-ui --all-targets --no-deps -- -D warnings`
```bash
git add bins/outline-ui/Cargo.toml bins/outline-ui/src/assets.rs bins/outline-ui/src/main.rs bins/outline-ui/src/tests
git commit -m "feat(ui): embed SPA bundle behind embed-assets feature + spa fallback"
```

---

## Task 12: Cutover — удалить старые HTML и шаблонизатор

**Files:**
- Delete: `bins/outline-ui/src/index.html`, `src/ss/dashboard.html`, `src/ws/dashboard.html`, `src/ws/uplinks.html`, `src/outline-logo.png`
- Modify: `src/ss/mod.rs`, `src/ws/mod.rs` (убрать `dashboard_page`/`uplinks_page`/logo-роуты, `DASHBOARD_TEMPLATE`/`BASE`/`render`), `src/ss/api.rs`, `src/ws/api.rs` (убрать `dashboard_page`), `src/tests/assets.rs`, `src/ws/tests/mod.rs` (удалить placeholder-тесты `__BASE__`).

**Interfaces:**
- Остаются все `…/dashboard/api/*` хендлеры; SPA-fallback (Task 11) обслуживает `/ss`,`/ws` UI-маршруты.

- [ ] **Step 1:** Удалить HTML/PNG и все `include_str!/include_bytes!` ссылки на них.
- [ ] **Step 2:** В `ss/mod.rs`/`ws/mod.rs` удалить `.route("/dashboard", …)`, `.route("/dashboard/uplinks", …)`, logo-роуты, `.route("/", redirect)`; оставить `…/dashboard/api/*`; `.fallback(spa_index)`.
- [ ] **Step 3:** Удалить тесты, проверяющие подстановку `__BASE__`/serve dashboard page (`ws/tests/mod.rs::serves_the_dashboard_page_with_its_prefix`, `serves_the_uplinks_page`; `tests/assets.rs` про render). API/instances/topology-тесты сохранить.
- [ ] **Step 4: Гейт**

Run:
```bash
cargo fmt --check -p outline-ui
cargo clippy -p outline-ui --all-targets --no-deps -- -D warnings
cargo test --workspace --exclude sockudo-ws
```
Expected: всё зелёное; ни одной ссылки на удалённые файлы.

- [ ] **Step 5: Commit**
```bash
git add -A bins/outline-ui/src
git commit -m "refactor(ui): remove legacy html dashboards and __BASE__ templating"
```

---

## Task 13: Dockerfile multi-stage + CI front-job + docs EN/RU + версия

**Files:**
- Modify: `bins/outline-ui/Dockerfile`, `.github/workflows/ci.yml`, `bins/outline-ui/README.md`, `bins/outline-ui/README.ru.md`, `bins/outline-ui/Cargo.toml` (version bump)

- [ ] **Step 1: Dockerfile**
```dockerfile
# 1) build the SPA
FROM node:22-alpine AS web
WORKDIR /web
RUN corepack enable
COPY bins/outline-ui/frontend/package.json bins/outline-ui/frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY bins/outline-ui/frontend/ ./
RUN pnpm build            # → /web/dist

# 2) build the binary with assets embedded
FROM rust:1-bookworm AS rust
WORKDIR /src
COPY . .
COPY --from=web /web/dist bins/outline-ui/frontend/dist
RUN cargo build --release -p outline-ui --features embed-assets --target aarch64-unknown-linux-musl

# 3) scratch — image is the binary
FROM scratch
COPY --from=rust /src/target/aarch64-unknown-linux-musl/release/outline-ui /outline-ui
USER 65534:65534
EXPOSE 9000
ENTRYPOINT ["/outline-ui"]
```
(Прод-сборка — как в README: `cargo zigbuild … --features embed-assets`; в CI/локально Docker выбирает удобный тулчейн. Сохранить musl-таргет.)

- [ ] **Step 2: CI front-job** — в `.github/workflows/ci.yml` добавить job `frontend`:
```yaml
frontend:
  runs-on: ubuntu-latest
  defaults: { run: { working-directory: bins/outline-ui/frontend } }
  steps:
    - uses: actions/checkout@v4
    - uses: pnpm/action-setup@v4
    - uses: actions/setup-node@v4
      with: { node-version: 22, cache: pnpm, cache-dependency-path: bins/outline-ui/frontend/pnpm-lock.yaml }
    - run: pnpm install --frozen-lockfile
    - run: pnpm exec svelte-check --tsconfig ./tsconfig.json
    - run: pnpm exec vitest run
    - run: pnpm build
```
Rust-джобы не трогать (они собирают без node; embed за фичей).

- [ ] **Step 3: docs EN/RU** — обновить `README.md` и `README.ru.md`: dev-режим (`pnpm dev` + proxy на `:9500`), сборка (`--features embed-assets`), multi-stage Dockerfile, CI-job; убрать упоминания `dashboard.html`/`__BASE__`. Обе стороны в этом же коммите.

- [ ] **Step 4: version bump** — `Cargo.toml` `version = "0.2.0"`.

- [ ] **Step 5: Финальный гейт**

Run:
```bash
cargo fmt --check -p outline-ui && cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings && cargo test --workspace --exclude sockudo-ws
(cd bins/outline-ui/frontend && pnpm exec svelte-check && pnpm exec vitest run && pnpm build)
```

- [ ] **Step 6: Commit**
```bash
git add bins/outline-ui/Dockerfile .github/workflows/ci.yml bins/outline-ui/README.md bins/outline-ui/README.ru.md bins/outline-ui/Cargo.toml
git commit -m "build(ui): multi-stage image, frontend CI job, docs, v0.2.0"
```

---

## Приёмка (definition of done)

- Оба гейта проходят: полный Rust CI-гейт + `frontend` (svelte-check, vitest, build).
- Паритет операций подтверждён против backend/стенда: **SS** create/edit/delete/block/unblock; **WS** activate(hard/soft)/reselect/set_enabled/apply/uplinks CRUD.
- Инварианты соблюдены: два гейта до роутинга; токены/`control_url` не утекают в браузер; `scratch` single-binary с вшитым фронтом; поллер с visibility-паузой.
- Старые `.html` и `__BASE__` удалены; docs EN/RU обновлены; версия `0.2.0`.
- Раскатка по существующей процедуре: zigbuild `--features embed-assets` → docker → `kubectl -n monitoring rollout restart deploy/outline-ui`.
