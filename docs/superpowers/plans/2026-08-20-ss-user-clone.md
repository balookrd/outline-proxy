# План реализации: «Дублировать УЗ» в ss-панели `outline-ui`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Добавить в ss-панель `outline-ui` действие «Clone» на строке пользователя: клик открывает форму создания, предзаполненную носителем шаблонного юзера (метод, пути, fwmark, enabled) с уже сгенерированными секретами; админ дописывает `id` и жмёт «Create».

**Architecture:** Только фронтенд (`bins/outline-ui/frontend`, Svelte 5). Крипто-генерация секретов и сборка полей формы — чистые функции в `lib/userForm.ts` (unit-тесты на vitest, random/uuid инъектируются). `UserDrawer.svelte` получает третий вход `seedFields` (create-режим с префиллом). `Users.svelte` добавляет кнопку и `openCloneDrawer`. Существующий `createUser` и control API не меняются; data-plane бинарь `outline-ss-rust` не трогаем.

**Tech Stack:** Svelte 5 (runes: `$state`/`$derived`/`$effect`/`$props`), TypeScript, Vite 8, Vitest 4, WebCrypto (`crypto.getRandomValues`/`crypto.randomUUID`), Tailwind + `app.css`.

## Global Constraints

- **Рабочий каталог фронта:** все `pnpm`/`vitest`/`vite` команды выполнять из `bins/outline-ui/frontend`.
- **Фронтенд-гейт (CI `ci.yml:184`):** `pnpm exec svelte-check --tsconfig ./tsconfig.app.json`, `pnpm exec vitest run`, `pnpm build` — все три обязаны быть зелёными.
- **Тесты рядом с модулем:** `lib/foo.test.ts` возле `lib/foo.ts` (действующая практика фронта; правило Rust `tests/` сюда не применяется).
- **Язык:** UI-подписи и комментарии в коде — английские (дашборд англоязычный: «Add user», «Edit user»). Git-коммиты — английские. Никаких trailer'ов `Co-Authored-By` и пометок об авторстве Claude.
- **Секреты:** генерировать только через WebCrypto; не логировать. Пути НЕ генерировать — копировать из шаблона (сервер принимает лишь предрегистрированные пути).
- **`method=default`:** пароль вслепую не генерировать (UI не знает серверный шифр) — вернуть `null`, в UI показать подсказку выбрать метод.
- **Не коммитить/пушить без явной команды владельца** — каждый шаг «Commit» выполнять только по подтверждению (либо оставить diff и ждать).

---

### Task 1: Крипто-генераторы секретов в `userForm.ts`

Чистые функции генерации `password` (по методу) и `vless_id`. Инъекция источника
случайности ради детерминированных тестов.

**Files:**
- Modify: `bins/outline-ui/frontend/src/lib/userForm.ts`
- Test: `bins/outline-ui/frontend/src/lib/userForm.test.ts`

**Interfaces:**
- Produces:
  - `type RandomBytes = (n: number) => Uint8Array`
  - `const webCryptoBytes: RandomBytes`
  - `generatePassword(method: string, rand?: RandomBytes): string | null` — SS-2022 метод → `base64(master key фикс. длины 16/32)`; legacy AEAD-метод → `base64url(24 байта)`; `''` (default) → `null`.
  - `generateVlessId(uuid?: () => string): string` — UUID v4.

- [ ] **Step 1: Написать падающие тесты**

Добавить в конец `bins/outline-ui/frontend/src/lib/userForm.test.ts`:

```ts
import {
  generatePassword,
  generateVlessId,
} from './userForm';

// Deterministic byte source: n bytes all equal to 0x07. Lets us assert the
// decoded master-key length without depending on real randomness.
const fixedBytes = (n: number): Uint8Array => new Uint8Array(n).fill(7);

describe('generatePassword', () => {
  it('SS-2022 aes-128 → base64 of a 16-byte master key', () => {
    const pw = generatePassword('2022-blake3-aes-128-gcm', fixedBytes);
    expect(pw).not.toBeNull();
    expect(atob(pw as string).length).toBe(16);
  });
  it('SS-2022 aes-256 → base64 of a 32-byte master key', () => {
    const pw = generatePassword('2022-blake3-aes-256-gcm', fixedBytes);
    expect(atob(pw as string).length).toBe(32);
  });
  it('SS-2022 chacha20 → base64 of a 32-byte master key', () => {
    const pw = generatePassword('2022-blake3-chacha20-poly1305', fixedBytes);
    expect(atob(pw as string).length).toBe(32);
  });
  it('legacy AEAD method → non-empty base64url secret (no padding, url-safe)', () => {
    const pw = generatePassword('aes-256-gcm', fixedBytes) as string;
    expect(pw.length).toBeGreaterThan(0);
    expect(pw).toMatch(/^[A-Za-z0-9_-]+$/);
  });
  it('empty method (server default) → null (UI cannot know the cipher)', () => {
    expect(generatePassword('', fixedBytes)).toBeNull();
  });
});

describe('generateVlessId', () => {
  it('returns the injected uuid verbatim', () => {
    expect(generateVlessId(() => 'fixed-uuid-value')).toBe('fixed-uuid-value');
  });
  it('default source produces a v4 UUID', () => {
    expect(generateVlessId()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });
});
```

- [ ] **Step 2: Прогнать тест — убедиться, что падает**

Run (из `bins/outline-ui/frontend`):
```bash
pnpm exec vitest run src/lib/userForm.test.ts
```
Expected: FAIL — `generatePassword`/`generateVlessId` не экспортированы (`No "generatePassword" export`).

- [ ] **Step 3: Реализовать генераторы**

Добавить в `bins/outline-ui/frontend/src/lib/userForm.ts` (после импортов, до `emptyUserFields`):

```ts
// Random-bytes source, injectable so unit tests stay deterministic. Default
// is WebCrypto (available in the browser and in Vitest's Node env via the
// global `crypto`).
export type RandomBytes = (n: number) => Uint8Array;
export const webCryptoBytes: RandomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// SS-2022 master-key length per cipher (bins/outline-ss-rust crates/outline-wire
// cipher.rs::key_len). For these methods the Shadowsocks "password" IS the
// base64 of a raw key of exactly this length.
const SS2022_KEY_LEN: Record<string, number> = {
  '2022-blake3-aes-128-gcm': 16,
  '2022-blake3-aes-256-gcm': 32,
  '2022-blake3-chacha20-poly1305': 32,
};

// Generate a Shadowsocks password appropriate for `method`:
//   - SS-2022  → base64 of a fresh random master key of the exact length;
//   - legacy AEAD (aes-*-gcm, chacha20-ietf-poly1305) → an arbitrary random
//     secret (the server EVP-derives the key from it), url-safe base64;
//   - '' (server default) → null: the UI does not know the server's effective
//     cipher, so it must not guess a format. Caller prompts to pick a method.
export function generatePassword(method: string, rand: RandomBytes = webCryptoBytes): string | null {
  if (!method) return null;
  const keyLen = SS2022_KEY_LEN[method];
  if (keyLen) return bytesToBase64(rand(keyLen));
  return bytesToBase64Url(rand(24));
}

export function generateVlessId(uuid: () => string = () => crypto.randomUUID()): string {
  return uuid();
}
```

- [ ] **Step 4: Прогнать тест — убедиться, что проходит**

Run (из `bins/outline-ui/frontend`):
```bash
pnpm exec vitest run src/lib/userForm.test.ts
```
Expected: PASS — все тесты `generatePassword`/`generateVlessId` зелёные, прежние тесты `userForm.test.ts` не сломаны.

- [ ] **Step 5: Commit** (по подтверждению владельца)

```bash
git add bins/outline-ui/frontend/src/lib/userForm.ts bins/outline-ui/frontend/src/lib/userForm.test.ts
git commit -m "feat(ui): add secret generators for ss user cloning"
```

---

### Task 2: `cloneUserFields` в `userForm.ts`

Собирает поля формы создания из шаблонного пользователя: копирует носитель,
генерит секреты только под имеющиеся идентичности, обнуляет `id`/`aliases`.

**Files:**
- Modify: `bins/outline-ui/frontend/src/lib/userForm.ts`
- Test: `bins/outline-ui/frontend/src/lib/userForm.test.ts`

**Interfaces:**
- Consumes (Task 1): `RandomBytes`, `webCryptoBytes`, `generatePassword`, `generateVlessId`; существующие `fieldsFromUser`, `UserFormFields`.
- Produces:
  - `cloneUserFields(template: User, rand?: RandomBytes, uuid?: () => string): UserFormFields`

- [ ] **Step 1: Написать падающие тесты**

Добавить в `bins/outline-ui/frontend/src/lib/userForm.test.ts`:

```ts
import { cloneUserFields } from './userForm';

const fixed7 = (n: number): Uint8Array => new Uint8Array(n).fill(7);
const fixedUuid = () => 'uuid-fixed';

describe('cloneUserFields', () => {
  it('copies the carrier, generates a password, blanks id/aliases (SS-2022 template)', () => {
    const template: User = {
      id: 'team-madrid',
      enabled: true,
      method: '2022-blake3-aes-256-gcm',
      fwmark: 7,
      ws_path_tcp: '/tcp',
      ws_path_ss: '/pss',
      xhttp_path_vless: '/pxhttp',
      aliases: { mobile: '10.0.0.0/8' },
      has_password: true,
    };
    const out = cloneUserFields(template, fixed7, fixedUuid);
    expect(out.id).toBe('');
    expect(out.aliases).toBe('');
    expect(out.method).toBe('2022-blake3-aes-256-gcm');
    expect(out.fwmark).toBe(7);
    expect(out.wsPathTcp).toBe('/tcp');
    expect(out.wsPathSs).toBe('/pss');
    expect(out.xhttpPathVless).toBe('/pxhttp');
    expect(out.enabled).toBe(true);
    expect(atob(out.password).length).toBe(32);
    expect(out.vlessId).toBe(''); // no has_vless_id on the template
  });

  it('generates vless_id only when the template has one', () => {
    const template: User = {
      id: 'v-only', enabled: true, method: '2022-blake3-aes-256-gcm',
      ws_path_vless: '/vless', has_vless_id: true,
    };
    const out = cloneUserFields(template, fixed7, fixedUuid);
    expect(out.vlessId).toBe('uuid-fixed');
    expect(out.password).toBe(''); // no has_password
  });

  it('generates both secrets when the template has both identities', () => {
    const template: User = {
      id: 'both', enabled: false, method: '2022-blake3-aes-128-gcm',
      ws_path_ss: '/pss', ws_path_vless: '/vless',
      has_password: true, has_vless_id: true,
    };
    const out = cloneUserFields(template, fixed7, fixedUuid);
    expect(atob(out.password).length).toBe(16);
    expect(out.vlessId).toBe('uuid-fixed');
    expect(out.enabled).toBe(false); // enabled copied verbatim
  });

  it('default-method template: password stays blank (not guessed)', () => {
    const template: User = {
      id: 'def', enabled: true, ws_path_ss: '/pss', has_password: true,
    };
    const out = cloneUserFields(template, fixed7, fixedUuid);
    expect(out.method).toBe('');
    expect(out.password).toBe('');
  });
});
```

- [ ] **Step 2: Прогнать тест — убедиться, что падает**

Run (из `bins/outline-ui/frontend`):
```bash
pnpm exec vitest run src/lib/userForm.test.ts
```
Expected: FAIL — `No "cloneUserFields" export`.

- [ ] **Step 3: Реализовать `cloneUserFields`**

Добавить в `bins/outline-ui/frontend/src/lib/userForm.ts` (после `fieldsFromUser`):

```ts
// Build create-form fields from an existing user as a template ("clone a
// similar account"): the carrier (method, fwmark, all ws/xhttp paths, enabled)
// is copied verbatim via fieldsFromUser; `id` and `aliases` are blanked (id
// must be unique; alias names are globally unique server-side, so they cannot
// be duplicated); fresh secrets are generated only for the identities the
// template actually has. A default-method template yields a blank password —
// generatePassword returns null and the drawer prompts the operator to pick a
// method (the UI cannot know the server's effective cipher).
export function cloneUserFields(
  template: User,
  rand: RandomBytes = webCryptoBytes,
  uuid: () => string = () => crypto.randomUUID(),
): UserFormFields {
  const base = fieldsFromUser(template);
  return {
    ...base,
    id: '',
    aliases: '',
    password: template.has_password ? (generatePassword(base.method, rand) ?? '') : '',
    vlessId: template.has_vless_id ? generateVlessId(uuid) : '',
  };
}
```

- [ ] **Step 4: Прогнать тест — убедиться, что проходит**

Run (из `bins/outline-ui/frontend`):
```bash
pnpm exec vitest run src/lib/userForm.test.ts
```
Expected: PASS — все тесты `cloneUserFields` зелёные; прежние тесты не тронуты.

- [ ] **Step 5: Commit** (по подтверждению владельца)

```bash
git add bins/outline-ui/frontend/src/lib/userForm.ts bins/outline-ui/frontend/src/lib/userForm.test.ts
git commit -m "feat(ui): build clone-user form fields from a template"
```

---

### Task 3: `UserDrawer.svelte` — clone-режим (seed + показ/регенерация секретов)

Третий вход формы: create-режим с префиллом `seedFields`, заголовок «Clone
user», секреты видны открыто, кнопки перегенерации. Гейт компонента —
`svelte-check` + `build` (в проекте `.svelte` юнит-тестами не покрываются) плюс
ручная проверка.

**Files:**
- Modify: `bins/outline-ui/frontend/src/features/ss/UserDrawer.svelte`
- Modify: `bins/outline-ui/frontend/src/app.css`

**Interfaces:**
- Consumes (Task 1): `generatePassword`, `generateVlessId`, `webCryptoBytes`, `UserFormFields`.
- Produces: новый опциональный проп `seedFields?: UserFormFields | null` у `UserDrawer` (потребитель — Task 4). Контракт create/edit не меняется: без `seedFields` поведение прежнее.

- [ ] **Step 1: Расширить импорты и пропсы**

В `UserDrawer.svelte`, заменить строку импорта из `userForm`:
```ts
  import { emptyUserFields, fieldsFromUser, validateUserForm, buildUserPayload } from '../../lib/userForm';
```
на:
```ts
  import {
    emptyUserFields, fieldsFromUser, validateUserForm, buildUserPayload,
    generatePassword, generateVlessId, webCryptoBytes,
  } from '../../lib/userForm';
  import type { UserFormFields } from '../../lib/userForm';
```

В типе `$props()` добавить `seedFields` (после `editingUser`):
```ts
    open: boolean;
    editingUser?: User | null;
    seedFields?: UserFormFields | null;
    onclose: () => void;
```
и в деструктуризации (после `editingUser = null,`):
```ts
    editingUser = null,
    seedFields = null,
    onclose,
    onsave,
```

- [ ] **Step 2: Добавить derived/state и хендлеры регенерации**

После `const hasVlessId = $derived(...)` добавить:
```ts
  // Clone mode = create (no editingUser) seeded from a template. Drives the
  // header label, the open-secret display, and the regenerate/show controls.
  const cloning = $derived(!editing && seedFields != null);
  let showSecret = $state(false);
```

После `let idInput: HTMLInputElement | undefined;` добавить хендлеры:
```ts
  function regeneratePassword() {
    const pw = generatePassword(fields.method, webCryptoBytes);
    if (pw === null) {
      toast('Choose a method to generate a password.', 'error');
      return;
    }
    fields.password = pw;
    showSecret = true;
  }
  function regenerateVlessId() {
    fields.vlessId = generateVlessId();
    showSecret = true;
  }
```

- [ ] **Step 3: Обновить $effect префилла (seed + видимость секретов)**

Заменить тело первого `$effect` (внутри `if (!open) return;`) строку:
```ts
    fields = editingUser ? fieldsFromUser(editingUser) : emptyUserFields();
```
на:
```ts
    // Copy the seed so editing the form never mutates the parent's snapshot.
    fields = editingUser ? fieldsFromUser(editingUser) : (seedFields ? { ...seedFields } : emptyUserFields());
    // Clone secrets are meant to be read and copied out — show them by default.
    showSecret = !editingUser && seedFields != null;
```

- [ ] **Step 4: Заголовок и секрет-поля в разметке**

Заменить заголовок:
```svelte
    <h3>{editing ? 'Edit user' : 'Add user'}</h3>
```
на:
```svelte
    <h3>{editing ? 'Edit user' : cloning ? 'Clone user' : 'Add user'}</h3>
```

Заменить весь блок Password `<div class="fieldrow">…</div>` (label + input + hint) на:
```svelte
    <div class="fieldrow">
      <label for="user-password">Password</label>
      <div class="secret-row">
        <input
          id="user-password"
          class="field-mono"
          type={showSecret ? 'text' : 'password'}
          bind:value={fields.password}
          autocomplete="new-password"
          placeholder={editing ? (hasPassword ? 'keep current password' : 'add Shadowsocks password') : 'for Shadowsocks'}
        />
        {#if cloning}
          <button class="iconbtn" type="button" title="Show/hide" aria-label="Show or hide password" onclick={() => (showSecret = !showSecret)}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
          <button class="iconbtn" type="button" title="Regenerate password" aria-label="Regenerate password" onclick={regeneratePassword}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-2.64-6.36M21 3v6h-6"/></svg>
          </button>
        {/if}
      </div>
      <span class="hint">{cloning && !fields.method ? 'Choose a method, then regenerate the password.' : 'password or vless_id is required.'}</span>
    </div>
```

Заменить весь блок VLESS UUID `<div class="fieldrow">…</div>` на:
```svelte
    <div class="fieldrow">
      <label for="user-vless-id">VLESS UUID</label>
      <div class="secret-row">
        <input
          id="user-vless-id"
          class="field-mono"
          type="text"
          bind:value={fields.vlessId}
          autocomplete="off"
          placeholder={editing ? (hasVlessId ? 'keep current UUID' : 'add VLESS UUID') : 'xxxxxxxx-xxxx-...'}
        />
        {#if cloning}
          <button class="iconbtn" type="button" title="Regenerate UUID" aria-label="Regenerate VLESS UUID" onclick={regenerateVlessId}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-2.64-6.36M21 3v6h-6"/></svg>
          </button>
        {/if}
      </div>
    </div>
```

- [ ] **Step 5: CSS для `.secret-row`**

Добавить в `bins/outline-ui/frontend/src/app.css` рядом с `.fieldrow` (например после строки `.rowactions { ... }` или в секции форм-полей):
```css
.secret-row { display: flex; gap: 6px; align-items: center; }
.secret-row input { flex: 1 1 auto; min-width: 0; }
```

- [ ] **Step 6: Проверка типов и сборка**

Run (из `bins/outline-ui/frontend`):
```bash
pnpm exec svelte-check --tsconfig ./tsconfig.app.json && pnpm build
```
Expected: `svelte-check found 0 errors` и успешная сборка (`dist/` собран). Существующие create/edit-потоки не затронуты (seedFields по умолчанию `null`).

- [ ] **Step 7: Прогнать все фронт-тесты (регресс)**

Run (из `bins/outline-ui/frontend`):
```bash
pnpm exec vitest run
```
Expected: PASS — все существующие тесты зелёные (компонент логику из `userForm.ts` не дублирует).

- [ ] **Step 8: Commit** (по подтверждению владельца)

```bash
git add bins/outline-ui/frontend/src/features/ss/UserDrawer.svelte bins/outline-ui/frontend/src/app.css
git commit -m "feat(ui): support clone mode in the ss user drawer"
```

---

### Task 4: `Users.svelte` — кнопка «Clone» и проброс `seedFields`

Строчная кнопка Clone открывает drawer в clone-режиме через `cloneUserFields`.
Гейт — `svelte-check` + `build` + ручная e2e-проверка.

**Files:**
- Modify: `bins/outline-ui/frontend/src/features/ss/Users.svelte`

**Interfaces:**
- Consumes (Task 2): `cloneUserFields`, тип `UserFormFields`. (Task 3): проп `seedFields` у `UserDrawer`.

- [ ] **Step 1: Импорт и состояние seed**

В `Users.svelte` после строки `import UserDrawer from './UserDrawer.svelte';` добавить:
```ts
  import { cloneUserFields } from '../../lib/userForm';
  import type { UserFormFields } from '../../lib/userForm';
```

После `let editingUser = $state<User | null>(null);` добавить:
```ts
  let seedFields = $state<UserFormFields | null>(null);
```

- [ ] **Step 2: Обновить open/close-хендлеры и добавить `openCloneDrawer`**

Заменить `openCreateDrawer`/`openEditDrawer`/`closeDrawer` на версии, сбрасывающие/устанавливающие `seedFields`:
```ts
  function openCreateDrawer() {
    editingUser = null;
    seedFields = null;
    drawerOpen = true;
  }
  function openEditDrawer(user: User) {
    editingUser = user;
    seedFields = null;
    drawerOpen = true;
  }
  function openCloneDrawer(user: User) {
    // Snapshot the template into seed fields (fresh secrets, blank id/aliases);
    // create-mode drawer (editingUser stays null) prefilled from it.
    editingUser = null;
    seedFields = cloneUserFields(user);
    drawerOpen = true;
  }
  function closeDrawer() {
    drawerOpen = false;
    editingUser = null;
    seedFields = null;
  }
```

- [ ] **Step 3: Кнопка «Clone» в сниппете `rowActions`**

В `{#snippet rowActions(user: User)}` первой кнопкой (перед «Edit») добавить:
```svelte
            <button class="iconbtn act-activate" title="Clone" disabled={mutating} aria-label={`Clone ${user.id}`} onclick={() => openCloneDrawer(user)}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
            </button>
```

- [ ] **Step 4: Прокинуть `seedFields` в drawer**

Заменить монтирование drawer:
```svelte
<UserDrawer open={drawerOpen} {editingUser} onclose={closeDrawer} onsave={saveUser} />
```
на:
```svelte
<UserDrawer open={drawerOpen} {editingUser} {seedFields} onclose={closeDrawer} onsave={saveUser} />
```

- [ ] **Step 5: Проверка типов и сборка**

Run (из `bins/outline-ui/frontend`):
```bash
pnpm exec svelte-check --tsconfig ./tsconfig.app.json && pnpm build
```
Expected: `0 errors`, успешная сборка.

- [ ] **Step 6: Ручная e2e-проверка**

Run (из `bins/outline-ui/frontend`): `pnpm dev`, открыть `http://localhost:5173/ss` (dev-прокси к control API на `:9500`). Проверить:
1. У пользователя со Shadowsocks-паролем и явным SS-2022 методом нажать **Clone** → drawer с заголовком «Clone user», метод и пути скопированы, поле Password заполнено видимым секретом, `id` пуст и в фокусе.
2. Кнопка ↻ у Password меняет секрет; кнопка «глаз» скрывает/показывает.
3. Вписать новый `id` → **Create** → тост «User created», новая строка появляется в таблице.
4. Клонировать пользователя с `method=default` → поле Password пустое, подсказка «Choose a method, then regenerate the password.»; выбрать метод, нажать ↻ → секрет появляется.
5. Клонировать VLESS-only пользователя → поле VLESS UUID заполнено новым UUID, Password пуст.

Expected: все пять сценариев проходят; в существующих потоках Add user / Edit user секрет-кнопки не появляются, поведение прежнее.

- [ ] **Step 7: Commit** (по подтверждению владельца)

```bash
git add bins/outline-ui/frontend/src/features/ss/Users.svelte
git commit -m "feat(ui): add clone action to the ss users table"
```

---

## Итоговая проверка перед завершением

Из `bins/outline-ui/frontend` прогнать полный фронт-гейт (как в CI):
```bash
pnpm exec svelte-check --tsconfig ./tsconfig.app.json && pnpm exec vitest run && pnpm build
```
Expected: `svelte-check` 0 ошибок, все тесты зелёные, сборка успешна.

## Соответствие спеке (self-review)

- §1 UX-поток → Task 3 (clone-режим drawer), Task 4 (кнопка + `openCloneDrawer`).
- §2 матрица переноса → Task 2 `cloneUserFields` (носитель копируется, id/aliases пусты) + тесты.
- §3 генерация по методу, default → Task 1 `generatePassword` (+ null для default), Task 3 подсказка/регенерация.
- §4 модель компонентов (чистые функции + seed-контракт) → Task 1/2 (userForm.ts), Task 3 (проп seedFields), Task 4 (проброс).
- §5 тесты → Task 1/2 (vitest), Task 3/4 (svelte-check + build + ручная e2e).
- Вне scope (серверная генерация, эндпоинт clone, копирование aliases, автосуффикс id, access_url) — ни одной задачи не заведено, как и требовалось.
