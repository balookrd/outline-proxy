# План реализации: серверные дефолты для клона + фиксы темы

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Клон пользователя, работающего на серверных дефолтах, показывает
эффективный метод и пути (→ пароль генерируется сразу, «глаз» работает);
значок темы переключается луна↔солнце, а `theme-color` браузера следует теме.

**Architecture:** Три слоя. (1) `outline-ss-rust`: новый read-only эндпоинт
`GET /control/defaults` отдаёт дефолты, которые `UserManager` уже держит в
памяти. (2) `outline-ui` backend: `/ss/dashboard/api/defaults` форвардит на
инстанс тем же `forward`, что и users. (3) Frontend: `cloneUserFields` берёт
вторым аргументом `ServerDefaults` и подставляет их туда, где у шаблона пусто;
плюс независимый фикс темы в `theme.svelte.ts` + `Topbar.svelte`.

**Tech Stack:** Rust (axum 0.8, serde, tokio), Svelte 5 (runes), TypeScript,
Vitest 4, Vite 8.

## Global Constraints

- **Рабочие каталоги:** Rust — из корня репо (`/Users/mvmalykh/IdeaProjects/outline-proxy`);
  фронт (`pnpm`/`vitest`) — из `bins/outline-ui/frontend`.
- **Rust CI-гейт (обязателен, в этом порядке):** `cargo fmt --all -- --check`
  (валит ПЕРВЫМ и маскирует clippy), затем
  `cargo clippy --all-targets -- -D warnings`, затем `cargo test`.
  Дополнительно для ss-rust: `cargo check -p outline-ss-rust --no-default-features`
  (`--workspace` НЕ ловит забытый `#[cfg(feature = ...)]` из-за feature unification).
- **Фронтенд-гейт:** `pnpm exec svelte-check --tsconfig ./tsconfig.app.json`,
  `pnpm exec vitest run`, `pnpm build` — все три зелёные.
- **Тесты Rust — в подкаталогах `tests/`,** рядом с модулем; inline
  `#[cfg(test)] mod tests { ... }` не использовать. Для `control/manager.rs`
  тесты уже живут в `control/tests/manager.rs` (подключены `#[cfg(test)] mod tests;`
  в `manager.rs:649`) — дописывать туда же.
- **Фронт-тесты** — рядом с модулем: `src/lib/userForm.test.ts` (Vitest).
- **Новый эндпоинт аддитивен и read-only:** секретов не отдаёт (только метод и
  пути), живёт за тем же bearer-гейтом, что `/control/users`.
- **Язык:** код, комментарии, коммиты — английские. Спеки/планы — русские.
- **Не коммитить и не пушить без явной команды владельца** — шаги «Commit»
  выполнять только по подтверждению; иначе оставлять изменения в рабочем дереве.
- **Деплой в этом плане НЕ выполняется** — он отдельным этапом после ревью
  (7 ss-узлов + `outline-ui:1.0.8`), см. «Деплой» в спеке.

---

### Task 1: ss-rust — `ServerDefaults` + `UserManager::defaults()`

Сериализуемый снимок дефолтов, которые менеджер уже держит. Без блокировки
`Inner`: поля `default_*` неизменны после `new`.

**Files:**
- Modify: `bins/outline-ss-rust/src/server/control/manager.rs`
- Test: `bins/outline-ss-rust/src/server/control/tests/manager.rs`

**Interfaces:**
- Produces:
  - `pub(super) struct ServerDefaults { method: CipherKind, ws_path_tcp: String, ws_path_udp: String, ws_path_ss: Option<String>, ws_path_vless: Option<String>, xhttp_path_tcp: Option<String>, xhttp_path_udp: Option<String>, xhttp_path_ss: Option<String>, xhttp_path_vless: Option<String> }` (все поля `pub`)
  - `impl UserManager { pub(super) fn defaults(&self) -> ServerDefaults }`

- [ ] **Step 1: Написать падающий тест**

Дописать в конец `bins/outline-ss-rust/src/server/control/tests/manager.rs`:

```rust
/// The clone-a-user UI needs the server's effective method and paths: a user
/// that carries none of its own runs on these, and without them the UI cannot
/// generate a password (it does not know the cipher) or show the real paths.
#[tokio::test]
async fn defaults_expose_effective_method_and_paths() {
    let manager = test_manager().await;
    let defaults = manager.defaults();

    assert_eq!(defaults.method, CipherKind::AES_256_GCM);
    assert_eq!(defaults.ws_path_tcp, "/tcp");
    assert_eq!(defaults.ws_path_udp, "/udp");
}

/// Serialization is the wire contract for `GET /control/defaults`: the method
/// must be a plain cipher string and unset optional paths must be absent (not
/// `null`), matching how `UserView` already serializes.
#[test]
fn server_defaults_serializes_method_as_string_and_omits_unset_paths() {
    let defaults = ServerDefaults {
        method: CipherKind::AES_256_GCM,
        ws_path_tcp: "/tcp".to_string(),
        ws_path_udp: "/udp".to_string(),
        ws_path_ss: None,
        ws_path_vless: Some("/vless".to_string()),
        xhttp_path_tcp: None,
        xhttp_path_udp: None,
        xhttp_path_ss: None,
        xhttp_path_vless: None,
    };

    let json = serde_json::to_value(&defaults).unwrap();
    assert_eq!(json["method"], "aes-256-gcm");
    assert_eq!(json["ws_path_tcp"], "/tcp");
    assert_eq!(json["ws_path_vless"], "/vless");
    assert!(json.get("ws_path_ss").is_none(), "unset path must be omitted, not null");
    assert!(json.get("xhttp_path_tcp").is_none(), "unset path must be omitted, not null");
}
```

Если в `tests/manager.rs` ещё нет хелпера, который строит менеджер, — использовать
уже существующий в этом файле (он там есть: тесты менеджера его применяют).
Найти его имя: `grep -n "async fn test_manager\|fn manager(" bins/outline-ss-rust/src/server/control/tests/manager.rs`,
и в тесте выше подставить фактическое имя вместо `test_manager` и фактические
дефолтные пути/шифр, которыми этот хелпер конфигурирует менеджер (значения
`/tcp`, `/udp`, `AES_256_GCM` в тесте — под дефолты хелпера; если хелпер строит
другие, привести ожидания к ним).

- [ ] **Step 2: Прогнать тест — убедиться, что падает**

Run (из корня репо):
```bash
cargo test -p outline-ss-rust --features control server::control::tests::manager 2>&1 | tail -20
```
Expected: FAIL — компиляция не проходит: `cannot find type ServerDefaults`
и `no method named defaults found for struct UserManager`.

- [ ] **Step 3: Реализовать `ServerDefaults` и `defaults()`**

В `bins/outline-ss-rust/src/server/control/manager.rs` добавить структуру
сразу ПОСЛЕ блока `impl From<&UserEntry> for UserView` (то есть после строки
`}` , закрывающей этот impl):

```rust
/// The server-wide fallbacks a user inherits when it carries none of its own.
/// Exposed read-only over `GET /control/defaults` so the dashboard can show a
/// user's *effective* method and paths: cloning a user that runs on these
/// otherwise yields a blank form, and the UI cannot generate a password
/// without knowing the cipher. Carries no secrets — method and paths only.
#[derive(Debug, Serialize)]
pub(super) struct ServerDefaults {
    pub method: CipherKind,
    pub ws_path_tcp: String,
    pub ws_path_udp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_path_ss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_path_vless: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xhttp_path_tcp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xhttp_path_udp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xhttp_path_ss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xhttp_path_vless: Option<String>,
}
```

И метод — внутрь существующего `impl UserManager`, рядом с `list()`
(сразу перед `pub(super) async fn list(&self)`):

```rust
    /// Snapshot of the server-wide defaults. Not `async` and takes no lock:
    /// these fields are set once in `new` and never mutate, unlike the user
    /// list behind `Inner`.
    pub(super) fn defaults(&self) -> ServerDefaults {
        ServerDefaults {
            method: self.default_method,
            ws_path_tcp: self.default_ws_path_tcp.clone(),
            ws_path_udp: self.default_ws_path_udp.clone(),
            ws_path_ss: self.default_ws_path_ss.clone(),
            ws_path_vless: self.default_ws_path_vless.clone(),
            xhttp_path_tcp: self.default_xhttp_path_tcp.clone(),
            xhttp_path_udp: self.default_xhttp_path_udp.clone(),
            xhttp_path_ss: self.default_xhttp_path_ss.clone(),
            xhttp_path_vless: self.default_xhttp_path_vless.clone(),
        }
    }
```

- [ ] **Step 4: Прогнать тест — убедиться, что проходит**

Run (из корня репо):
```bash
cargo test -p outline-ss-rust --features control server::control::tests::manager 2>&1 | tail -20
```
Expected: PASS — оба новых теста зелёные, прежние тесты менеджера не сломаны.

- [ ] **Step 5: Прогнать Rust-гейт**

Run (из корня репо):
```bash
cargo fmt --all -- --check && cargo clippy -p outline-ss-rust --all-targets --features control -- -D warnings && cargo check -p outline-ss-rust --no-default-features
```
Expected: fmt без вывода, clippy без warnings, `--no-default-features` собирается
(новый код целиком под `control`-плоскостью, slim-сборка его не видит).

- [ ] **Step 6: Commit** (по подтверждению владельца)

```bash
git add bins/outline-ss-rust/src/server/control/manager.rs bins/outline-ss-rust/src/server/control/tests/manager.rs
git commit -m "feat(ss): expose server-wide defaults from the user manager"
```

---

### Task 2: ss-rust — эндпоинт `GET /control/defaults`

Handler + маршрут за тем же bearer-гейтом.

**Files:**
- Modify: `bins/outline-ss-rust/src/server/control/handlers.rs`
- Modify: `bins/outline-ss-rust/src/server/control/server.rs:57-62`
- Test: `bins/outline-ss-rust/src/server/control/tests/server.rs`

**Interfaces:**
- Consumes (Task 1): `UserManager::defaults() -> ServerDefaults`.
- Produces: `pub(super) async fn get_defaults(State<ControlState>) -> axum::response::Response`;
  маршрут `GET /control/defaults`.

- [ ] **Step 1: Написать падающий тест**

Дописать в конец `bins/outline-ss-rust/src/server/control/tests/server.rs`:

```rust
/// `/control/defaults` must sit behind the same bearer gate as every other
/// control route: it is read-only, but the control listener as a whole is
/// authenticated, and an unauthenticated 200 here would be a policy hole.
/// Drives a real request through the same router `run()` builds.
#[tokio::test]
async fn defaults_route_requires_the_bearer_token_and_answers_json() {
    use tower::ServiceExt; // for `oneshot`

    let state = test_control_state().await;
    let router = Router::new()
        .route("/control/defaults", get(get_defaults))
        .fallback(any(not_found))
        .layer(middleware::from_fn_with_state(state.clone(), require_bearer_token))
        .with_state(state);

    // No token -> rejected by the gate, never reaches the handler.
    let unauthorized = router
        .clone()
        .oneshot(Request::builder().uri("/control/defaults").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    // With the token -> 200 with the defaults payload.
    let authorized = router
        .oneshot(
            Request::builder()
                .uri("/control/defaults")
                .header(AUTHORIZATION, "Bearer test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);

    let body = axum::body::to_bytes(authorized.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["method"].is_string(), "method must be present as a string");
    assert!(json.get("password").is_none(), "defaults must never carry secrets");
    assert!(json.get("vless_id").is_none(), "defaults must never carry secrets");
}
```

Хелпер состояния: если в `tests/server.rs` уже есть конструктор `ControlState`
для тестов — использовать его имя вместо `test_control_state()`. Если нет,
добавить в этот же файл:

```rust
/// A control state over a manager with no users and the default paths — enough
/// to exercise routing and the bearer gate.
async fn test_control_state() -> ControlState {
    ControlState {
        manager: std::sync::Arc::new(crate::server::control::tests::manager::test_manager().await),
        token: std::sync::Arc::from("test-token"),
    }
}
```

где `test_manager()` — тот же хелпер, что использован в Task 1 (взять его
фактическое имя и путь модуля; если он приватный для `tests/manager.rs`,
сделать его `pub(super)` — это тестовый код, изменение безопасно).

- [ ] **Step 2: Прогнать тест — убедиться, что падает**

Run (из корня репо):
```bash
cargo test -p outline-ss-rust --features control server::control::tests::server 2>&1 | tail -20
```
Expected: FAIL — компиляция: `no function named get_defaults` в
`crate::server::control::handlers`.

- [ ] **Step 3: Реализовать handler**

В `bins/outline-ss-rust/src/server/control/handlers.rs` добавить сразу ПОСЛЕ
`list_users` (то есть после его закрывающей `}` на строке 153):

```rust
/// Read-only snapshot of the server-wide defaults (method + paths). The
/// dashboard needs it to show a user's *effective* configuration: a user that
/// carries no method of its own runs on `default_method`, and the clone form
/// cannot generate a password without knowing which cipher that is.
pub(super) async fn get_defaults(State(state): State<ControlState>) -> axum::response::Response {
    ok_json(state.manager.defaults())
}
```

- [ ] **Step 4: Зарегистрировать маршрут**

В `bins/outline-ss-rust/src/server/control/server.rs` в импорте handlers
(строки 27-30) добавить `get_defaults` в список — итоговый импорт:

```rust
use super::handlers::{
    ControlState, block_user, create_user, delete_user, get_defaults, get_user, list_users,
    unblock_user, update_user,
};
```

И в построении роутера (после строки с `/control/users/{id}/unblock`) добавить
маршрут — итоговый блок:

```rust
    let router = Router::new()
        .route("/control/users", get(list_users).post(create_user))
        .route("/control/users/{id}", get(get_user).patch(update_user).delete(delete_user))
        .route("/control/users/{id}/block", post(block_user))
        .route("/control/users/{id}/unblock", post(unblock_user))
        .route("/control/defaults", get(get_defaults))
        .fallback(any(not_found))
        .layer(middleware::from_fn_with_state(state.clone(), require_bearer_token))
        .with_state(state);
```

- [ ] **Step 5: Прогнать тест — убедиться, что проходит**

Run (из корня репо):
```bash
cargo test -p outline-ss-rust --features control server::control 2>&1 | tail -20
```
Expected: PASS — новый тест зелёный, тесты control-сервера не сломаны.

- [ ] **Step 6: Прогнать Rust-гейт**

Run (из корня репо):
```bash
cargo fmt --all -- --check && cargo clippy -p outline-ss-rust --all-targets --features control -- -D warnings && cargo check -p outline-ss-rust --no-default-features
```
Expected: всё зелёное, без warnings.

- [ ] **Step 7: Commit** (по подтверждению владельца)

```bash
git add bins/outline-ss-rust/src/server/control/handlers.rs bins/outline-ss-rust/src/server/control/server.rs bins/outline-ss-rust/src/server/control/tests/server.rs
git commit -m "feat(ss): add GET /control/defaults endpoint"
```

---

### Task 3: outline-ui backend — проксирование `/ss/dashboard/api/defaults`

Тот же `forward`, что у users; токен инстанса инъектится сервером.

**Files:**
- Modify: `bins/outline-ui/src/ss/api.rs`
- Modify: `bins/outline-ui/src/ss/mod.rs:21-29`
- Test: `bins/outline-ui/src/tests/routing.rs`

**Interfaces:**
- Produces: `pub async fn defaults(State<SsState>, Query<InstanceQuery>) -> Response`;
  маршрут `GET /dashboard/api/defaults` в ss-роутере (полный путь `/ss/dashboard/api/defaults`).

- [ ] **Step 1: Написать падающий тест**

Сначала посмотреть, как в `bins/outline-ui/src/tests/routing.rs` проверяются
существующие ss-маршруты:
```bash
grep -n 'dashboard/api' bins/outline-ui/src/tests/routing.rs
```
Дописать в конец `bins/outline-ui/src/tests/routing.rs` тест в том же стиле,
что уже используется в этом файле для `/ss/dashboard/api/users`. Если файл
проверяет маршруты через построение роутера и `oneshot`, тест такой:

```rust
/// The clone form fetches the instance's effective defaults through this
/// route; without it the request falls through to the SPA fallback and the
/// browser gets HTML where it expects JSON.
#[tokio::test]
async fn ss_defaults_route_is_not_the_spa_fallback() {
    let router = crate::ss::router(test_ss_state());
    let response = router
        .oneshot(
            http::Request::builder()
                .uri("/dashboard/api/defaults?instance=missing")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // An unknown instance is a 404 *from the handler* with a JSON body; the
    // SPA fallback would answer 200 text/html instead.
    let content_type = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.contains("application/json"),
        "expected JSON from the defaults handler, got content-type {content_type:?}"
    );
}
```

Имя хелпера состояния (`test_ss_state()`) взять фактическое из этого файла
(`grep -n "fn .*state\|SsState {" bins/outline-ui/src/tests/routing.rs`); если
существующие тесты строят состояние иначе — построить так же, как соседний
тест для `/ss/dashboard/api/users`.

- [ ] **Step 2: Прогнать тест — убедиться, что падает**

Run (из корня репо):
```bash
cargo test -p outline-ui 2>&1 | tail -20
```
Expected: FAIL — маршрут не зарегистрирован: ответ приходит от SPA-fallback
(`text/html`), ассерт про `application/json` не выполняется.

- [ ] **Step 3: Реализовать handler**

В `bins/outline-ui/src/ss/api.rs` добавить сразу ПОСЛЕ `list_users`:

```rust
/// Effective server-wide defaults (method + paths) of one instance. The clone
/// form needs them to fill a user that carries none of its own: without the
/// method it cannot generate a password, and the paths would show up blank.
pub async fn defaults(
    State(state): State<SsState>,
    Query(query): Query<InstanceQuery>,
) -> Response {
    forward(&state, &query.instance, Method::GET, "/control/defaults", None).await
}
```

- [ ] **Step 4: Зарегистрировать маршрут**

В `bins/outline-ui/src/ss/mod.rs` в `router()` добавить маршрут после
`/dashboard/api/instances` — итоговый блок:

```rust
pub fn router(state: SsState) -> Router {
    Router::new()
        .route("/dashboard/api/instances", get(api::list_instances))
        .route("/dashboard/api/defaults", get(api::defaults))
        .route("/dashboard/api/users", get(api::list_users).post(api::create_user))
        .route("/dashboard/api/users/{id}", patch(api::update_user).delete(api::delete_user))
        .route("/dashboard/api/users/{id}/block", post(api::block_user))
        .route("/dashboard/api/users/{id}/unblock", post(api::unblock_user))
        .fallback(|| async { crate::assets::spa_index() })
        .with_state(state)
}
```

- [ ] **Step 5: Прогнать тест — убедиться, что проходит**

Run (из корня репо):
```bash
cargo test -p outline-ui 2>&1 | tail -20
```
Expected: PASS — новый тест зелёный, остальные тесты `outline-ui` не сломаны.

- [ ] **Step 6: Прогнать Rust-гейт**

Run (из корня репо):
```bash
cargo fmt --all -- --check && cargo clippy -p outline-ui --all-targets -- -D warnings
```
Expected: без вывода fmt, clippy без warnings.

- [ ] **Step 7: Commit** (по подтверждению владельца)

```bash
git add bins/outline-ui/src/ss/api.rs bins/outline-ui/src/ss/mod.rs bins/outline-ui/src/tests/routing.rs
git commit -m "feat(ui): proxy instance defaults to the ss dashboard API"
```

---

### Task 4: frontend — тип, API-клиент и подстановка дефолтов в `cloneUserFields`

Чистая логика + юнит-тесты. Правило подстановки: дефолт применяется **только
там, где у шаблона пусто, и только по идентичностям шаблона**.

**Files:**
- Modify: `bins/outline-ui/frontend/src/lib/types.ts`
- Modify: `bins/outline-ui/frontend/src/lib/api.ts`
- Modify: `bins/outline-ui/frontend/src/lib/userForm.ts`
- Test: `bins/outline-ui/frontend/src/lib/userForm.test.ts`

**Interfaces:**
- Consumes: существующие `fieldsFromUser`, `UserFormFields`, `generatePassword`,
  `generateVlessId`, `webCryptoBytes`, `RandomBytes` (все в `lib/userForm.ts`).
- Produces:
  - `interface ServerDefaults` в `lib/types.ts`
  - `getDefaults(instance: string): Promise<ServerDefaults>` в `lib/api.ts`
  - `cloneUserFields(template: User, defaults?: ServerDefaults | null, rand?: RandomBytes, uuid?: () => string): UserFormFields`
    (второй параметр НОВЫЙ и опциональный — вызов с одним аргументом остаётся валидным)

- [ ] **Step 1: Добавить тип и API-клиент**

В `bins/outline-ui/frontend/src/lib/types.ts` добавить в конец:

```ts
// Server-wide fallbacks a user inherits when it carries none of its own —
// mirrors ServerDefaults in outline-ss-rust's control API. `method`,
// `ws_path_tcp` and `ws_path_udp` always come back; the rest are omitted
// when unset (the server skips `None`).
export interface ServerDefaults {
  method: string;
  ws_path_tcp: string;
  ws_path_udp: string;
  ws_path_ss?: string;
  ws_path_vless?: string;
  xhttp_path_tcp?: string;
  xhttp_path_udp?: string;
  xhttp_path_ss?: string;
  xhttp_path_vless?: string;
}
```

В `bins/outline-ui/frontend/src/lib/api.ts` добавить рядом с `listUsers`
(строка 42), сохраняя стиль файла:

```ts
export const getDefaults = (i: string) => json<ServerDefaults>(`/ss/dashboard/api/defaults?${q(i)}`);
```

и добавить `ServerDefaults` в существующий импорт типов из `./types` в этом файле
(найти строку `import type { ... } from './types';` и дописать имя в список).

- [ ] **Step 2: Написать падающие тесты**

Дописать в конец `bins/outline-ui/frontend/src/lib/userForm.test.ts`:

```ts
import type { ServerDefaults } from './types';

const srvDefaults: ServerDefaults = {
  method: '2022-blake3-aes-256-gcm',
  ws_path_tcp: '/dtcp',
  ws_path_udp: '/dudp',
  ws_path_vless: '/dvless',
  xhttp_path_vless: '/dxvless',
};

describe('cloneUserFields with server defaults', () => {
  it('fills the effective method so a default-method template still gets a password', () => {
    const template: User = { id: 'plain', enabled: true, has_password: true };
    const out = cloneUserFields(template, srvDefaults, fixedBytes, () => 'uuid-fixed');
    expect(out.method).toBe('2022-blake3-aes-256-gcm');
    expect(atob(out.password).length).toBe(32);
  });

  it('fills split ss paths from defaults when the template has none', () => {
    const template: User = { id: 'plain', enabled: true, has_password: true };
    const out = cloneUserFields(template, srvDefaults, fixedBytes, () => 'uuid-fixed');
    expect(out.wsPathTcp).toBe('/dtcp');
    expect(out.wsPathUdp).toBe('/dudp');
    expect(out.wsPathSs).toBe('');
  });

  it('prefers a combined ss path when the server default is combined', () => {
    const combined: ServerDefaults = { ...srvDefaults, ws_path_ss: '/dss' };
    const template: User = { id: 'plain', enabled: true, has_password: true };
    const out = cloneUserFields(template, combined, fixedBytes, () => 'uuid-fixed');
    expect(out.wsPathSs).toBe('/dss');
    expect(out.wsPathTcp).toBe('');
    expect(out.wsPathUdp).toBe('');
  });

  it("never overrides the template's own explicit values", () => {
    const template: User = {
      id: 'explicit', enabled: true, method: 'aes-256-gcm',
      ws_path_tcp: '/own-tcp', has_password: true,
    };
    const out = cloneUserFields(template, srvDefaults, fixedBytes, () => 'uuid-fixed');
    expect(out.method).toBe('aes-256-gcm');
    expect(out.wsPathTcp).toBe('/own-tcp');
    expect(out.wsPathUdp).toBe('/dudp'); // unset on the template -> default
  });

  it('fills vless paths only for a template that has a vless identity', () => {
    const vlessOnly: User = { id: 'v', enabled: true, has_vless_id: true };
    const out = cloneUserFields(vlessOnly, srvDefaults, fixedBytes, () => 'uuid-fixed');
    expect(out.wsPathVless).toBe('/dvless');
    expect(out.xhttpPathVless).toBe('/dxvless');
    expect(out.wsPathTcp).toBe(''); // no ss identity -> no ss paths
    expect(out.password).toBe('');
    expect(out.vlessId).toBe('uuid-fixed');
  });

  it('without defaults behaves exactly as before (no password for a default method)', () => {
    const template: User = { id: 'plain', enabled: true, has_password: true };
    const out = cloneUserFields(template, null, fixedBytes, () => 'uuid-fixed');
    expect(out.method).toBe('');
    expect(out.password).toBe('');
    expect(out.wsPathTcp).toBe('');
  });
});
```

- [ ] **Step 3: Прогнать тесты — убедиться, что падают**

Run (из `bins/outline-ui/frontend`):
```bash
pnpm exec vitest run src/lib/userForm.test.ts
```
Expected: FAIL — новые тесты падают: `cloneUserFields` игнорирует второй
аргумент, поэтому `out.method` пустой, `out.password` пустой, пути пустые.

- [ ] **Step 4: Реализовать подстановку дефолтов**

В `bins/outline-ui/frontend/src/lib/userForm.ts` заменить существующую функцию
`cloneUserFields` целиком на:

```ts
// Build create-form fields from an existing user as a template ("clone a
// similar account"): the carrier (method, fwmark, all ws/xhttp paths, enabled)
// is copied verbatim via fieldsFromUser; `id` and `aliases` are blanked (id
// must be unique; alias names are globally unique server-side, so they cannot
// be duplicated); fresh secrets are generated only for the identities the
// template actually has.
//
// `defaults` are the server's effective fallbacks (GET /control/defaults). A
// user that carries no method/paths of its own runs on them, so a clone that
// ignored them would show a blank form — and, with no method, could not
// generate a password at all. They are applied only where the template is
// silent, and only for the identities it has: filling ss paths for a
// VLESS-only user would attach it to routes it never used.
export function cloneUserFields(
  template: User,
  defaults: ServerDefaults | null = null,
  rand: RandomBytes = webCryptoBytes,
  uuid: () => string = () => crypto.randomUUID(),
): UserFormFields {
  const base = fieldsFromUser(template);
  const out: UserFormFields = { ...base, id: '', aliases: '' };

  if (defaults) {
    if (template.has_password) {
      out.method = base.method || defaults.method;
      // The server runs ss either combined (one path carrying tcp+udp) or
      // split; mirror whichever shape the default describes instead of
      // filling both and inventing a routing shape the server never had.
      if (defaults.ws_path_ss) {
        out.wsPathSs = base.wsPathSs || defaults.ws_path_ss;
      } else {
        out.wsPathTcp = base.wsPathTcp || defaults.ws_path_tcp;
        out.wsPathUdp = base.wsPathUdp || defaults.ws_path_udp;
      }
      if (defaults.xhttp_path_ss) {
        out.xhttpPathSs = base.xhttpPathSs || defaults.xhttp_path_ss;
      } else {
        out.xhttpPathTcp = base.xhttpPathTcp || defaults.xhttp_path_tcp || '';
        out.xhttpPathUdp = base.xhttpPathUdp || defaults.xhttp_path_udp || '';
      }
    }
    if (template.has_vless_id) {
      out.wsPathVless = base.wsPathVless || defaults.ws_path_vless || '';
      out.xhttpPathVless = base.xhttpPathVless || defaults.xhttp_path_vless || '';
    }
  }

  out.password = template.has_password ? (generatePassword(out.method, rand) ?? '') : '';
  out.vlessId = template.has_vless_id ? generateVlessId(uuid) : '';
  return out;
}
```

и добавить `ServerDefaults` в импорт типов в начале `userForm.ts` — итоговая
строка импорта типов:

```ts
import type { NewUser, PatchUser, ServerDefaults, User } from './types';
```

- [ ] **Step 5: Прогнать тесты — убедиться, что проходят**

Run (из `bins/outline-ui/frontend`):
```bash
pnpm exec vitest run src/lib/userForm.test.ts
```
Expected: PASS — новые тесты зелёные И прежние тесты `cloneUserFields`
(из предыдущей фичи) тоже зелёные: без `defaults` поведение не изменилось.

- [ ] **Step 6: Прогнать полный фронт-гейт**

Run (из `bins/outline-ui/frontend`):
```bash
pnpm exec svelte-check --tsconfig ./tsconfig.app.json && pnpm exec vitest run && pnpm build
```
Expected: `svelte-check` 0 ошибок, все тесты зелёные, сборка успешна.
(`Users.svelte` пока зовёт `cloneUserFields(user)` с одним аргументом — это
валидно, второй параметр опциональный.)

- [ ] **Step 7: Commit** (по подтверждению владельца)

```bash
git add bins/outline-ui/frontend/src/lib/types.ts bins/outline-ui/frontend/src/lib/api.ts bins/outline-ui/frontend/src/lib/userForm.ts bins/outline-ui/frontend/src/lib/userForm.test.ts
git commit -m "feat(ui): fill clone form from the instance's server defaults"
```

---

### Task 5: frontend — `Users.svelte` грузит дефолты при клике «Clone»

**Files:**
- Modify: `bins/outline-ui/frontend/src/features/ss/Users.svelte`

**Interfaces:**
- Consumes (Task 4): `getDefaults(instance)`, `cloneUserFields(user, defaults)`.

- [ ] **Step 1: Обновить импорты**

В `bins/outline-ui/frontend/src/features/ss/Users.svelte` в существующий импорт
из `../../lib/api` добавить `getDefaults` — то есть строку

```ts
  import { listUsers, createUser, updateUser, deleteUser, blockUser, unblockUser } from '../../lib/api';
```

заменить на:

```ts
  import { listUsers, createUser, updateUser, deleteUser, blockUser, unblockUser, getDefaults } from '../../lib/api';
```

- [ ] **Step 2: Сделать `openCloneDrawer` асинхронным с загрузкой дефолтов**

Заменить функцию `openCloneDrawer` целиком на:

```ts
  async function openCloneDrawer(user: User) {
    // Snapshot the template into seed fields (fresh secrets, blank id/aliases);
    // create-mode drawer (editingUser stays null) prefilled from it. The
    // server's defaults fill whatever the template leaves unset — without them
    // a user running on defaults would clone into a blank form with no
    // password (the UI cannot pick a cipher it does not know).
    editingUser = null;
    seedNeedsPassword = Boolean(user.has_password);
    let defaults: ServerDefaults | null = null;
    try {
      defaults = await getDefaults(instance);
    } catch (e) {
      // Non-fatal: clone still works, it just cannot prefill the effective
      // method/paths. Better a degraded form than a dead button.
      toast(`Could not load server defaults: ${errorMessage(e)}`, 'error');
    }
    seedFields = cloneUserFields(user, defaults);
    drawerOpen = true;
  }
```

и добавить тип в импорт типов — строку

```ts
  import type { User, NewUser, PatchUser } from '../../lib/types';
```

заменить на:

```ts
  import type { User, NewUser, PatchUser, ServerDefaults } from '../../lib/types';
```

- [ ] **Step 3: Прогнать фронт-гейт**

Run (из `bins/outline-ui/frontend`):
```bash
pnpm exec svelte-check --tsconfig ./tsconfig.app.json && pnpm exec vitest run && pnpm build
```
Expected: `svelte-check` 0 ошибок (в т.ч. никаких претензий к `await` в
обработчике `onclick` — Svelte это допускает), тесты зелёные, сборка успешна.

- [ ] **Step 4: Commit** (по подтверждению владельца)

```bash
git add bins/outline-ui/frontend/src/features/ss/Users.svelte
git commit -m "feat(ui): load instance defaults when cloning a user"
```

---

### Task 6: frontend — фикс темы: значок луна↔солнце и `theme-color`

Независимый от клона фикс. `theme.svelte.ts` получает вычисление эффективной
темы + обновление `<meta name="theme-color">`; `Topbar.svelte` рисует значок
по эффективной теме и реагирует на смену системной.

**Files:**
- Modify: `bins/outline-ui/frontend/src/lib/theme.svelte.ts`
- Modify: `bins/outline-ui/frontend/src/components/layout/Topbar.svelte`
- Test: `bins/outline-ui/frontend/src/lib/theme.test.ts` (создать)

**Interfaces:**
- Produces:
  - `export function effectiveMode(): 'dark' | 'light'` в `lib/theme.svelte.ts`
    (явный `theme.mode`, иначе системная `prefers-color-scheme`)
  - `applyTheme()` дополнительно синхронизирует `<meta name="theme-color">`
  - `THEME_COLORS: Record<'dark' | 'light', string>` — цвета фона под тему
    (значения из `app.css`: dark `#020617`, light `#f4f6fb`)

- [ ] **Step 1: Написать падающий тест**

Создать `bins/outline-ui/frontend/src/lib/theme.test.ts`:

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { theme, applyTheme, effectiveMode, THEME_COLORS } from './theme.svelte';

// jsdom gives us a real document; matchMedia is not implemented there, so the
// system-preference branch needs an explicit stub per test.
function stubPrefersDark(dark: boolean) {
  window.matchMedia = ((query: string) => ({
    matches: dark && query.includes('dark'),
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  })) as unknown as typeof window.matchMedia;
}

beforeEach(() => {
  theme.mode = null;
  document.documentElement.removeAttribute('data-theme');
  document.querySelector('meta[name="theme-color"]')?.remove();
});

describe('effectiveMode', () => {
  it('returns the explicit mode when one is set', () => {
    stubPrefersDark(true);
    theme.mode = 'light';
    expect(effectiveMode()).toBe('light');
  });
  it('falls back to the system preference when no explicit mode is set', () => {
    stubPrefersDark(true);
    expect(effectiveMode()).toBe('dark');
    stubPrefersDark(false);
    expect(effectiveMode()).toBe('light');
  });
});

describe('applyTheme', () => {
  it('creates the theme-color meta tag and matches the effective theme', () => {
    stubPrefersDark(false);
    theme.mode = 'dark';
    applyTheme();
    const meta = document.querySelector('meta[name="theme-color"]');
    expect(meta).not.toBeNull();
    expect(meta?.getAttribute('content')).toBe(THEME_COLORS.dark);
  });

  it('updates the existing meta tag when the theme flips', () => {
    stubPrefersDark(false);
    theme.mode = 'dark';
    applyTheme();
    theme.mode = 'light';
    applyTheme();
    const metas = document.querySelectorAll('meta[name="theme-color"]');
    expect(metas.length).toBe(1); // updated in place, not duplicated
    expect(metas[0].getAttribute('content')).toBe(THEME_COLORS.light);
  });

  it('follows the system preference for the browser chrome when no mode is set', () => {
    stubPrefersDark(true);
    theme.mode = null;
    applyTheme();
    expect(document.querySelector('meta[name="theme-color"]')?.getAttribute('content'))
      .toBe(THEME_COLORS.dark);
  });
});
```

- [ ] **Step 2: Прогнать тест — убедиться, что падает**

Run (из `bins/outline-ui/frontend`):
```bash
pnpm exec vitest run src/lib/theme.test.ts
```
Expected: FAIL — `No "effectiveMode" export` / `No "THEME_COLORS" export`.

Если vitest ругается, что `document` не определён (окружение node вместо jsdom),
добавить в начало файла теста строку `// @vitest-environment jsdom` первой
строкой — проверить, как это делают соседние тесты
(`grep -rn "vitest-environment" bins/outline-ui/frontend/src`), и следовать
тому же способу; если jsdom не установлен, добавить его:
`pnpm add -D jsdom` (из `bins/outline-ui/frontend`).

- [ ] **Step 3: Реализовать в `theme.svelte.ts`**

Заменить содержимое `bins/outline-ui/frontend/src/lib/theme.svelte.ts` на:

```ts
type Mode = 'dark' | 'light';

const stored = (typeof localStorage !== 'undefined' ? localStorage.getItem('theme') : null) as Mode | null;

// `mode: null` means "no explicit choice yet" — `applyTheme()` then removes
// `data-theme` entirely so app.css's `@media (prefers-color-scheme)` block
// governs first paint. An explicit toggle always stamps a concrete mode and
// persists it, which outranks the OS preference from then on (see app.css).
export const theme = $state<{ mode: Mode | null }>({ mode: stored });

// Page background per theme, kept in sync with `--bg` in app.css. Used for the
// browser's own chrome (`<meta name="theme-color">`) so the address bar on
// mobile/PWA matches the page instead of staying on the opposite theme.
export const THEME_COLORS: Record<Mode, string> = {
  dark: '#020617',
  light: '#f4f6fb',
};

// The theme actually being rendered: the explicit choice when there is one,
// otherwise whatever the OS asks for. Both the icon and the browser chrome key
// off this, so a user on "system" still sees the correct sun/moon.
export function effectiveMode(): Mode {
  if (theme.mode) return theme.mode;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyThemeColor(mode: Mode) {
  let meta = document.querySelector('meta[name="theme-color"]');
  if (!meta) {
    meta = document.createElement('meta');
    meta.setAttribute('name', 'theme-color');
    document.head.appendChild(meta);
  }
  meta.setAttribute('content', THEME_COLORS[mode]);
}

export function applyTheme() {
  const root = document.documentElement;
  if (theme.mode) root.dataset.theme = theme.mode;
  else root.removeAttribute('data-theme'); // let @media (prefers-color-scheme) decide
  applyThemeColor(effectiveMode());
}

export function toggleTheme() {
  const effective: Mode = effectiveMode();
  theme.mode = effective === 'dark' ? 'light' : 'dark';
  localStorage.setItem('theme', theme.mode);
  applyTheme();
}
```

- [ ] **Step 4: Прогнать тест — убедиться, что проходит**

Run (из `bins/outline-ui/frontend`):
```bash
pnpm exec vitest run src/lib/theme.test.ts
```
Expected: PASS — все тесты `effectiveMode` и `applyTheme` зелёные.

- [ ] **Step 5: Значок в `Topbar.svelte`**

В `bins/outline-ui/frontend/src/components/layout/Topbar.svelte` заменить
строку импорта

```ts
  import { toggleTheme } from '../../lib/theme.svelte';
```

на:

```ts
  import { toggleTheme, theme, effectiveMode } from '../../lib/theme.svelte';

  // Recomputed whenever the explicit mode changes; `systemDark` additionally
  // tracks the OS preference so the icon stays correct for a user who never
  // toggled (theme.mode === null) and flips their system theme.
  let systemDark = $state(
    typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches,
  );
  $effect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = (e: MediaQueryListEvent) => (systemDark = e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  });
  const isDark = $derived(theme.mode ? theme.mode === 'dark' : systemDark);
```

И заменить кнопку темы

```svelte
  <button class="iconbtn" title="Toggle theme" aria-label="Toggle theme" onclick={toggleTheme}>
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>
  </button>
```

на:

```svelte
  <button
    class="iconbtn"
    title={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
    aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
    onclick={toggleTheme}
  >
    {#if isDark}
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
    {:else}
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>
    {/if}
  </button>
```

Замечание для реализующего: `effectiveMode` импортирован ради консистентности
API темы, но в компоненте используется `isDark` (он реактивен на обе причины
смены). Если линтер сообщает о неиспользуемом импорте — убрать `effectiveMode`
из строки импорта, оставив `toggleTheme, theme`.

- [ ] **Step 6: Прогнать полный фронт-гейт**

Run (из `bins/outline-ui/frontend`):
```bash
pnpm exec svelte-check --tsconfig ./tsconfig.app.json && pnpm exec vitest run && pnpm build
```
Expected: `svelte-check` 0 ошибок, все тесты зелёные (включая новый
`theme.test.ts`), сборка успешна.

- [ ] **Step 7: Ручная проверка темы**

Run (из `bins/outline-ui/frontend`): `pnpm dev`, открыть `http://localhost:5173/ss`.
Проверить:
1. В светлой теме в топбаре — **луна**; клик → тема тёмная и значок становится
   **солнцем**; повторный клик возвращает светлую и луну.
2. В DevTools → Elements: `<meta name="theme-color">` присутствует в `<head>`
   и его `content` меняется между `#020617` (тёмная) и `#f4f6fb` (светлая) при
   каждом переключении; тег ровно один, не дублируется.

Expected: оба пункта выполняются.

- [ ] **Step 8: Commit** (по подтверждению владельца)

```bash
git add bins/outline-ui/frontend/src/lib/theme.svelte.ts bins/outline-ui/frontend/src/lib/theme.test.ts bins/outline-ui/frontend/src/components/layout/Topbar.svelte
git commit -m "fix(ui): reflect the active theme in the toggle icon and browser chrome"
```

---

### Task 7: Ручная сквозная проверка клона против живого инстанса

Проверка того, что три слоя стыкуются. Выполняется владельцем или агентом,
имеющим доступ к control API инстанса.

**Files:** нет правок кода — только проверка.

**Interfaces:**
- Consumes: всё из Task 1-5.

- [ ] **Step 1: Собрать и запустить ss-rust локально или использовать боевой инстанс**

Проверить эндпоинт напрямую (подставить адрес и токен инстанса):
```bash
curl -sS -H "Authorization: Bearer $CONTROL_TOKEN" http://127.0.0.1:9191/control/defaults
```
Expected: JSON вида
`{"method":"2022-blake3-aes-256-gcm","ws_path_tcp":"/tcp","ws_path_udp":"/udp",...}` —
метод строкой, незаданные пути отсутствуют. Секретов (`password`, `vless_id`) в
ответе нет.

- [ ] **Step 2: Проверить, что эндпоинт закрыт авторизацией**

```bash
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9191/control/defaults
```
Expected: `401` — без bearer-токена доступа нет.

- [ ] **Step 3: Проверить клон через UI**

Открыть ss-дашборд, выбрать инстанс, нажать **Clone** на пользователе,
у которого в колонке метода — серверный дефолт (метод не задан явно).
Expected:
1. Поле **Method** заполнено эффективным серверным методом (не «default»).
2. Поле **Password** содержит видимый сгенерированный секрет.
3. Кнопка «глаз» скрывает и показывает пароль.
4. Поля путей заполнены эффективными серверными путями.
5. Ввод нового `id` и **Create** создаёт пользователя (тост «User created»),
   новая строка появляется в таблице.

- [ ] **Step 4: Проверить, что Edit не изменился**

Открыть **Edit** у любого пользователя.
Expected: поля Password/VLESS UUID пустые с плейсхолдерами «keep current…»,
пути и метод — как раньше (пустые = следовать дефолту). Дефолты в форму
редактирования НЕ подставляются.

---

## Итоговая проверка перед завершением

Из корня репо:
```bash
cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings && cargo test -p outline-ss-rust --features control && cargo test -p outline-ui && cargo check -p outline-ss-rust --no-default-features
```
Из `bins/outline-ui/frontend`:
```bash
pnpm exec svelte-check --tsconfig ./tsconfig.app.json && pnpm exec vitest run && pnpm build
```
Expected: всё зелёное, clippy без warnings, svelte-check 0 ошибок.

## Соответствие спеке (self-review)

- §1 (ss-rust эндпоинт `/control/defaults`) → Task 1 (`ServerDefaults` +
  `defaults()`), Task 2 (handler + маршрут).
- §2 (outline-ui проксирование) → Task 3.
- §3 (frontend: тип, api, подстановка в клоне) → Task 4 (логика + тесты),
  Task 5 (`Users.svelte` грузит дефолты, мягкая деградация при ошибке).
- §4 (значок темы + `theme-color`) → Task 6.
- §5 («глаз» — не баг, отдельного фикса не требует) → задач нет намеренно;
  проверяется в Task 7 Step 3 пункт 3.
- Деплой (7 ss-узлов + `outline-ui:1.0.8`) → вне плана, отдельным этапом
  после ревью, как указано в Global Constraints.
- Вне scope (пароль в Edit, генерация ss://-ссылки, дефолты в create/edit) →
  задач нет, как и требовалось; Task 7 Step 4 проверяет, что Edit не задет.
