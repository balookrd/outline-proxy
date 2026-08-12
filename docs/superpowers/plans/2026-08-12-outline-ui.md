# План реализации `outline-ui`

> **Для агентов-исполнителей:** ОБЯЗАТЕЛЬНЫЙ СУБ-НАВЫК — используй
> superpowers:subagent-driven-development (рекомендуется) или
> superpowers:executing-plans, чтобы выполнять план задача за задачей. Шаги
> размечены чекбоксами (`- [ ]`) для отслеживания.

**Цель:** вынести оба web-дашборда из бинарей, везущих трафик, в новый бинарь
`outline-ui`, который отдаёт их на одном порту под `/ws` и `/ss`, — чтобы UI жил
в k3s и исчез с боевых узлов.

**Архитектура:** `bins/outline-ui` — stateless-сервис на axum. Своего data plane
у него нет: он читает собственный TOML, охраняет листенер (credentials + origin) и
проксирует к control API каждого узла, подставляя per-instance bearer-токены на
стороне сервера. Два UI монтируются как `Router::nest("/ws", …)` и
`nest("/ss", …)`; каждый HTML узнаёт свой префикс через плейсхолдер `__BASE__`,
подставляемый в момент ответа.

**Стек:** Rust 2024, axum 0.8, tokio 1.48, hyper 1.8 (клиент к control API),
tokio-rustls 0.26 (aws-lc-rs), serde/toml, clap 4.5, tracing.

## Глобальные ограничения

- **rustls только на aws-lc-rs.** Любая зависимость, тянущая rustls, идёт с
  `default-features = false` и явной фичей `aws_lc_rs`. Два провайдера в графе
  дают панику в рантайме: «exactly one of aws-lc-rs and ring».
- **Тесты живут в подкаталогах `tests/`**, никаких inline-блоков
  `#[cfg(test)] mod tests {}`. Схема: `src/auth.rs` → `src/tests/auth.rs`,
  подключение `#[cfg(test)] #[path = "tests/auth.rs"] mod tests;`. Каталог-модуль
  использует `<dir>/tests/mod.rs` и простое `#[cfg(test)] mod tests;`.
- **Комментарии в коде, сообщения коммитов и текст PR — на английском.**
  Документы владельцу в `ops/` — по-русски; доки `bins/*` идут парами EN + RU и
  обновляются вместе.
- **CI-гейт, гонять перед каждым коммитом** (точные команды, в них зашиты
  vendored-исключения):
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
    -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
    -p outline-tun -p outline-uplink -p outline-wire \
    -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  ```
- **`cargo fmt` использует корневой `rustfmt.toml` (100 колонок).**
- **Никаких секретов в логах и в git.** Токены инстансов приходят через
  `token_file`, а не литералами в закоммиченном файле.
- **Не выполнять `git commit` и `git push` без явной команды владельца.** Шаги с
  коммитами ниже — часть рецепта; перед их запуском спрашивать.

---

## Раскладка файлов

**Создаётся — `bins/outline-ui/`:**

| Файл | За что отвечает |
|---|---|
| `Cargo.toml` | пакет и зависимости (rustls на aws-lc-rs) |
| `src/main.rs` | аргументы CLI, загрузка конфига, сборка роутера, bind, остановка |
| `src/config.rs` | `UiConfig`, `InstanceConfig`, разрешение `token_file` |
| `src/auth.rs` | гейт по credentials (Basic/Bearer + `WWW-Authenticate`) |
| `src/origin.rs` | `OriginPolicy` — проверки Host/Origin/Content-Type (CSRF) |
| `src/backend.rs` | HTTP(S)-клиент к control API одного инстанса |
| `src/assets.rs` | логотип и страница-указатель |
| `src/ws/mod.rs`, `src/ws/api.rs` | маршруты и хендлеры `/ws` |
| `src/ss/mod.rs`, `src/ss/api.rs` | маршруты и хендлеры `/ss` |
| `src/tests/{config,auth,origin,backend,assets,routing}.rs` | тесты модулей верхнего уровня |
| `src/ws/tests/mod.rs`, `src/ss/tests/mod.rs` | тесты каждого дерева |

Раскладка тестов подчиняется правилу репозитория: модуль `src/foo.rs` держит
тесты в `src/tests/foo.rs` с подключением
`#[cfg(test)] #[path = "tests/foo.rs"] mod tests;`, а каталог-модуль — в
`<dir>/tests/mod.rs` с простым `#[cfg(test)] mod tests;`.

**Изменяется:**

| Файл | Что меняется |
|---|---|
| `Cargo.toml` (корневой) | добавить `bins/outline-ui` в `members` |
| `.github/workflows/ci.yml:63-67` | добавить `-p outline-ui` в список fmt |
| `bins/outline-ws-rust/*` | удалить `src/http/dashboard/`, убрать feature `dashboard`, убрать `[dashboard]` из конфига |
| `bins/outline-ss-rust/*` | удалить `src/server/dashboard/` и его подключение |
| `ops/nanopi-r5c-k3s/apps/monitoring/` | новые Deployment/Service |
| `ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml` | запись Ingress (в этом репозитории они лежат централизованно) |

---

### Задача 1: скелет пакета и конфигурация

**Файлы:**
- Создать: `bins/outline-ui/Cargo.toml`, `bins/outline-ui/src/main.rs`, `bins/outline-ui/src/config.rs`
- Создать: `bins/outline-ui/src/tests/config.rs`
- Изменить: `Cargo.toml` (корневой, `members`), `.github/workflows/ci.yml:63-67`

**Интерфейсы:**
- Отдаёт наружу: `UiConfig { listen: SocketAddr, token: String, request_timeout_secs: u64, refresh_interval_secs: u64, allowed_hosts: Vec<String>, ws: Vec<InstanceConfig>, ss: Vec<InstanceConfig> }`;
  `InstanceConfig { name: String, control_url: String, token: String }`;
  `UiConfig::load(path: &Path) -> anyhow::Result<UiConfig>`

- [ ] **Шаг 1: написать падающий тест**

Создать `bins/outline-ui/src/tests/config.rs`:

```rust
use std::io::Write;

use super::*;

/// Writes `body` to a temp file plus a sibling token file, returns both paths.
fn write_config(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("ui-token");
    std::fs::write(&secret, "s3cr3t").unwrap();
    let inst = dir.path().join("inst-token");
    std::fs::write(&inst, "inst-tok").unwrap();
    let path = dir.path().join("ui.toml");
    let body = body
        .replace("__UI_TOKEN_FILE__", secret.to_str().unwrap())
        .replace("__INST_TOKEN_FILE__", inst.to_str().unwrap());
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    (dir, path)
}

#[test]
fn loads_instances_for_both_trees_and_reads_token_files() {
    let (_dir, path) = write_config(
        r#"
[server]
listen = "0.0.0.0:9000"
token_file = "__UI_TOKEN_FILE__"

[[ws.instances]]
name = "beelink102"
control_url = "http://198.18.1.102:9191"
token_file = "__INST_TOKEN_FILE__"

[[ss.instances]]
name = "cloud1"
control_url = "https://cloud1.beerloga.su/rust-ss-exporter"
token_file = "__INST_TOKEN_FILE__"
"#,
    );

    let config = UiConfig::load(&path).expect("config loads");

    assert_eq!(config.token, "s3cr3t");
    assert_eq!(config.ws.len(), 1);
    assert_eq!(config.ws[0].name, "beelink102");
    assert_eq!(config.ws[0].token, "inst-tok");
    assert_eq!(config.ss.len(), 1);
    assert_eq!(config.ss[0].control_url, "https://cloud1.beerloga.su/rust-ss-exporter");
}

/// The listener is on 0.0.0.0 inside the pod, and reaching it grants every
/// instance token. An unauthenticated UI is a configuration error, not a
/// permissive default.
#[test]
fn missing_token_is_rejected() {
    let (_dir, path) = write_config(
        r#"
[server]
listen = "0.0.0.0:9000"

[[ws.instances]]
name = "beelink102"
control_url = "http://198.18.1.102:9191"
token_file = "__INST_TOKEN_FILE__"
"#,
    );

    let error = UiConfig::load(&path).expect_err("must refuse an unauthenticated listener");
    assert!(
        error.to_string().contains("token"),
        "error should name the missing token, got: {error}"
    );
}

/// A trailing newline is what `echo` and most secret mounts produce; carrying it
/// into the Authorization header makes every request fail with a 401 nobody can
/// explain.
#[test]
fn token_file_trailing_newline_is_trimmed() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("ui-token");
    std::fs::write(&secret, "s3cr3t\n").unwrap();
    let path = dir.path().join("ui.toml");
    std::fs::write(
        &path,
        format!(
            "[server]\nlisten = \"0.0.0.0:9000\"\ntoken_file = \"{}\"\n",
            secret.to_str().unwrap()
        ),
    )
    .unwrap();

    let config = UiConfig::load(&path).unwrap();

    assert_eq!(config.token, "s3cr3t");
}
```

- [ ] **Шаг 2: прогнать тест и убедиться, что он падает**

Команда: `cargo test -p outline-ui`
Ожидается: FAIL — пакета ещё нет (`error: package ID specification 'outline-ui'
did not match any packages`).

- [ ] **Шаг 3: создать манифест пакета**

Создать `bins/outline-ui/Cargo.toml`:

```toml
[package]
name = "outline-ui"
version = "0.1.0"
edition = "2024"

[dependencies]
anyhow = "1.0"
axum = { version = "0.8", features = ["http2"] }
base64 = "0.22"
bytes = "1.10"
clap = { version = "4.5", features = ["derive", "env"] }
http = "1.3"
http-body-util = "0.1"
hyper = { version = "1.8", features = ["client", "http1"] }
hyper-util = { version = "0.1", features = ["tokio"] }
# aws-lc-rs only: a second provider in the graph panics the rustls default
# provider with "exactly one of aws-lc-rs and ring".
rustls = { version = "0.23", default-features = false, features = ["aws_lc_rs", "std"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.48", features = ["rt-multi-thread", "net", "sync", "time", "io-util", "macros", "signal"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["logging", "tls12", "aws_lc_rs"] }
toml = "0.9"
tracing = "0.1"
tracing-subscriber = { version = "0.3", default-features = false, features = ["fmt", "env-filter", "tracing-log"] }
webpki-roots = "1.0"

[dev-dependencies]
tempfile = "3"
tower = "0.5"
```

В корневой `Cargo.toml` добавить `"bins/outline-ui",` в `members`, последним
среди `bins/` (список отсортирован, `ui` идёт после `ss` и `ws`).

- [ ] **Шаг 4: написать модуль конфигурации**

Создать `bins/outline-ui/src/config.rs`:

```rust
//! Configuration for the UI service.
//!
//! Deliberately its own file rather than a slice of a data-plane config: this
//! process has no uplinks, no listeners and no users of its own. It knows only
//! where to listen, how to authenticate a browser, and which control APIs to
//! aggregate.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Default seconds between browser refreshes; mirrors the value both dashboards
/// shipped with.
const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 5;
/// Default per-request timeout when talking to an instance control API.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone)]
pub struct UiConfig {
    pub listen: SocketAddr,
    /// Guards the listener itself. Mandatory: see `tests/config.rs`.
    pub token: String,
    pub request_timeout_secs: u64,
    pub refresh_interval_secs: u64,
    pub allowed_hosts: Vec<String>,
    pub ws: Vec<InstanceConfig>,
    pub ss: Vec<InstanceConfig>,
}

#[derive(Debug, Clone)]
pub struct InstanceConfig {
    pub name: String,
    pub control_url: String,
    pub token: String,
}

#[derive(Deserialize)]
struct FileConfig {
    server: ServerSection,
    #[serde(default)]
    ws: TreeSection,
    #[serde(default)]
    ss: TreeSection,
}

#[derive(Deserialize)]
struct ServerSection {
    listen: SocketAddr,
    token: Option<String>,
    token_file: Option<PathBuf>,
    request_timeout_secs: Option<u64>,
    refresh_interval_secs: Option<u64>,
    #[serde(default)]
    allowed_hosts: Vec<String>,
}

#[derive(Deserialize, Default)]
struct TreeSection {
    #[serde(default)]
    instances: Vec<InstanceSection>,
}

#[derive(Deserialize)]
struct InstanceSection {
    name: String,
    control_url: String,
    token: Option<String>,
    token_file: Option<PathBuf>,
}

/// Reads a secret from either the literal or the file form. Trailing whitespace
/// is stripped: secret mounts and `echo` both add a newline, and carrying it
/// into an `Authorization` header turns every request into an unexplainable 401.
fn resolve_secret(
    literal: Option<String>,
    file: Option<PathBuf>,
    what: &str,
) -> Result<Option<String>> {
    match (literal, file) {
        (Some(_), Some(_)) => bail!("{what}: set either token or token_file, not both"),
        (Some(value), None) => Ok(Some(value)),
        (None, Some(path)) => {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("{what}: failed to read {}", path.display()))?;
            Ok(Some(raw.trim_end().to_string()))
        },
        (None, None) => Ok(None),
    }
}

impl UiConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let file: FileConfig =
            toml::from_str(&raw).with_context(|| format!("invalid config {}", path.display()))?;

        let token = resolve_secret(file.server.token, file.server.token_file, "[server]")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "[server]: token or token_file is required — this listener grants every \
                     configured instance token to whoever reaches it"
                )
            })?;

        let convert = |tree: TreeSection, label: &str| -> Result<Vec<InstanceConfig>> {
            tree.instances
                .into_iter()
                .map(|i| {
                    let what = format!("[[{label}.instances]] {}", i.name);
                    let token = resolve_secret(i.token, i.token_file, &what)?
                        .ok_or_else(|| anyhow::anyhow!("{what}: token or token_file is required"))?;
                    Ok(InstanceConfig { name: i.name, control_url: i.control_url, token })
                })
                .collect()
        };

        Ok(Self {
            listen: file.server.listen,
            token,
            request_timeout_secs: file
                .server
                .request_timeout_secs
                .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS),
            refresh_interval_secs: file
                .server
                .refresh_interval_secs
                .unwrap_or(DEFAULT_REFRESH_INTERVAL_SECS),
            allowed_hosts: file.server.allowed_hosts,
            ws: convert(file.ws, "ws")?,
            ss: convert(file.ss, "ss")?,
        })
    }
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
```

Создать временный `bins/outline-ui/src/main.rs`, чтобы крейт собирался:

```rust
//! Aggregating web UI for the outline fleet. Serves both dashboards and nothing
//! else: no uplinks, no listeners, no traffic.

mod config;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "outline-ui", about = "Web UI for the outline fleet")]
struct Args {
    /// Path to the UI configuration file.
    #[arg(long, env = "OUTLINE_UI_CONFIG", default_value = "/etc/outline-ui/config.toml")]
    config: PathBuf,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let config = config::UiConfig::load(&args.config)?;
    tracing::info!(
        listen = %config.listen,
        ws_instances = config.ws.len(),
        ss_instances = config.ss.len(),
        "configuration loaded"
    );
    Ok(())
}
```

- [ ] **Шаг 5: прогнать тест и убедиться, что он проходит**

Команда: `cargo test -p outline-ui`
Ожидается: PASS, 3 теста. Флаг `--lib` здесь не подходит: это binary-крейт, и с
ним тесты не найдутся.

- [ ] **Шаг 6: добавить пакет в список fmt в CI**

В `.github/workflows/ci.yml`, строка 64, расширить явный список пакетов:

```yaml
          -p outline-ss-rust -p outline-ws-rust -p outline-ui
```

- [ ] **Шаг 7: прогнать гейт**

```bash
cargo fmt --check -p outline-ui
cargo clippy -p outline-ui --all-targets --no-deps -- -D warnings
cargo test -p outline-ui
```
Ожидается: чисто, 3 теста проходят.

- [ ] **Шаг 8: коммит** (сначала спросить владельца — см. «Глобальные ограничения»)

```bash
git add bins/outline-ui Cargo.toml .github/workflows/ci.yml
git commit -m "feat(ui): add outline-ui package skeleton and configuration"
```

---

### Задача 2: гейт по credentials

**Файлы:**
- Создать: `bins/outline-ui/src/auth.rs`, `bins/outline-ui/src/tests/auth.rs`
- Ориентир: `bins/outline-ws-rust/src/http/dashboard/auth.rs` и его тесты

**Интерфейсы:**
- Использует: `UiConfig::token` (задача 1)
- Отдаёт: `require_auth(State<AuthState>, Request, Next) -> Response` (middleware axum);
  `AuthState { token: Arc<str> }`

- [ ] **Шаг 1: написать падающий тест**

Создать `bins/outline-ui/src/tests/auth.rs`:

```rust
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use axum::{Router, middleware};
use base64::Engine as _;
use tower::ServiceExt as _;

use super::*;

fn app(token: &str) -> Router {
    let state = AuthState { token: std::sync::Arc::from(token) };
    Router::new()
        .route("/probe", get(|| async { "ok" }))
        .layer(middleware::from_fn_with_state(state, require_auth))
}

async fn status_for(request: Request<Body>) -> StatusCode {
    app("s3cr3t").oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn no_credentials_is_401_with_a_browser_prompt() {
    let response =
        app("s3cr3t").oneshot(Request::get("/probe").body(Body::empty()).unwrap()).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // Without this a browser shows a bare 401 page and the operator has no way
    // to enter the token at all.
    assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
}

#[tokio::test]
async fn correct_bearer_passes() {
    let request = Request::get("/probe")
        .header(header::AUTHORIZATION, "Bearer s3cr3t")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status_for(request).await, StatusCode::OK);
}

#[tokio::test]
async fn correct_basic_password_passes() {
    let encoded = base64::engine::general_purpose::STANDARD.encode("admin:s3cr3t");
    let request = Request::get("/probe")
        .header(header::AUTHORIZATION, format!("Basic {encoded}"))
        .body(Body::empty())
        .unwrap();

    assert_eq!(status_for(request).await, StatusCode::OK);
}

#[tokio::test]
async fn wrong_token_is_rejected() {
    let request = Request::get("/probe")
        .header(header::AUTHORIZATION, "Bearer wrong")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status_for(request).await, StatusCode::UNAUTHORIZED);
}

/// A prefix of the real token must not pass; comparison is over the whole value.
#[tokio::test]
async fn token_prefix_is_rejected() {
    let request = Request::get("/probe")
        .header(header::AUTHORIZATION, "Bearer s3cr")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status_for(request).await, StatusCode::UNAUTHORIZED);
}
```

- [ ] **Шаг 2: прогнать тест и убедиться, что он падает**

Команда: `cargo test -p outline-ui auth`
Ожидается: FAIL — `cannot find module auth` / не разрешается `AuthState`.

- [ ] **Шаг 3: написать реализацию**

Создать `bins/outline-ui/src/auth.rs`:

```rust
//! Credential gate for the whole listener.
//!
//! Reaching this service is equivalent to holding every instance token it is
//! configured with — the tokens are injected server-side on every proxied
//! request. So the gate is mandatory (see `config.rs`) and runs before routing,
//! not inside individual handlers: a route added later must not be able to sit
//! outside the check by simply not asking for it.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;

#[derive(Clone)]
pub struct AuthState {
    pub token: Arc<str>,
}

/// Constant-time comparison. A short-circuiting `==` leaks the length of the
/// matching prefix through timing, which is enough to recover a token byte by
/// byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Accepts `Bearer <token>` for scripted clients and `Basic <base64>` for
/// browsers, where any username is allowed and the password carries the token.
fn presented_token(header_value: &str) -> Option<String> {
    if let Some(rest) = header_value.strip_prefix("Bearer ") {
        return Some(rest.trim().to_string());
    }
    let encoded = header_value.strip_prefix("Basic ")?.trim();
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (_user, password) = decoded.split_once(':')?;
    Some(password.to_string())
}

pub async fn require_auth(State(state): State<AuthState>, request: Request, next: Next) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(presented_token);

    match presented {
        Some(token) if constant_time_eq(token.as_bytes(), state.token.as_bytes()) => {
            next.run(request).await
        },
        _ => unauthorized(),
    }
}

/// `WWW-Authenticate` makes a browser show a login prompt instead of a bare 401
/// the operator cannot answer.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"outline-ui\"")],
        "unauthorized\n",
    )
        .into_response()
}

#[cfg(test)]
#[path = "tests/auth.rs"]
mod tests;
```

Подключить модуль в `main.rs`: добавить `mod auth;` рядом с `mod config;`.

- [ ] **Шаг 4: прогнать тест и убедиться, что он проходит**

Команда: `cargo test -p outline-ui auth`
Ожидается: PASS, 5 тестов.

- [ ] **Шаг 5: прогнать гейт и закоммитить**

```bash
cargo fmt --check -p outline-ui
cargo clippy -p outline-ui --all-targets --no-deps -- -D warnings
cargo test -p outline-ui
git add bins/outline-ui
git commit -m "feat(ui): add the credential gate"
```

---

### Задача 3: origin policy (гейт против CSRF)

Гейт по credentials эту проверку не заменяет. Браузер сам прикладывает
закэшированные Basic-креды к межсайтовому запросу, поэтому чужая страница поедет
на авторизации оператора; origin-гейт отвечает на вопрос, *откуда* пришёл
запрос. Обе проверки есть в дашбордах сегодня, и при переносе их терять нельзя.

**Файлы:**
- Создать: `bins/outline-ui/src/origin.rs`, `bins/outline-ui/src/tests/origin.rs`
- Ориентир: `bins/outline-ws-rust/src/http/dashboard/guard.rs` (177 строк),
  `bins/outline-ss-rust/src/server/dashboard/guard.rs` (204 строки) и их тесты

**Интерфейсы:**
- Использует: `UiConfig::{listen, allowed_hosts}` (задача 1)
- Отдаёт: `OriginPolicy::new(listen: SocketAddr, allowed_hosts: &[String]) -> OriginPolicy`;
  `enforce_origin(State<OriginPolicy>, Request, Next) -> Response`

- [ ] **Шаг 1: написать падающий тест**

Создать `bins/outline-ui/src/tests/origin.rs`:

```rust
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::{get, post};
use axum::{Router, middleware};
use tower::ServiceExt as _;

use super::*;

fn app(allowed: &[&str]) -> Router {
    let policy = OriginPolicy::new(
        "127.0.0.1:9000".parse().unwrap(),
        &allowed.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    );
    Router::new()
        .route("/probe", get(|| async { "ok" }))
        .route("/mutate", post(|| async { "ok" }))
        .layer(middleware::from_fn_with_state(policy, enforce_origin))
}

async fn status(app: Router, request: Request<Body>) -> StatusCode {
    app.oneshot(request).await.unwrap().status()
}

/// curl sends no Origin at all. Refusing that would break every scripted client
/// while stopping no browser attack, because a browser always sends one.
#[tokio::test]
async fn request_without_origin_is_allowed() {
    let request =
        Request::get("/probe").header(header::HOST, "127.0.0.1:9000").body(Body::empty()).unwrap();

    assert_eq!(status(app(&[]), request).await, StatusCode::OK);
}

#[tokio::test]
async fn foreign_origin_on_a_mutation_is_refused() {
    let request = Request::post("/mutate")
        .header(header::HOST, "127.0.0.1:9000")
        .header(header::ORIGIN, "https://evil.example")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status(app(&[]), request).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn matching_origin_on_a_mutation_is_allowed() {
    let request = Request::post("/mutate")
        .header(header::HOST, "127.0.0.1:9000")
        .header(header::ORIGIN, "http://127.0.0.1:9000")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status(app(&[]), request).await, StatusCode::OK);
}

/// Behind an ingress the browser's Host is the public name, not the pod's
/// listen address, so that name has to be configurable or the UI 403s itself.
#[tokio::test]
async fn configured_allowed_host_is_accepted() {
    let request = Request::post("/mutate")
        .header(header::HOST, "ui.k3s.beerloga.su")
        .header(header::ORIGIN, "https://ui.k3s.beerloga.su")
        .body(Body::empty())
        .unwrap();

    assert_eq!(status(app(&["ui.k3s.beerloga.su"]), request).await, StatusCode::OK);
}

#[tokio::test]
async fn unknown_host_is_refused() {
    let request =
        Request::get("/probe").header(header::HOST, "attacker.example").body(Body::empty()).unwrap();

    assert_eq!(status(app(&[]), request).await, StatusCode::FORBIDDEN);
}
```

- [ ] **Шаг 2: прогнать тест и убедиться, что он падает**

Команда: `cargo test -p outline-ui origin`
Ожидается: FAIL — `cannot find module origin`.

- [ ] **Шаг 3: перенести политику**

Прочитать `bins/outline-ss-rust/src/server/dashboard/guard.rs` и перенести
`OriginPolicy` в `bins/outline-ui/src/origin.rs` с двумя изменениями:

1. Сигнатура middleware для axum становится
   `pub async fn enforce_origin(State(policy): State<OriginPolicy>, request: Request, next: Next) -> Response`.
2. `OriginPolicy::new` принимает `&[String]` (тип из задачи 1).

Семантику сохранить точно: отсутствующий `Origin` разрешён; присутствующий
должен совпадать с authority листенера или записью из `allowed_hosts`; `Host`
тоже должен быть authority листенера или разрешённым хостом; несовпадение —
`403`.

В конце файла:

```rust
#[cfg(test)]
#[path = "tests/origin.rs"]
mod tests;
```

Подключить в `main.rs`: `mod origin;`.

- [ ] **Шаг 4: прогнать тест и убедиться, что он проходит**

Команда: `cargo test -p outline-ui origin`
Ожидается: PASS, 5 тестов.

- [ ] **Шаг 5: прогнать гейт и закоммитить**

```bash
cargo fmt --check -p outline-ui
cargo clippy -p outline-ui --all-targets --no-deps -- -D warnings
cargo test -p outline-ui
git add bins/outline-ui
git commit -m "feat(ui): port the origin policy"
```

---

### Задача 4: клиент к control API

**Файлы:**
- Создать: `bins/outline-ui/src/backend.rs`, `bins/outline-ui/src/tests/backend.rs`
- Ориентир: `bins/outline-ws-rust/src/http/dashboard/backend_client.rs` (152 строки),
  `bins/outline-ss-rust/src/server/dashboard/{proxy.rs,tls.rs}`

**Интерфейсы:**
- Использует: `InstanceConfig` (задача 1)
- Отдаёт:
  `pub struct Backend { timeout: Duration, tls: TlsConnector }`;
  `Backend::new(timeout_secs: u64) -> Backend`;
  `Backend::request(&self, instance: &InstanceConfig, method: Method, path: &str, body: Option<Bytes>) -> Result<BackendResponse>`;
  `pub struct BackendResponse { pub status: StatusCode, pub body: Bytes }`

- [ ] **Шаг 1: написать падающий тест**

Создать `bins/outline-ui/src/tests/backend.rs`:

```rust
use std::net::SocketAddr;

use axum::Router;
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::get;
use tokio::net::TcpListener;

use super::*;
use crate::config::InstanceConfig;

/// Spins a throwaway control API that echoes back what it received, so the test
/// asserts on the wire shape rather than on a mock's expectations.
async fn spawn_echo() -> SocketAddr {
    let app = Router::new().route(
        "/control/topology",
        get(|headers: HeaderMap| async move {
            let auth = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            (StatusCode::OK, format!("{{\"auth\":\"{auth}\"}}"))
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn instance(addr: SocketAddr) -> InstanceConfig {
    InstanceConfig {
        name: "probe".to_string(),
        control_url: format!("http://{addr}"),
        token: "inst-tok".to_string(),
    }
}

#[tokio::test]
async fn injects_the_instance_bearer_token() {
    let addr = spawn_echo().await;
    let backend = Backend::new(5);

    let response = backend
        .request(&instance(addr), http::Method::GET, "/control/topology", None)
        .await
        .expect("request succeeds");

    assert_eq!(response.status, StatusCode::OK);
    let body = String::from_utf8(response.body.to_vec()).unwrap();
    assert!(
        body.contains("Bearer inst-tok"),
        "the instance token must be injected server-side, got: {body}"
    );
}

/// An unreachable instance must surface as an error for that instance, not as a
/// panic or a hang that takes the whole page down.
#[tokio::test]
async fn unreachable_instance_errors_quickly() {
    let backend = Backend::new(1);
    let dead = InstanceConfig {
        name: "dead".to_string(),
        // Port 1 on loopback refuses immediately.
        control_url: "http://127.0.0.1:1".to_string(),
        token: "x".to_string(),
    };

    let error = backend
        .request(&dead, http::Method::GET, "/control/topology", None)
        .await
        .expect_err("must not succeed");

    assert!(
        error.to_string().contains("dead") || error.to_string().contains("connect"),
        "error should identify the failure, got: {error}"
    );
}
```

- [ ] **Шаг 2: прогнать тест и убедиться, что он падает**

Команда: `cargo test -p outline-ui backend`
Ожидается: FAIL — `cannot find module backend`.

- [ ] **Шаг 3: написать клиент**

Перенести `backend_client.rs` в `bins/outline-ui/src/backend.rs`. Поведение
сохранить: свежее TCP (+TLS) соединение на вызов с `Connection: close`,
`Authorization: Bearer <токен инстанса>` подставляется на стороне сервера, путь
приклеивается к базовому пути из `control_url`. Туда же добавить TLS-коннектор со
стороны ss (`webpki_roots`, провайдер aws-lc-rs).

`control_pool.rs` **не переносить**: агрегатор делает горстку запросов на
просмотр страницы, поэтому пул оптимизирует то, что не горячее, и добавляет
состояние сервису, который в остальном stateless.

Каждую ошибку заворачивать с именем инстанса —
`.with_context(|| format!("{}: ...", instance.name))`, — чтобы сломанный инстанс
был опознаваем в агрегированном ответе.

В конце:

```rust
#[cfg(test)]
#[path = "tests/backend.rs"]
mod tests;
```

Подключить в `main.rs`: `mod backend;`.

- [ ] **Шаг 4: прогнать тест и убедиться, что он проходит**

Команда: `cargo test -p outline-ui backend`
Ожидается: PASS, 2 теста.

- [ ] **Шаг 5: прогнать гейт и закоммитить**

```bash
cargo fmt --check -p outline-ui
cargo clippy -p outline-ui --all-targets --no-deps -- -D warnings
cargo test -p outline-ui
git add bins/outline-ui
git commit -m "feat(ui): add the control-API client"
```

---

### Задача 5: подстановка префикса и общая статика

**Файлы:**
- Создать: `bins/outline-ui/src/assets.rs`, `bins/outline-ui/src/tests/assets.rs`,
  `bins/outline-ui/src/index.html`
- Скопировать: `bins/outline-ws-rust/src/http/dashboard/outline-logo.png` → `bins/outline-ui/src/outline-logo.png`

**Интерфейсы:**
- Отдаёт: `render(template: &str, base: &str, refresh_ms: u64) -> String`;
  `html(body: String) -> Response`; `logo() -> Response`; `index() -> Response`;
  `not_found() -> Response`

- [ ] **Шаг 1: написать падающий тест**

Создать `bins/outline-ui/src/tests/assets.rs`:

```rust
use super::*;

#[test]
fn substitutes_the_base_prefix() {
    let out = render("const API_BASE = \"__BASE__\";", "/ws", 5000);

    assert_eq!(out, "const API_BASE = \"/ws\";");
}

#[test]
fn substitutes_the_refresh_interval() {
    let out = render("const MS = __DASHBOARD_REFRESH_MS__;", "/ws", 5000);

    assert_eq!(out, "const MS = 5000;");
}

/// A surviving placeholder means the browser would fetch a literal `__BASE__`
/// path and every call would 404 — worth failing loudly on.
#[test]
fn leaves_no_placeholder_behind() {
    let out = render("a __BASE__ b __DASHBOARD_REFRESH_MS__ c __BASE__", "/ss", 1000);

    assert!(!out.contains("__BASE__"), "unsubstituted base: {out}");
    assert!(!out.contains("__DASHBOARD_REFRESH_MS__"), "unsubstituted refresh: {out}");
}
```

- [ ] **Шаг 2: прогнать тест и убедиться, что он падает**

Команда: `cargo test -p outline-ui assets`
Ожидается: FAIL — `cannot find module assets`.

- [ ] **Шаг 3: написать модуль**

Создать `bins/outline-ui/src/assets.rs`:

```rust
//! Static assets and HTML templating.
//!
//! Both UIs address their APIs absolutely (`/dashboard/api/...`). Mounted under
//! `/ws` and `/ss` those URLs would miss, and the two would collide on the same
//! paths, so each page learns its own prefix through `__BASE__`, substituted
//! here at response time.
//!
//! `<base href>` would have been shorter and was rejected: it silently rewrites
//! every relative URL and anchor on the page, fixing the fetches by changing
//! things nobody audited.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

const INDEX_TEMPLATE: &str = include_str!("index.html");
const LOGO: &[u8] = include_bytes!("outline-logo.png");

pub fn render(template: &str, base: &str, refresh_ms: u64) -> String {
    template.replace("__BASE__", base).replace("__DASHBOARD_REFRESH_MS__", &refresh_ms.to_string())
}

pub fn html(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

pub fn logo() -> Response {
    ([(header::CONTENT_TYPE, "image/png")], LOGO).into_response()
}

pub fn index() -> Response {
    html(INDEX_TEMPLATE.to_string())
}

pub fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

#[cfg(test)]
#[path = "tests/assets.rs"]
mod tests;
```

Создать `bins/outline-ui/src/index.html` — простая страница без скриптов:

```html
<!doctype html>
<meta charset="utf-8">
<title>outline UI</title>
<style>
  body { font: 15px/1.5 system-ui, sans-serif; margin: 3rem auto; max-width: 32rem; }
  a { display: block; padding: .9rem 1.1rem; margin: .6rem 0; border: 1px solid #d0d7de;
      border-radius: 8px; text-decoration: none; color: inherit; }
  a:hover { background: #f6f8fa; }
  span { display: block; color: #57606a; font-size: 13px; }
</style>
<h1>outline</h1>
<a href="/ws/dashboard">Client dashboard<span>uplinks, topology, carrier loss</span></a>
<a href="/ss/dashboard">Server dashboard<span>users</span></a>
```

Скопировать логотип:

```bash
cp bins/outline-ws-rust/src/http/dashboard/outline-logo.png bins/outline-ui/src/outline-logo.png
```

Подключить в `main.rs`: `mod assets;`.

- [ ] **Шаг 4: прогнать тест и убедиться, что он проходит**

Команда: `cargo test -p outline-ui assets`
Ожидается: PASS, 3 теста.

- [ ] **Шаг 5: прогнать гейт и закоммитить**

```bash
cargo fmt --check -p outline-ui
cargo clippy -p outline-ui --all-targets --no-deps -- -D warnings
cargo test -p outline-ui
git add bins/outline-ui
git commit -m "feat(ui): add shared assets and base-prefix templating"
```

---

### Задача 6: дерево `/ws`

**Файлы:**
- Создать: `bins/outline-ui/src/ws/mod.rs`, `bins/outline-ui/src/ws/api.rs`
- Скопировать: `bins/outline-ws-rust/src/http/dashboard/{dashboard.html,uplinks.html}` → `bins/outline-ui/src/ws/`
- Скопировать и адаптировать: `bins/outline-ws-rust/src/http/dashboard/tests/{api.rs,backend_client.rs}` → `bins/outline-ui/src/ws/tests/`

**Интерфейсы:**
- Использует: `Backend` (задача 4), `render`/`html`/`logo` (задача 5), `InstanceConfig` (задача 1)
- Отдаёт: `ws::router(state: WsState) -> Router`;
  `WsState { backend: Arc<Backend>, instances: Arc<[InstanceConfig]>, refresh_ms: u64 }`;
  `ws::BASE: &str = "/ws"`

- [ ] **Шаг 1: перевести HTML на префикс**

В `bins/outline-ui/src/ws/dashboard.html` и `uplinks.html` добавить строку в
начало первого `<script>`:

```js
const API_BASE = "__BASE__";
```

Затем перевести на неё все абсолютные URL. Их 12 на два файла, полный список:

| Сейчас | Становится |
|---|---|
| `fetch("/dashboard/api/instances", …)` | ``fetch(`${API_BASE}/dashboard/api/instances`, …)`` |
| ``fetch(`/dashboard/api/topology?instance=…`)`` | ``fetch(`${API_BASE}/dashboard/api/topology?instance=…`)`` |
| `fetch("/dashboard/api/activate", …)` | ``fetch(`${API_BASE}/dashboard/api/activate`, …)`` |
| `fetch("/dashboard/api/set_enabled", …)` | ``fetch(`${API_BASE}/dashboard/api/set_enabled`, …)`` |
| `fetch("/dashboard/api/reselect", …)` | ``fetch(`${API_BASE}/dashboard/api/reselect`, …)`` |
| `fetch("/dashboard/api/uplinks", …)` | ``fetch(`${API_BASE}/dashboard/api/uplinks`, …)`` |
| `fetch("/dashboard/api/apply", …)` | ``fetch(`${API_BASE}/dashboard/api/apply`, …)`` |
| `href="/dashboard/uplinks"` | `href="__BASE__/dashboard/uplinks"` |
| `href="/dashboard"` | `href="__BASE__/dashboard"` |
| `src="/dashboard/outline-logo.png"` | `src="__BASE__/dashboard/outline-logo.png"` |

Проверить, что ничего не пропущено:

```bash
grep -nE '"/dashboard|`/dashboard' bins/outline-ui/src/ws/*.html
```
Ожидается: пустой вывод.

- [ ] **Шаг 2: написать падающий тест**

Создать `bins/outline-ui/src/ws/tests/mod.rs`:

```rust
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

use super::*;

fn state() -> WsState {
    WsState {
        backend: std::sync::Arc::new(crate::backend::Backend::new(5)),
        instances: std::sync::Arc::from(Vec::new()),
        refresh_ms: 5000,
    }
}

#[tokio::test]
async fn serves_the_dashboard_page_with_its_prefix() {
    let response =
        router(state()).oneshot(Request::get("/dashboard").body(Body::empty()).unwrap()).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains(r#"const API_BASE = "/ws""#), "prefix not substituted");
    assert!(!body.contains("__BASE__"), "placeholder survived into the response");
}

#[tokio::test]
async fn serves_the_uplinks_page() {
    let response = router(state())
        .oneshot(Request::get("/dashboard/uplinks").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn lists_configured_instances() {
    let response = router(state())
        .oneshot(Request::get("/dashboard/api/instances").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
```

- [ ] **Шаг 3: прогнать тест и убедиться, что он падает**

Команда: `cargo test -p outline-ui ws::`
Ожидается: FAIL — `cannot find module ws`.

- [ ] **Шаг 4: написать роутер и хендлеры**

Создать `bins/outline-ui/src/ws/mod.rs`:

```rust
//! Client dashboard: uplinks, topology, carrier loss.

mod api;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use crate::backend::Backend;
use crate::config::InstanceConfig;

const DASHBOARD_TEMPLATE: &str = include_str!("dashboard.html");
const UPLINKS_TEMPLATE: &str = include_str!("uplinks.html");

/// Mount point of this tree. Handlers embed it in the HTML they serve, so it
/// must match the `nest` prefix in `main.rs` — a mismatch makes every fetch from
/// the page 404 while the page itself loads fine.
pub const BASE: &str = "/ws";

#[derive(Clone)]
pub struct WsState {
    pub backend: Arc<Backend>,
    pub instances: Arc<[InstanceConfig]>,
    pub refresh_ms: u64,
}

pub fn router(state: WsState) -> Router {
    Router::new()
        .route("/", get(|| async { axum::response::Redirect::temporary("/ws/dashboard") }))
        .route("/dashboard", get(api::dashboard_page))
        .route("/dashboard/uplinks", get(api::uplinks_page))
        .route("/dashboard/outline-logo.png", get(|| async { crate::assets::logo() }))
        .route("/dashboard/api/instances", get(api::list_instances))
        .route("/dashboard/api/topology", get(api::topology))
        .route("/dashboard/api/activate", post(api::activate))
        .route("/dashboard/api/set_enabled", post(api::set_enabled))
        .route("/dashboard/api/reselect", post(api::reselect))
        .route(
            "/dashboard/api/uplinks",
            get(api::uplinks_proxy)
                .post(api::uplinks_proxy)
                .patch(api::uplinks_proxy)
                .delete(api::uplinks_proxy),
        )
        .route("/dashboard/api/apply", post(api::apply_proxy))
        .fallback(|| async { crate::assets::not_found() })
        .with_state(state)
}

#[cfg(test)]
mod tests;
```

Создать `bins/outline-ui/src/ws/api.rs`, перенеся
`bins/outline-ws-rust/src/http/dashboard/api.rs`. Логика не меняется: тот же
разлёт по инстансам, те же формы JSON, та же обработка ошибок отдельного
инстанса. Меняется только обвязка:

- `pub async fn handle_x(request: Request<Incoming>, state: DashboardState)`
  становится хендлером axum: `State(state): State<WsState>` плюс нужные
  экстракторы (`Query<…>` для `?instance=`, `body: Bytes` для тел POST);
- вызовы `backend_client` становятся
  `state.backend.request(instance, method, path, body)`;
- хендлеры страниц используют шаблоны:
  ```rust
  pub async fn dashboard_page(State(state): State<WsState>) -> Response {
      crate::assets::html(crate::assets::render(
          super::DASHBOARD_TEMPLATE,
          super::BASE,
          state.refresh_ms,
      ))
  }

  pub async fn uplinks_page(State(state): State<WsState>) -> Response {
      crate::assets::html(crate::assets::render(
          super::UPLINKS_TEMPLATE,
          super::BASE,
          state.refresh_ms,
      ))
  }
  ```

Подключить в `main.rs`: `mod ws;`.

- [ ] **Шаг 5: прогнать тест и убедиться, что он проходит**

Команда: `cargo test -p outline-ui ws::`
Ожидается: PASS, 3 теста.

- [ ] **Шаг 6: прогнать гейт и закоммитить**

```bash
cargo fmt --check -p outline-ui
cargo clippy -p outline-ui --all-targets --no-deps -- -D warnings
cargo test -p outline-ui
git add bins/outline-ui
git commit -m "feat(ui): mount the client dashboard under /ws"
```

---

### Задача 7: дерево `/ss`

**Файлы:**
- Создать: `bins/outline-ui/src/ss/mod.rs`, `bins/outline-ui/src/ss/api.rs`
- Скопировать: `bins/outline-ss-rust/src/server/dashboard/dashboard.html` → `bins/outline-ui/src/ss/`
- Скопировать и адаптировать: `bins/outline-ss-rust/src/server/dashboard/tests/{handlers.rs,proxy.rs}` → `bins/outline-ui/src/ss/tests/`

**Интерфейсы:**
- Использует: `Backend` (задача 4), `render`/`html`/`logo` (задача 5), `InstanceConfig` (задача 1)
- Отдаёт: `ss::router(state: SsState) -> Router`;
  `SsState { backend: Arc<Backend>, instances: Arc<[InstanceConfig]>, refresh_ms: u64 }`;
  `ss::BASE: &str = "/ss"`

- [ ] **Шаг 1: перевести HTML на префикс**

В `bins/outline-ui/src/ss/dashboard.html` добавить в начало первого `<script>`:

```js
const API_BASE = "__BASE__";
```

Переписать 5 абсолютных URL:

| Сейчас | Становится |
|---|---|
| `fetch("/dashboard/api/instances", …)` | ``fetch(`${API_BASE}/dashboard/api/instances`, …)`` |
| `fetch("/dashboard/api/users", …)` | ``fetch(`${API_BASE}/dashboard/api/users`, …)`` |
| ``fetch(`/dashboard/api/users/${id}`, …)`` | ``fetch(`${API_BASE}/dashboard/api/users/${id}`, …)`` |
| ``fetch(`/dashboard/api/users/${id}/block`, …)`` | ``fetch(`${API_BASE}/dashboard/api/users/${id}/block`, …)`` |
| `src="/dashboard/assets/outline-logo.png"` | `src="__BASE__/dashboard/assets/outline-logo.png"` |

Сегмент `/assets/` у логотипа ss остаётся как был: деревья монтируются
раздельно, унифицировать пути незачем, а лишняя правка разметки этой задаче не
нужна.

Проверить:

```bash
grep -nE '"/dashboard|`/dashboard' bins/outline-ui/src/ss/dashboard.html
```
Ожидается: пустой вывод.

- [ ] **Шаг 2: написать падающий тест**

Создать `bins/outline-ui/src/ss/tests/mod.rs`:

```rust
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

use super::*;

fn state() -> SsState {
    SsState {
        backend: std::sync::Arc::new(crate::backend::Backend::new(5)),
        instances: std::sync::Arc::from(Vec::new()),
        refresh_ms: 5000,
    }
}

#[tokio::test]
async fn serves_the_dashboard_page_with_its_prefix() {
    let response =
        router(state()).oneshot(Request::get("/dashboard").body(Body::empty()).unwrap()).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains(r#"const API_BASE = "/ss""#), "prefix not substituted");
    assert!(!body.contains("__BASE__"), "placeholder survived into the response");
}

#[tokio::test]
async fn lists_configured_instances() {
    let response = router(state())
        .oneshot(Request::get("/dashboard/api/instances").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
```

- [ ] **Шаг 3: прогнать тест и убедиться, что он падает**

Команда: `cargo test -p outline-ui ss::`
Ожидается: FAIL — `cannot find module ss`.

- [ ] **Шаг 4: написать роутер и хендлеры**

Создать `bins/outline-ui/src/ss/mod.rs`:

```rust
//! Server dashboard: user CRUD across instances.

mod api;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, patch, post};

use crate::backend::Backend;
use crate::config::InstanceConfig;

const DASHBOARD_TEMPLATE: &str = include_str!("dashboard.html");

/// Mount point of this tree; see the note on `ws::BASE`.
pub const BASE: &str = "/ss";

#[derive(Clone)]
pub struct SsState {
    pub backend: Arc<Backend>,
    pub instances: Arc<[InstanceConfig]>,
    pub refresh_ms: u64,
}

pub fn router(state: SsState) -> Router {
    Router::new()
        .route("/", get(|| async { axum::response::Redirect::temporary("/ss/dashboard") }))
        .route("/dashboard", get(api::dashboard_page))
        .route("/dashboard/assets/outline-logo.png", get(|| async { crate::assets::logo() }))
        .route("/dashboard/api/instances", get(api::list_instances))
        .route("/dashboard/api/users", get(api::list_users).post(api::create_user))
        .route("/dashboard/api/users/{id}", patch(api::update_user).delete(api::delete_user))
        .route("/dashboard/api/users/{id}/block", post(api::block_user))
        .route("/dashboard/api/users/{id}/unblock", post(api::unblock_user))
        .fallback(|| async { crate::assets::not_found() })
        .with_state(state)
}

#[cfg(test)]
mod tests;
```

Создать `bins/outline-ui/src/ss/api.rs`, перенеся
`bins/outline-ss-rust/src/server/dashboard/handlers.rs`. Это уже хендлеры axum,
поэтому правки узкие: `State<DashboardState>` становится `State<SsState>`, а
проксирующие вызовы идут через `state.backend.request(instance, method, path,
body)` вместо `proxy::forward` / `forward_json` с пулом. `dashboard_page`
рендерится через `crate::assets::render(DASHBOARD_TEMPLATE, BASE,
state.refresh_ms)`.

Подключить в `main.rs`: `mod ss;`.

- [ ] **Шаг 5: прогнать тест и убедиться, что он проходит**

Команда: `cargo test -p outline-ui ss::`
Ожидается: PASS, 2 теста.

- [ ] **Шаг 6: прогнать гейт и закоммитить**

```bash
cargo fmt --check -p outline-ui
cargo clippy -p outline-ui --all-targets --no-deps -- -D warnings
cargo test -p outline-ui
git add bins/outline-ui
git commit -m "feat(ui): mount the server dashboard under /ss"
```

---

### Задача 8: собрать сервис воедино

**Файлы:**
- Изменить: `bins/outline-ui/src/main.rs`
- Создать: `bins/outline-ui/src/tests/routing.rs`

**Интерфейсы:**
- Использует: всё выше
- Отдаёт: `build_app(config: &UiConfig) -> Router` — вынесен из `main`, чтобы
  тест маршрутизации мог его прогнать без реального сокета

- [ ] **Шаг 1: написать падающий тест**

Создать `bins/outline-ui/src/tests/routing.rs`:

```rust
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt as _;

use super::*;

fn config() -> crate::config::UiConfig {
    crate::config::UiConfig {
        listen: "127.0.0.1:9000".parse().unwrap(),
        token: "s3cr3t".to_string(),
        request_timeout_secs: 5,
        refresh_interval_secs: 5,
        allowed_hosts: Vec::new(),
        ws: Vec::new(),
        ss: Vec::new(),
    }
}

fn authed(uri: &str) -> Request<Body> {
    Request::get(uri)
        .header(header::HOST, "127.0.0.1:9000")
        .header(header::AUTHORIZATION, "Bearer s3cr3t")
        .body(Body::empty())
        .unwrap()
}

/// The whole point of the extraction: the two dashboards share a port without
/// colliding, each seeing its own prefix.
#[tokio::test]
async fn both_trees_are_reachable_and_distinct() {
    let app = build_app(&config());

    let ws = app.clone().oneshot(authed("/ws/dashboard")).await.unwrap();
    assert_eq!(ws.status(), StatusCode::OK);
    let ws_body = axum::body::to_bytes(ws.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8(ws_body.to_vec()).unwrap().contains(r#""/ws""#));

    let ss = app.oneshot(authed("/ss/dashboard")).await.unwrap();
    assert_eq!(ss.status(), StatusCode::OK);
    let ss_body = axum::body::to_bytes(ss.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8(ss_body.to_vec()).unwrap().contains(r#""/ss""#));
}

#[tokio::test]
async fn the_index_lists_both() {
    let response = build_app(&config()).oneshot(authed("/")).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("/ws/dashboard") && body.contains("/ss/dashboard"));
}

/// The gate must cover both trees, not just the root.
#[tokio::test]
async fn every_tree_is_behind_the_credential_gate() {
    let app = build_app(&config());

    for uri in ["/", "/ws/dashboard", "/ss/dashboard", "/ws/dashboard/api/instances"] {
        let response = app
            .clone()
            .oneshot(
                Request::get(uri)
                    .header(header::HOST, "127.0.0.1:9000")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "unguarded route: {uri}");
    }
}
```

- [ ] **Шаг 2: прогнать тест и убедиться, что он падает**

Команда: `cargo test -p outline-ui routing`
Ожидается: FAIL — `cannot find function build_app`.

- [ ] **Шаг 3: написать `build_app` и листенер**

Заменить `bins/outline-ui/src/main.rs` на:

```rust
//! Aggregating web UI for the outline fleet. Serves both dashboards and nothing
//! else: no uplinks, no listeners, no traffic. Every route reaches the
//! configured instances' control APIs with their bearer tokens injected
//! server-side, so both gates below run before routing rather than inside
//! handlers.

mod assets;
mod auth;
mod backend;
mod config;
mod origin;
mod ss;
mod ws;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{Router, middleware, routing::get};
use clap::Parser;
use tokio::net::TcpListener;
use tracing::info;

use crate::backend::Backend;
use crate::config::UiConfig;

#[derive(Parser, Debug)]
#[command(name = "outline-ui", about = "Web UI for the outline fleet")]
struct Args {
    /// Path to the UI configuration file.
    #[arg(long, env = "OUTLINE_UI_CONFIG", default_value = "/etc/outline-ui/config.toml")]
    config: PathBuf,
}

fn build_app(config: &UiConfig) -> Router {
    let backend = Arc::new(Backend::new(config.request_timeout_secs));
    let refresh_ms = config.refresh_interval_secs.saturating_mul(1000);

    let ws_state = ws::WsState {
        backend: Arc::clone(&backend),
        instances: Arc::from(config.ws.clone()),
        refresh_ms,
    };
    let ss_state =
        ss::SsState { backend, instances: Arc::from(config.ss.clone()), refresh_ms };

    let router = Router::new()
        .route("/", get(|| async { assets::index() }))
        .nest("/ws", ws::router(ws_state))
        .nest("/ss", ss::router(ss_state))
        .fallback(|| async { assets::not_found() });

    // Origin first, credentials outermost: an unauthorised caller gets a plain
    // 401 rather than a 403 describing what this listener expects.
    let policy = origin::OriginPolicy::new(config.listen, &config.allowed_hosts);
    let router = router.layer(middleware::from_fn_with_state(policy, origin::enforce_origin));
    let auth_state = auth::AuthState { token: Arc::from(config.token.as_str()) };
    router.layer(middleware::from_fn_with_state(auth_state, auth::require_auth))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let config = UiConfig::load(&args.config)?;
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.listen))?;
    info!(
        listen = %config.listen,
        ws_instances = config.ws.len(),
        ss_instances = config.ss.len(),
        "outline-ui started"
    );

    axum::serve(listener, build_app(&config))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("server stopped")
}

#[cfg(test)]
#[path = "tests/routing.rs"]
mod tests;
```

- [ ] **Шаг 4: прогнать тест и убедиться, что он проходит**

Команда: `cargo test -p outline-ui`
Ожидается: PASS — все тесты задач 1–8.

- [ ] **Шаг 5: прогнать руками**

```bash
mkdir -p /tmp/ui && printf '%s' 'devtoken' > /tmp/ui/token
cat > /tmp/ui/config.toml <<'EOF'
[server]
listen = "127.0.0.1:9500"
token_file = "/tmp/ui/token"
allowed_hosts = ["127.0.0.1:9500"]
EOF
cargo run -p outline-ui -- --config /tmp/ui/config.toml &
sleep 2
curl -s -o /dev/null -w "no auth: %{http_code}\n" http://127.0.0.1:9500/
curl -s -o /dev/null -w "with auth: %{http_code}\n" -H "Authorization: Bearer devtoken" http://127.0.0.1:9500/
curl -s -H "Authorization: Bearer devtoken" http://127.0.0.1:9500/ws/dashboard | grep -c '__BASE__'
kill %1
```
Ожидается: `no auth: 401`, `with auth: 200` и `0` оставшихся плейсхолдеров.

- [ ] **Шаг 6: прогнать гейт и закоммитить**

```bash
cargo fmt --check -p outline-ui
cargo clippy -p outline-ui --all-targets --no-deps -- -D warnings
cargo test -p outline-ui
git add bins/outline-ui
git commit -m "feat(ui): serve both dashboards from one listener"
```

---

### Задача 9: убрать дашборд из `outline-ws-rust`

**Файлы:**
- Удалить: `bins/outline-ws-rust/src/http/dashboard/` (15 файлов)
- Изменить: `bins/outline-ws-rust/Cargo.toml` (убрать feature `dashboard`),
  `bins/outline-ws-rust/src/http/mod.rs`, `bins/outline-ws-rust/src/bootstrap/mod.rs`,
  `bins/outline-ws-rust/src/config/types.rs` и загрузчики конфига

- [ ] **Шаг 1: удалить модуль и его подключение**

```bash
git rm -r bins/outline-ws-rust/src/http/dashboard
```

Затем убрать по порядку:
- `bins/outline-ws-rust/src/http/mod.rs`: объявление `#[cfg(feature = "dashboard")] pub mod dashboard;`;
- `bins/outline-ws-rust/src/bootstrap/mod.rs`: импорт `use crate::http::dashboard::spawn_dashboard_server;` и блок, который его вызывает;
- `bins/outline-ws-rust/Cargo.toml`: строку feature `dashboard = [...]`, `dashboard` из `default` и `base64`, если он больше нигде не нужен (проверить `grep -rn "base64" bins/outline-ws-rust/src`);
- `bins/outline-ws-rust/src/config/types.rs`: `DashboardConfig`, `DashboardInstanceConfig` и поле `dashboard` в конфиге приложения;
- записи схемы и загрузчика, которые их строят (`grep -rn "dashboard" bins/outline-ws-rust/src/config`).

- [ ] **Шаг 2: убедиться, что ссылок не осталось**

```bash
grep -rn "dashboard" bins/outline-ws-rust/src bins/outline-ws-rust/Cargo.toml | grep -viE "^\s*//|grafana"
```
Ожидается: пустой вывод.

- [ ] **Шаг 3: собрать оба набора фич**

```bash
cargo check -p outline-ws-rust
cargo check -p outline-ws-rust --no-default-features
```
Ожидается: оба чисто. `--no-default-features` входит в feature-матрицу CI,
поэтому забытый `#[cfg]` иначе всплывёт позже прямо в гейте.

- [ ] **Шаг 4: прогнать гейт**

```bash
cargo fmt --check -p outline-ws-rust
cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings
cargo test -p outline-ws-rust
```
Ожидается: зелено. Тесты дашборда ушли вместе с ним, всё остальное обязано
проходить.

- [ ] **Шаг 5: коммит**

```bash
git add -A bins/outline-ws-rust
git commit -m "refactor(ws): remove the built-in dashboard, it now lives in outline-ui"
```

---

### Задача 10: убрать дашборд из `outline-ss-rust`

**Файлы:**
- Удалить: `bins/outline-ss-rust/src/server/dashboard/` (15 файлов)
- Изменить: `bins/outline-ss-rust/src/server/mod.rs`, модуль конфига, `bins/outline-ss-rust/Cargo.toml`

- [ ] **Шаг 1: удалить модуль и его подключение**

```bash
git rm -r bins/outline-ss-rust/src/server/dashboard
```

Затем убрать:
- `bins/outline-ss-rust/src/server/mod.rs`: объявление `mod dashboard;` и вызов `spawn_dashboard_server(...)`;
- типы `DashboardConfig` / `DashboardInstanceConfig` и поле `dashboard` в конфиге (`grep -rn "Dashboard" bins/outline-ss-rust/src`);
- `bins/outline-ss-rust/Cargo.toml`: `axum`, если он больше нигде не используется, и `base64` — сначала проверить:
  ```bash
  grep -rn "axum::\|base64::" bins/outline-ss-rust/src | head
  ```

- [ ] **Шаг 2: убедиться, что ссылок не осталось**

```bash
grep -rn "dashboard" bins/outline-ss-rust/src bins/outline-ss-rust/Cargo.toml | grep -viE "^\s*//|grafana"
```
Ожидается: пустой вывод.

- [ ] **Шаг 3: собрать оба набора фич**

```bash
cargo check -p outline-ss-rust
cargo check -p outline-ss-rust --no-default-features
```
Ожидается: оба чисто.

- [ ] **Шаг 4: прогнать гейт**

```bash
cargo fmt --check -p outline-ss-rust
cargo clippy -p outline-ss-rust --all-targets --no-deps -- -D warnings
cargo test -p outline-ss-rust
```
Ожидается: зелено.

- [ ] **Шаг 5: коммит**

```bash
git add -A bins/outline-ss-rust
git commit -m "refactor(ss): remove the built-in dashboard, it now lives in outline-ui"
```

---

### Задача 11: образ и манифесты k3s

**Файлы:**
- Создать: `ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml`, `bins/outline-ui/Dockerfile`
- Изменить: `ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml` (в этом
  репозитории Ingress'ы лежат централизованно, а не рядом с приложением)

**Про архитектуру образа:** ноды кластера — aarch64 (NanoPi R5C), поэтому бинарь
собирается под `aarch64-unknown-linux-musl` и образ строится под ту же
архитектуру. Кросс-сборка в репозитории уже есть (`cargo ws-release-musl-aarch64`).

- [ ] **Шаг 1: собрать бинарь под архитектуру кластера**

```bash
cargo zigbuild --release -p outline-ui --target aarch64-unknown-linux-musl
file target/aarch64-unknown-linux-musl/release/outline-ui
```
Ожидается: `ELF 64-bit LSB executable, ARM aarch64, ... statically linked`.

- [ ] **Шаг 2: написать Dockerfile**

Создать `bins/outline-ui/Dockerfile`:

```dockerfile
# Statically linked musl binary: nothing else is needed at runtime, so the image
# is the binary and nothing more.
FROM scratch
COPY target/aarch64-unknown-linux-musl/release/outline-ui /outline-ui
USER 65534:65534
EXPOSE 9000
ENTRYPOINT ["/outline-ui"]
```

Собрать и запушить в кластерный реестр (он уже есть, см.
`ops/nanopi-r5c-k3s/apps/README.md`):

```bash
docker build --platform linux/arm64 -f bins/outline-ui/Dockerfile -t registry.k3s.beerloga.su/outline-ui:0.1.0 .
docker push registry.k3s.beerloga.su/outline-ui:0.1.0
```

- [ ] **Шаг 3: написать манифесты**

Создать `ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: outline-ui-config
  namespace: monitoring
data:
  config.toml: |
    [server]
    listen = "0.0.0.0:9000"
    token_file = "/etc/outline-ui/secrets/ui-token"
    # Behind the ingress the browser's Host is the public name, not the pod's
    # listen address. Without it here the origin policy 403s every request that
    # arrives through the ingress.
    allowed_hosts = ["ui.k3s.beerloga.su"]

    [[ws.instances]]
    name = "beelink102"
    control_url = "http://198.18.1.102:9191"
    token_file = "/etc/outline-ui/secrets/ws-beelink102"

    [[ws.instances]]
    name = "nanopi104"
    control_url = "http://198.18.1.104:9191"
    token_file = "/etc/outline-ui/secrets/ws-nanopi104"

    [[ws.instances]]
    name = "cloud1"
    control_url = "https://cloud1.beerloga.su/rust-ws-exporter"
    token_file = "/etc/outline-ui/secrets/ws-cloud1"

    [[ws.instances]]
    name = "cloud2"
    control_url = "https://cloud2.beerloga.su/rust-ws-exporter"
    token_file = "/etc/outline-ui/secrets/ws-cloud2"

    [[ss.instances]]
    name = "beerloga-1"
    control_url = "http://198.18.1.104:9190"
    token_file = "/etc/outline-ui/secrets/ss-beerloga-1"

    [[ss.instances]]
    name = "beerloga-2"
    control_url = "http://198.18.1.102:9190"
    token_file = "/etc/outline-ui/secrets/ss-beerloga-2"

    [[ss.instances]]
    name = "cloud1"
    control_url = "https://cloud1.beerloga.su/rust-ss-exporter"
    token_file = "/etc/outline-ui/secrets/ss-cloud1"

    [[ss.instances]]
    name = "cloud2"
    control_url = "https://cloud2.beerloga.su/rust-ss-exporter"
    token_file = "/etc/outline-ui/secrets/ss-cloud2"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: outline-ui
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels: { app: outline-ui }
  template:
    metadata:
      labels: { app: outline-ui }
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
      containers:
        - name: outline-ui
          image: registry.k3s.beerloga.su/outline-ui:0.1.0
          args: ["--config", "/etc/outline-ui/config.toml"]
          ports:
            - containerPort: 9000
          volumeMounts:
            - name: config
              mountPath: /etc/outline-ui/config.toml
              subPath: config.toml
              readOnly: true
            - name: secrets
              mountPath: /etc/outline-ui/secrets
              readOnly: true
          resources:
            requests: { cpu: 10m, memory: 32Mi }
            limits: { memory: 128Mi }
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
      volumes:
        - name: config
          configMap: { name: outline-ui-config }
        - name: secrets
          secret: { secretName: outline-ui-tokens }
---
apiVersion: v1
kind: Service
metadata:
  name: outline-ui
  namespace: monitoring
spec:
  selector: { app: outline-ui }
  ports:
    - { port: 9000, targetPort: 9000 }
```

Liveness-пробы намеренно нет: все маршруты стоят за гейтом credentials, поэтому
неаутентифицированная проба получала бы 401 и kubelet перезапускал бы здоровый
под по кругу. Если проба понадобится, ей нужен осознанно добавленный health-роут
без авторизации.

Затем добавить Ingress в центральный файл
`ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml` — в том же виде, что
соседние записи:

```yaml
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: outline-ui
  namespace: monitoring
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: "true"
spec:
  ingressClassName: traefik
  rules:
    - host: ui.k3s.beerloga.su
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: outline-ui
                port:
                  number: 9000
```

Восемь токенов инстансов плюс токен UI кладутся в Secret, созданный отдельно и
никогда не попадающий в git:

```bash
kubectl -n monitoring create secret generic outline-ui-tokens \
  --from-literal=ui-token='<generated>' \
  --from-literal=ws-beelink102='<token>' \
  --from-literal=ws-nanopi104='<token>' \
  --from-literal=ws-cloud1='<token>' \
  --from-literal=ws-cloud2='<token>' \
  --from-literal=ss-beerloga-1='<token>' \
  --from-literal=ss-beerloga-2='<token>' \
  --from-literal=ss-cloud1='<token>' \
  --from-literal=ss-cloud2='<token>'
```

Текущие per-node токены лежат в `config.toml` каждого узла в секции `[control]` —
брать их оттуда, а не выдумывать новые (либо ротировать осознанно).

- [ ] **Шаг 4: раскатать и проверить**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml
kubectl apply -f ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml
kubectl -n monitoring rollout status deploy/outline-ui --timeout=120s
kubectl -n monitoring logs deploy/outline-ui --tail=20
```
Ожидается: `outline-ui started` с числом инстансов из конфига.

Затем проверить, что сервис действительно достаёт до парка, — агрегирующий вызов
и есть настоящая проверка:

```bash
kubectl -n monitoring run uicheck --rm -i --restart=Never --image=curlimages/curl -- \
  curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer <ui-token>" \
  http://outline-ui.monitoring:9000/ws/dashboard/api/instances
```
Ожидается: `200`.

- [ ] **Шаг 5: коммит**

```bash
git add ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml \
        ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml \
        bins/outline-ui/Dockerfile
git commit -m "ops(ui): deploy outline-ui to the monitoring namespace"
```

---

### Задача 12: документация

**Файлы:**
- Создать: `bins/outline-ui/README.md`, `bins/outline-ui/README.ru.md`
- Изменить: `AGENTS.md`, `bins/outline-ws-rust/README.md` + `.ru.md`,
  `bins/outline-ss-rust/README.md` + `.ru.md`, `ops/nanopi-r5c-k3s/apps/README.md`

- [ ] **Шаг 1: написать README нового бинаря (EN + RU)**

Оба файла покрывают: что это за сервис (агрегирующий UI, без data plane), форму
конфига с `token_file`, два префикса, почему гейт по credentials обязателен, и
как запустить локально. Держать их в паре — правило репозитория требует менять
EN/RU вместе.

- [ ] **Шаг 2: обновить доки бинарей**

Во всех четырёх `bins/outline-{ws,ss}-rust/README{,.ru}.md` убрать разделы про
дашборд и сослаться на `outline-ui`. Сначала найти все упоминания:

```bash
grep -rn "dashboard" bins/outline-ws-rust/README.md bins/outline-ws-rust/README.ru.md \
  bins/outline-ss-rust/README.md bins/outline-ss-rust/README.ru.md
```

- [ ] **Шаг 3: обновить `AGENTS.md`**

Добавить `bins/outline-ui/` в раздел структуры как третий бинарь, отметить, что
он держит web-UI для обоих, и добавить его в команду fmt в блоке CI-гейта, чтобы
описанный гейт совпадал с `ci.yml`.

- [ ] **Шаг 4: обновить индекс приложений k3s**

Добавить `outline-ui` в `ops/nanopi-r5c-k3s/apps/README.md` рядом с другими
приложениями мониторинга — с его ingress-хостом и пометкой, что его Secret
держит control-токены всего парка.

- [ ] **Шаг 5: прогнать полный гейт в последний раз**

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
cargo test --workspace --exclude sockudo-ws
```
Ожидается: всё зелёное.

- [ ] **Шаг 6: коммит**

```bash
git add -A
git commit -m "docs(ui): document outline-ui and drop the dashboard from the binaries"
```

---

## Порядок раскатки

Узлы не должны остаться без дашбордов раньше, чем заработает замена, поэтому:

1. Задачи 1–8 создают новый сервис; на парке при этом ничего не меняется.
2. Задача 11 раскатывает его и доказывает, что он достаёт до каждого инстанса.
3. И только потом задачи 9–10 убирают дашборды, после чего бинари пересобираются
   и раскатываются по узлам (`ops/deploy/deploy-binary.sh`, по одному узлу за
   раз — каждая раскатка рестартует юнит и роняет трафик этого узла).

Пересборка и раскатка бинарей — боевое действие: спрашивать владельца перед
каждым узлом и помнить, что `.104` — aarch64, а остальные x86_64.
