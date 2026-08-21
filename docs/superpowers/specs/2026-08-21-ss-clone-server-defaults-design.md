# Эффективные серверные дефолты для клона + UI-фиксы (дизайн)

Дата: 2026-08-21
Статус: согласовано в чате, ждёт вычитки владельцем

## Контекст

Фича «Clone user» раскатана в `outline-ui:1.0.7`
(см. [`2026-08-20-ss-user-clone-design.md`](2026-08-20-ss-user-clone-design.md)).
На проде вскрылось: для пользователей, у которых `method` и пути **не заданы
явно** (работают через серверные дефолты `[shadowsocks] method` и
`default_ws_path_*`), форма клона показывает:

- **пустой пароль** — `generatePassword('')` возвращает `null` (UI не знает
  эффективный серверный шифр), пароль не генерируется;
- **пустые пути** — у шаблона они `null`, копировать нечего;
- **бесполезный «глаз»** — переключатель show/hide визуально бездействует,
  потому что скрывать нечего (пароль пуст) — это **не баг**, а следствие.

Корень: control API ss-rust (`UserView`) отдаёт наружу **только явные поля
пользователя** (`skip_serializing_if` на `None`), а серверные дефолты не
отдаёт вовсе. При этом `UserManager` (`server/control/manager.rs:45-53`) уже
**держит все дефолты в памяти**: `default_method: CipherKind` (всегда
конкретный — `config.method`, прошедший `unwrap_or` в загрузчике),
`default_ws_path_tcp/udp: String`, `default_ws_path_ss/vless: Option<String>`,
`default_xhttp_path_{tcp,udp,ss,vless}: Option<String>`. Их просто никто не
сериализует.

## Проблема

UI не может корректно клонировать пользователя на серверных дефолтах, потому
что не видит эффективный метод (нужен для генерации пароля) и эффективные пути.
Плюс два мелких UI-дефекта, замеченных на проде:

- значок переключателя темы (`Topbar.svelte:22`) — статичный SVG луны, не
  меняется на солнце при смене темы;
- «глаз» у пароля кажется сломанным (на самом деле — пустой пароль).

## Цель

1. Control API ss-rust отдаёт серверные дефолты (метод + все дефолтные пути);
   `outline-ui` проксирует их; клон подставляет дефолты туда, где у шаблона
   пусто, — чтобы пароль генерировался и пути были видны.
2. Значок темы реагирует на эффективную тему (луна ↔ солнце).

## Дизайн

### §1. ss-rust: эндпоинт `GET /control/defaults`

- `server/control/manager.rs`: новая `#[derive(Serialize)] struct ServerDefaults`
  с полями `method: CipherKind`, `ws_path_tcp: String`, `ws_path_udp: String`,
  `ws_path_ss: Option<String>`, `ws_path_vless: Option<String>`,
  `xhttp_path_tcp/udp/ss/vless: Option<String>` (та же раскладка, что
  `default_*` поля менеджера). Метод `UserManager::defaults(&self) ->
  ServerDefaults` — читает `default_*` поля напрямую (без блокировки `Inner`:
  дефолты неизменны после `new`). `Option`-поля — `skip_serializing_if`.
- `server/control/handlers.rs`: `pub(super) async fn get_defaults(State) ->
  Response` → `ok_json(state.manager.defaults())`.
- `server/control/server.rs`: `.route("/control/defaults", get(get_defaults))`.

Только чтение неизменных дефолтов; секретов не отдаёт. Гейт (`control` фича)
уже покрывает роут авторизацией — как у `/control/users`.

### §2. outline-ui backend: проксирование

- `bins/outline-ui/src/ss/api.rs`: handler `defaults(State, Query{instance})`
  → `forward(&state, &instance, Method::GET, "/control/defaults", None)`
  (точно как `list_users` форвардит `/control/users`).
- Роутер ss: добавить `/dashboard/api/defaults` → `defaults` (рядом с
  `/dashboard/api/users`). Токен инстанса инъектится `forward`, как везде.

### §3. frontend: клон подставляет дефолты

- `lib/types.ts`: интерфейс `ServerDefaults` (snake_case, зеркало §1).
- `lib/api.ts`: `getDefaults = (i) => json<ServerDefaults>(
  \`/ss/dashboard/api/defaults?${q(i)}\`)`.
- `lib/userForm.ts`: `cloneUserFields(template, defaults, rand?, uuid?)` —
  подставляет дефолты **только туда, где у шаблона пусто, и только по
  идентичностям шаблона**:
  - если `has_password`: `method ← template.method || defaults.method`
    (→ `generatePassword` получает конкретный шифр → пароль генерируется);
    SS-пути — уважая combined-vs-split: если `defaults.ws_path_ss` задан
    (combined) → `ws_path_ss ← template || defaults.ws_path_ss`, иначе
    `ws_path_tcp/udp ← template || defaults.ws_path_{tcp,udp}`; симметрично
    для `xhttp_path_ss` vs `xhttp_path_{tcp,udp}`;
  - если `has_vless_id`: `ws_path_vless ← template || defaults.ws_path_vless`,
    `xhttp_path_vless ← template || defaults.xhttp_path_vless`;
  - `id`/`aliases` по-прежнему пустые; секреты генерируются как раньше
    (`has_password` → password по методу, `has_vless_id` → vless_id).
- `features/ss/Users.svelte`: `openCloneDrawer(user)` становится `async` —
  грузит `getDefaults(instance)`, затем `seedFields =
  cloneUserFields(user, defaults)`. При ошибке загрузки дефолтов — тост
  ошибки, дефолты не подставляются (клон открывается как раньше, с пустым
  паролем; не блокируем). `seedNeedsPassword` — как есть.
- `UserDrawer.svelte` не меняется: авто-регенерация по методу уже работает,
  и теперь метод приходит непустым → пароль виден сразу, «глаз» работает.

### §4. UI-фикс: тема (значок + цвет браузера)

- **Значок.** `components/layout/Topbar.svelte`: импортировать `theme` из
  `lib/theme.svelte`, вычислить эффективную тему реактивно (`theme.mode ??`
  системная `prefers-color-scheme`) и показывать **солнце** в тёмной теме
  (клик уводит в светлую) / **луну** в светлой. Для реактивности на системную
  тему при `mode == null` — подписка на `matchMedia('(prefers-color-scheme:
  dark)')` `change`. Два инлайновых SVG (луна/солнце), выбор по `isDark`.
- **Цвет браузера (`theme-color`).** `lib/theme.svelte.ts::applyTheme` при
  каждом применении темы обновляет `<meta name="theme-color">` под цвет фона
  текущей темы — чтобы UI-хром браузера (адресная строка на мобильных/PWA)
  совпадал с темой. Значение берётся из вычисленного `--bg` (или двух явных
  токенов light/dark). Тег `<meta name="theme-color">` при отсутствии
  создаётся в `document.head`. Эффективная тема — та же `isDark`, что и для
  значка (учитывает `mode == null` → системная).

### §5. «Глаз» — не баг

Переключатель show/hide (`UserDrawer.svelte:161`) корректен; он визуально
бездействует только при пустом пароле. После §1-§3 клон default-юзера сразу
несёт пароль → «глаз» работает без правок. Отдельного фикса не требует.

## Деплой

- **ss-rust на 7 ss-узлов**: `nuxt`, `nuxt2`, `sebek`, `cloud1`, `cloud2`,
  `.102`, `.104`. Новый эндпоинт компилируется в бинарь → нужен деплой +
  рестарт (data plane; рестарт рвёт флоу узла — **по одному узлу**,
  уводя клиентов, через `ops/deploy/deploy-binary.sh`). Две архитектуры
  (x86_64-musl + aarch64-musl — `.104` вендорный aarch64) — проверить арку
  каждого узла перед деплоем, собрать обе. Обратная совместимость: старый UI
  не зовёт `/control/defaults`, новый эндпоинт аддитивен — порядок
  ss-then-ui или ui-then-ss некритичен (UI мягко переживает отсутствие
  дефолтов, см. §3).
- **outline-ui `:1.0.8`**: та же процедура, что `:1.0.7`
  (`pnpm build` → `cargo ui-release-musl-aarch64 --features embed-assets` →
  `docker build --provenance=false --sbom=false` → push → `kubectl apply`
  манифест `1.0.7→1.0.8` → rollout). Несёт §3 и §4.

## Вне scope (YAGNI)

- Показ существующего пароля/UUID при **Edit** — control API намеренно не
  отдаёт секреты наружу (только `has_*`); чтобы показать, сервер должен был
  бы отдавать сам секрет в браузер/агрегатор — снижение безопасности, не
  делаем.
- Генерация строки подключения (`ss://` / `vless://` / share-link) в UI —
  отдельная фича, здесь не трогаем.
- Подстановка дефолтов в **create/edit** формах — только клон.
