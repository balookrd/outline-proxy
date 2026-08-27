# Модель эндпоинтов сервера + padding как атрибут эндпоинта (дизайн)

Дата: 2026-08-27
Статус: согласовано в чате

## Проблема

Сегодня на сервере (`bins/outline-ss-rust`) carrier-пути и их padding-статус
живут в трёх несогласованных местах, а маршрутизация построена вокруг
per-user путей:

1. **Пути** задаются глобально в `[websocket]` (`ws_path_tcp/udp/ss/vless`,
   `xhttp_path_tcp/udp/ss/vless`) и переопределяются per-user в `[[users]]`
   (те же 8 полей + `effective_*_path`).
2. **Padding** задаётся ОТДЕЛЬНЫМ списком `[padding] paths` (плюс `enabled`),
   который дублирует пути из пункта 1 и должен держаться с ними в синхроне.
3. **Маршрутизация** (`server/setup.rs`) строит 6 карт `path → TransportRoute`
   из per-user маршрутов (`build_*_user_routes` → `build_*_route_map`);
   аутентификация (`auth_users`) выводится из тех же per-user маршрутов.

Padding «config-synchronised, без on-wire бита»
(`crates/outline-wire/src/padding.rs:18`): сервер декодирует padding на пути
`P` тогда и только тогда, когда `P ∈ [padding] paths`; при рассинхроне
padded-кадр `real_len|pad_len|real|pad` скармливается прямо в SS-декриптор и
рвёт сессию (симптом «трафик стоит, пробы зелёные»). Отдельный список `paths`
— главный источник этого класса багов.

Побочно: per-user пути — это ручная изоляция «юзер доступен только на своём
пути». Но пул ключей на путь УЖЕ существует: `build_transport_route_map`
(`server/setup.rs:75`) группирует users по пути в `TransportRoute.users:
Arc<[UserKey]>`, а аутентификация перебирает пул. То есть «несколько users на
одном пути» — не новая механика, а то, что уже происходит на глобальном пути.

## Цель

Одна модель, один источник истины:

- Сервер объявляет **глобальный список эндпоинтов** (startup-only). Каждый
  эндпоинт несёт `path`, `kind` (carrier + transport-shape) и флаг `padded`.
- **Users — чистый пул кредов** (`password` / `vless_id`, `method`, `fwmark`,
  `aliases`, `enabled`), без путей. Каждый user работает на ВСЕХ эндпоинтах
  подходящего kind.
- **Padding — атрибут эндпоинта**. Выбор, паддить ли сессию, целиком за
  клиентом: он выбирает, на какой эндпоинт подключиться. Сервер обслуживает и
  padded-, и plain-эндпоинты для всех клиентов; сторонние plain-клиенты
  (Outline/xray) на plain-эндпоинтах не затронуты.

Wire-протокол не трогаем: on-wire capability-бита по-прежнему нет,
padded-эндпоинт всегда padded, plain — всегда plain. Клиентскую сторону
(`outline-ws-rust`, per-uplink `padding`) не трогаем — это и есть «выбор на
клиенте».

Изменение breaking: старые `[websocket] ws_path_*`/`xhttp_path_*`, per-user
пути и `[padding] enabled/paths` удаляются. Прод-конфиги парка переписываются
вручную при выкатке (по одному узлу).

## Подход

### 1. Config-схема

Новая top-level секция-список (имя `[[endpoint]]`, не `[websocket.endpoint]`,
т.к. охватывает и xhttp):

```toml
[[endpoint]]
path  = "/pss"
kind  = "ws_ss"        # combined SS over WS (обе ноги TCP+UDP)
padded = true

[[endpoint]]
path  = "/tcp"
kind  = "ws_ss_tcp"    # split SS TCP over WS; padded по умолчанию false

[[endpoint]]
path  = "/vl"
kind  = "ws_vless"
padded = true

[[endpoint]]
path  = "/ssx"
kind  = "xhttp_ss"
padded = true

[[users]]
id = "alice"
password = "..."       # без путей — alice на всех ss-эндпоинтах

[[users]]
id = "bob"
vless_id = "uuid..."   # bob на всех vless-эндпоинтах

[padding]              # ТОЛЬКО параметры; без enabled/paths
min_bytes = 0
max_bytes = 256
cover = false
cover_jitter_min_ms = 250
cover_jitter_max_ms = 1500
# throttle_* — как раньше
```

`EndpointKind` — плоский enum из 8 значений (прямой маппинг на 6 route-карт;
combined расширяется в две): `ws_ss`, `ws_ss_tcp`, `ws_ss_udp`, `ws_vless`,
`xhttp_ss`, `xhttp_ss_tcp`, `xhttp_ss_udp`, `xhttp_vless`. Секция
`#[serde(deny_unknown_fields)]`, `padded` — `#[serde(default)] = false`.

Удаляется:

- `[websocket]` секция целиком — `WebsocketSection` содержит только 8
  path-полей (`ws_path_*` / `xhttp_path_*`), других полей там нет.
- Из `UserEntry` — все 8 path-полей (`ws_path_tcp/udp/ss/vless`,
  `xhttp_path_vless/tcp/udp/ss`) и методы `effective_*_path` / `effective_*_ss`.
  Остаются: `id`, `password`, `fwmark`, `method`, `vless_id`, `enabled`,
  `aliases`.
- Из `[padding]` — `enabled` и `paths`. `PaddingConfig` теряет поле `enabled`;
  поле `paths` становится ВЫВЕДЕННЫМ множеством padded-путей (`padded_paths`),
  собранным из эндпоинтов.

### 2. Резолвинг padded-множества

При загрузке (`config/loader.rs`, где доступны и эндпоинты, и users) собирается
`padded_paths: Vec<String>` = пути всех эндпоинтов с `padded = true`. Для
xhttp кладётся base-path (резолвер зовётся с base, суффикс `/{id}` уже снят).
Множество кладётся в `PaddingConfig`; `carrier_padding::init` работает как
раньше.

`PaddingConfig::applies_to/scheme_for_path/cover_enabled/scheme` теряют
зависимость от `enabled`: активность = членство пути в `padded_paths`.
**14 call-sites `scheme_for_path`/`cover_for_path`/`throttle_params_for_path`
(в `transport/mod.rs`, `tcp.rs`, `udp.rs`, `vless/mod.rs`, `xhttp/handlers.rs`,
`h3/http.rs`) НЕ меняются** — меняется только источник множества.

### 3. Routing (`server/setup.rs`)

Вместо `build_*_user_routes` (обход per-user путей) — обход эндпоинтов:

- Разложить `config.endpoints` по kind в наборы путей (`tcp_paths`,
  `udp_paths`, `vless_paths`, `xhttp_ss_paths`, `xhttp_ss_udp_paths`,
  `xhttp_vless_paths`). Combined (`ws_ss` → tcp+udp; `xhttp_ss` → xhttp_ss +
  xhttp_ss_udp) попадает в обе.
- Для каждого пути построить `TransportRoute`/`VlessTransportRoute` с пулом
  **всех** подходящих users: SS-users (у кого есть `password`, по
  `effective_method`) на ss-путях; vless-users (у кого есть `vless_id`) на
  vless-путях. `TransportRoute.users` / `candidate_users` / `peer_user_cache`
  — как сейчас.
- `auth_users` (`user_keys`) выводится из общего пула SS-users, не из
  per-user маршрутов.

Целевая логика проще текущей (эндпоинт × общий пул вместо per-user
комбинаторики), но переписывается весь `setup.rs` route-building и структуры
`UserRoute`/`VlessUserRoute*` (теряют path-поля или заменяются).

Смежная поверхность — **регистрация путей в axum-роутер**
(`server/bootstrap/axum.rs`): combined `<path>/{token}` через
`combined_websocket_upgrade`, split `tcp_/udp_/vless_websocket_upgrade`, xhttp
`<base>` / `<base>/{id}` / `<base>/{id}/{seq}`. Сейчас строится из глобальных
и per-user путей; переезжает на наборы путей, собранные из эндпоинтов (тех же,
что питают route-карты и H3 frozen path-sets).

### 4. Validation (`config/validation.rs`)

Переписать под эндпоинты:

- Уникальность `path` среди эндпоинтов; запрет пересечения путей разных kind,
  которые обязаны быть distinct (tcp/udp/vless/xhttp), как сейчас между
  наборами; combined vs split на одном пути — конфликт.
- Предупредить (WARN, не fail), если объявлен эндпоинт kind, для которого нет
  ни одного подходящего user (ss-эндпоинт без ss-users; vless — без
  vless-users).
- Убрать проверку «`[padding] enabled` requires non-empty `paths`».

### 5. Control-plane (`server/control/manager.rs`, `persist.rs`)

Users управляются через control как **креды** (без путей). Удаляются
`default_ws_path_*` / `default_xhttp_path_*`, `allowed_*_paths` и per-user
пути; `rendered_user` сериализует `UserEntry` без path-полей. Инвариант
persist (патчить ровно одну запись `[[users]]`, не пересобирать список)
сохраняется — это защита от реальной потери боевого конфига.

Эндпоинты — **startup-only**, как текущий «H3 path registry startup-time»
(`bins/outline-ss-rust/AGENTS.md`): задаются в `config.toml`, меняются
рестартом; control API их не трогает. Добавление/удаление эндпоинта = новый
путь = требует рестарта, как и сегодня для новых путей.

### 6. H3

Автоматически: ws/xhttp-эндпоинты доступны по H3 через те же `RouteRegistry`
(`ctx.routes.load()`) и frozen path-sets (`tcp_paths`/`udp_paths`/
`vless_paths`/`xhttp_paths` в `H3ConnectionCtx`), которые теперь собираются из
эндпоинтов. Правило «замораживать в ctx можно только НАБОРЫ путей, а
route-записи читать из живого снапшота» сохраняется.

## Инварианты (не регрессировать)

- **Plain-путь байт-в-байт как раньше.** Эндпоинт без `padded` не фреймит и
  не декодирует — сторонние клиенты (Outline/xray/Happ) не затронуты. Padding
  остаётся config-synchronised с клиентом: padded-эндпоинт требует клиента с
  включённым padding, иначе сессия рвётся (это осознанный контракт, не
  негоциация).
- **Пул ключей на путь и `peer_user_cache`.** Аутентификация по-прежнему
  перебирает пул users пути; LRU `peer_addr → user_index` заменяется вместе с
  `users` на любом rebuild.
- **Bounded resources / resume / H3-keepalive** — не трогаем: NAT, replay,
  session-resumption, cross-transport resume (`X-Outline-Resume*`), запрет
  server→client WS `Ping` на H3-carrier.
- **persist патчит одну `[[users]]`, не пересобирает список** —
  сторож `control/tests/persist.rs`.

## Тестирование

- **Config.** Парсинг `[[endpoint]]` всех 8 kind + `padded`; падение (ошибка)
  на старых `ws_path_*`/`xhttp_path_*`/per-user путях/`[padding] enabled|paths`
  (breaking, `deny_unknown_fields`); `UserEntry` без путей round-trip.
- **Padded-множество.** Сбор из эндпоинтов; combined → base-path; xhttp →
  base без суффикса; plain-эндпоинт отсутствует в множестве.
- **Routing.** Эндпоинт → route с полным пулом подходящих users; combined
  (`ws_ss`) регистрируется в tcp+udp; ss-эндпоинт не тянет vless-users и
  наоборот; пустой пул → route без users (+WARN).
- **Validation.** Дубликат path; конфликт kind на одном пути; combined vs
  split; WARN на эндпоинт без users.
- **Padding-резолвер.** `scheme_for_path` даёт scheme на padded-пути и
  disabled на plain; `cover_for_path`/`throttle_params_for_path` только на
  padded.
- **Control.** Upsert/remove user (креды без путей); persist патчит одну
  запись; snapshot без путей.
- **E2e padding.** Существующие `tests/e2e_padding.rs` переключить на
  эндпоинты (padded помечается флагом эндпоинта, а не списком) — все зелёные.
- **Gate перед коммитом.** Полный: `cargo fmt` с явным списком пакетов,
  `clippy --workspace --exclude sockudo-ws --all-targets --no-deps -D warnings`,
  `test --workspace --exclude sockudo-ws`; плюс `check -p outline-ss-rust
  --no-default-features`.

## Документация

EN + RU параллельно: `bins/outline-ss-rust/config.toml` (переписать секции
путей → `[[endpoint]]`, `[padding]` без enabled/paths, `[[users]]` без путей),
`docs/PADDING.md` / `.ru.md`, `bins/outline-ss-rust/README.md` / `.ru.md`,
`CHANGELOG.md` / `.ru.md`. Заметка в `bins/outline-ss-rust/AGENTS.md` про новую
модель эндпоинтов (startup-only, users на всех путях, padding = атрибут
эндпоинта). Grafana-дашборд/systemd — проверить на упоминания путей.

## Rollout / миграция

Breaking для config. Бинарь падает на старом формате (`deny_unknown_fields`),
поэтому конфиг узла обновляется ОДНОВРЕМЕННО с бинарём. Выкатка по одному узлу,
клиенты уводятся с трогаемого узла, без рестарта прода без явного согласия
(`ops/deploy/deploy-binary.sh`, бэкап+автооткат). Клиентские конфиги
(`outline-ws-rust`) не меняются — per-uplink `padding` и URL остаются; padded
URL клиента должен указывать на padded-эндпоинт сервера (как и сейчас).

## Вне scope

Клиент (`outline-ws-rust`), wire-протокол и on-wire negotiation, hot-add
эндпоинтов через control API, серверные padding-метрики (их нет), raw
SS/VLESS-over-QUIC (ALPN удалён ранее).
