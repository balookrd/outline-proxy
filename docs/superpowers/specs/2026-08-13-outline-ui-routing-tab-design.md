# Вкладка редактирования routing-конфига в `outline-ui` (дизайн)

Дата: 2026-08-13
Статус: согласовано в чате, ждёт вычитки владельцем

## Контекст

`outline-ui` — агрегирующий web-UI парка (`bins/outline-ui/`): отдаёт два
дашборда (`/ss`, `/ws`) и лендинг, сам data plane не несёт — только проксирует
к control API каждого узла, подставляя bearer-токен на своей стороне
(см. [`2026-08-12-outline-ui-dashboard-extraction-design.md`](2026-08-12-outline-ui-dashboard-extraction-design.md)
и [`2026-08-12-outline-ui-svelte-rewrite-design.md`](2026-08-12-outline-ui-svelte-rewrite-design.md)).

WS-панель (клиент `outline-ws-rust`) сейчас несёт три вкладки: **Topology**
(`/ws`, read-view топологии аплинков), **Uplinks** (`/ws/uplinks`, CRUD
аплинков) и операции (activate/reselect/on-off). Вкладка Uplinks —
готовый образец «редактирование части `config.toml` через UI»:

- control-endpoint узла `/control/uplinks` (GET/POST/PATCH/DELETE) правит
  массив `[[outline.uplinks]]` через `toml_edit::DocumentMut` (сохраняя
  комментарии/форматирование), пишет атомарно 0600, round-trip-валидирует;
- прокси в `outline-ui`: `ws/api.rs::uplinks_proxy` → `/control/uplinks`,
  токен инъектится на сервере (`backend.rs`);
- фронт: `features/ws/Uplinks.svelte` + `UplinkDrawer.svelte`, форм-логика
  вынесена в framework-free `lib/uplinkForm.ts` (unit-тестируемая сборка
  payload), модель **staged → apply**: мутации пишут в `config.toml` (dirty),
  кнопка «Apply now» зовёт `/control/apply`, который hot-применяет группы
  без рестарта.

## Проблема

Policy-routing клиента (`[[route]]` в `config.toml` узла) сейчас нельзя править
из UI вообще — только руками по SSH. При этом routing — операторский инструмент
не реже аплинков: он решает, какой трафик идёт через какую группу, какой
`direct`, какой `drop`.

Две технические особенности отличают routing от аплинков и определяют объём:

1. **В control API узла нет ни одного endpoint для routing.** Есть только
   `topology/summary/activate/reselect/uplink_enabled/uplinks/apply`. Секция
   `[[route]]` читается один раз при старте (`load_routing_config`),
   компилируется в `RoutingTable` и живёт до конца процесса.
2. **`/control/apply` намеренно не применяет routing** — только uplink-группы
   (`registry.apply_new_groups`). Структурные правки `[[route]]` (набор правил,
   порядок, `via`, inline-`prefixes`/`domains`, `default`, `invert`, fallback)
   вступают в силу **только при полном рестарте процесса**. Hot без рестарта
   перечитывается лишь *содержимое* CIDR/domain-файлов (по mtime, через
   `ArcSwap` внутри каждого правила).

## Цель

Добавить в WS-панель вкладку **Routing** (`/ws/routing`) — структурированный
CRUD-редактор правил `[[route]]` с управлением порядком и кнопкой **Apply**,
применяющей изменения **без рестарта узла**, точно как у Uplinks. Это требует
не только UI и нового control-endpoint, но и доработки data plane: механизма
горячей пересборки и атомарной подмены `RoutingTable` в TUN и SOCKS.

## Зафиксированные в брейншторме решения

- **Форма редактора** — структурированный CRUD, как Uplinks (таблица правил +
  drawer), а не raw-TOML и не «только редактор файлов-списков».
- **Применение** — hot-apply без рестарта (кнопка Apply, как у Uplinks). Data
  plane дорабатывается.
- **Порядок правил** — reorder (вверх/вниз) + вставка в позицию; правила
  адресуются индексом (у `[[route]]` нет имён).
- **Объём** — одна спека / один план: CRUD + reorder + hot-apply + UI с Apply
  вместе.
- **Конкурентность** — оптимистичная блокировка через `revision` секции
  `route`; при рассинхроне `409` (у Uplinks адресация по имени, здесь по
  индексу — без guard reorder хрупок).
- **`default`-правило** — редактируется ограниченно (только `via`/fallback,
  без источников), неудаляемо, второй создать нельзя.
- **reorder** — отдельный endpoint `/control/routes/reorder`, а не move внутри
  PATCH.

## Модель данных: что такое `[[route]]`

Top-level массив таблиц в `config.toml` узла (не `[routing]`, не вложен в
`[outline]`). First-match-wins + ровно одно правило `default = true`. Схема
`RouteSection` (`bins/outline-ws-rust/src/config/schema.rs:716`,
`#[serde(deny_unknown_fields)]`), валидатор `load_routing_config`
(`config/load/routing.rs:22`). Поля правила (все `Option`):

| Поле | Тип | Назначение |
|------|-----|-----------|
| `prefixes` | `Vec<String>` | inline CIDR-префиксы |
| `file` / `files` | `PathBuf` / `Vec<PathBuf>` | файл(ы) CIDR-списка |
| `domains` | `Vec<String>` | inline доменные суффиксы |
| `domain_file` / `domain_files` | `PathBuf` / `Vec<PathBuf>` | файл(ы) доменов |
| `file_poll_secs` | `u64` | период опроса mtime (default 60) |
| `default` | `bool` | catch-all правило (ровно одно) |
| `via` | `String` | цель: имя группы / `"direct"` / `"drop"` |
| `fallback_via` / `fallback_direct` / `fallback_drop` | `String` / `bool` / `bool` | fallback, взаимоисключающие |
| `invert` | `bool` | матчит адреса НЕ из CIDR-набора (только CIDR, несовместимо с `domains`) |

Локальные инварианты правила (проверяет `load_routing_config`): у не-default
обязателен хотя бы один источник и непустой `via`; `default` без источников;
`invert` ⊕ `domains`; ≤1 fallback; `via`/`fallback_via` резолвятся в
`direct`/`drop` или имя объявленной `[[uplink_group]]`.

Правила секретов не содержат (в отличие от аплинков с `password`/`vless_id`) —
все поля можно показывать и отдавать в UI как есть.

## Архитектура

Четыре слоя: (A) data plane hot-swap, (B) control-endpoint узла, (C) прокси в
`outline-ui`, (D) фронт. Порядок изложения — снизу вверх.

### A. Data plane: горячая пересборка `RoutingTable`

**Как таблица держится сейчас** (`bootstrap/mod.rs:153-272`): компилируется один
раз в `Option<Arc<RoutingTable>>`. TUN получает свой клон `Arc<RoutingTable>`
(конкретный тип, `TunRouting::new`), SOCKS — свой клон как `Arc<dyn Router>`
(`ProxyConfig.router`). То есть **оба потребителя держат независимые `Arc` на
одну таблицу**. Подменить её «снаружи» невозможно: `Arc` неизменяем по
содержимому, `ArcSwap` есть только *внутри правил* (`CompiledRule.cidrs/domains`)
для hot-reload файлов, но не над таблицей целиком.

Внутри таблицы уже есть `version: AtomicU64` — механизм инвалидации кэшей
(UDP per-association route cache сравнивает версию, снятую при вставке, с
текущей; расхождение → повторный резолв). File-watcher бампает версию при
перезагрузке содержимого файлов.

**Что вводим — общая подменяемая обёртка** `SharedRoutingTable` в крейте
`crates/outline-routing` (чтобы её видели и `outline-tun`, и ws-rust):

```rust
pub struct SharedRoutingTable { current: ArcSwap<RoutingTable> }

impl SharedRoutingTable {
    pub fn new(table: RoutingTable) -> Arc<Self>;
    pub fn load_full(&self) -> Arc<RoutingTable>;      // для spawn_route_watchers
    /// Подменяет таблицу, СОХРАНЯЯ монотонность version.
    pub fn swap_preserving_version(&self, new: RoutingTable) -> Arc<RoutingTable>;
}

impl Router for SharedRoutingTable {
    fn version(&self) -> u64 { self.current.load().version() }
    fn resolve_versioned(&self, t: &TargetAddr) -> (RouteDecision, u64) {
        self.current.load().resolve_versioned(t)
    }
}
```

Резолв читает `current.load()` (дешёвый `arc_swap::Guard`, без локов и await —
сохраняем контракт `Router`: синхронный, на packet-path без await-точки).

**Монотонность version (критично для инвалидации кэша).** `RoutingTable::compile`
всегда создаёт `version = 0`. Если после подмены новая таблица начнёт с 0, а
потребитель кэшировал решение на версии 5 старой таблицы — сравнение может
пропустить инвалидацию. Поэтому `swap_preserving_version` **перед** `store`
выставляет новой таблице `version = old.version() + 1`:

```rust
pub fn swap_preserving_version(&self, mut new: RoutingTable) -> Arc<RoutingTable> {
    let next = self.current.load().version() + 1;
    *new.version.get_mut() = next;           // до публикации
    let arc = Arc::new(new);
    self.current.store(arc.clone());
    arc
}
```

Дальнейшие file-reload бампают уже `new.version` (со `next`), continuity
сохраняется. Подмена атомарна и видна **обоим** потребителям одновременно —
они теперь читают одну обёртку, а не два независимых `Arc`.

**File-watchers.** `spawn_route_watchers(Arc<RoutingTable>)` привязан к
конкретной таблице (клонирует `Arc<ArcSwap<..>>` каждого правила). После
подмены старые watchers указывают на ушедшую таблицу — их надо остановить и
поднять новые на новой. `RouteWatchersGuard` уже гасит задачи на drop. Значит
apply: `drop(old_guard)` → `spawn_route_watchers(new_arc)` → сохранить новый
guard. Guard живёт в `ApplyHandle` за `Mutex` (см. B).

**Изменения в потребителях:**

- `outline-tun::TunRouting` — держать `Option<Arc<SharedRoutingTable>>` вместо
  `Option<Arc<RoutingTable>>`; резолв через `.load()`/`Router`. Меняется
  сигнатура `TunRouting::new`.
- `proxy/router.rs` — `impl Router for SharedRoutingTable` (выше); в остальном
  трейт `Router` не меняется.
- `bootstrap/mod.rs` — создать `SharedRoutingTable::new(compile(..))`, раздать
  клоны в TUN, в `ProxyConfig.router` (`as Arc<dyn Router>`) и в `ApplyHandle`;
  первый `spawn_route_watchers(shared.load_full())`, guard передать в
  `ApplyHandle`.

### B. Control API узла: `routes_crud` + расширение `/control/apply`

**Новый модуль** `bins/outline-ws-rust/src/http/control/routes_crud/` по образцу
`uplinks_crud/` (io/list/mutate/payload), плюс ветка в `handle_request`
(`http/control/server.rs:126`). Все ответы — JSON; правка `config.toml` — через
`toml_edit::DocumentMut` (сохраняя комментарии/форматирование top-level
`[[route]]`), атомарная запись `fs_util::atomic_write` (0600), под общим
`config_write_lock`. Тело ≤1 MiB. Авторизация — bearer, как у всех control-роутов
(проверка до диспетчеризации).

Endpoints (`revision` — хэш секции `route`, оптимистичная блокировка):

- **`GET /control/routes`** →
  ```json
  {
    "routes": [
      { "index": 0, "is_default": false, "config": { "prefixes": ["10.0.0.0/8"], "via": "direct" } },
      { "index": 1, "is_default": true,  "config": { "default": true, "via": "main" } }
    ],
    "groups": ["main", "backup"],
    "revision": "<hex>"
  }
  ```
  `config` — TOML-таблица правила как JSON (`table_to_json`, как uplinks).
  `groups` — имена объявленных `[[uplink_group]]` (для `<select>` `via` и
  клиентской подсказки). `is_default` — вычисляемый флаг.
- **`POST /control/routes`** — создать. Body
  `{ rule: {<поля>}, at_index?: usize, revision }`. По умолчанию вставка перед
  `default` (или в конец, если секция пуста).
- **`PATCH /control/routes`** — заменить правило по индексу **целиком**. Body
  `{ index, rule: {<поля>}, revision }`. Полная замена (не merge): снятое в
  drawer поле должно исчезнуть с диска. `default`-правило: сервер отвергает
  попытку выставить ему источники или снять `default`.
- **`DELETE /control/routes`** — Body `{ index, revision }`. Удаление
  `default`-правила отвергается (`400`).
- **`POST /control/routes/reorder`** — Body `{ from, to, revision }`.

Ответ мутаций — `202 Accepted`, `{ action, index?, apply_required: true,
revision: "<new>" }`.

**Валидация на мутации** (staged-модель, как uplinks): проверяем **отдельное
правило** — round-trip как `RouteSection` + локальные инварианты (непустой
`via`, `invert`⊕`domains`, ≤1 fallback, не-default имеет источник, default без
источников). **Межправиловую согласованность** (ровно один `default`,
`via`→существующая группа) НЕ требуем на каждом шаге — она проверяется при
**Apply**, как `/control/apply` уже ре-валидирует весь файл для аплинков. Это
позволяет собирать routing с нуля по одному правилу. UI подсказывает
недостающий `default`/битый `via` заранее (данные для этого есть в `groups`),
но жёсткий гейт — Apply.

**Ошибки:** `400` (битый JSON/правило/локальный инвариант), `404` (индекс вне
диапазона), `409` (рассинхрон `revision`, либо нет `config_path`), `413`
(тело >1 MiB), `500` (I/O). Маппинг — как в `uplinks_crud`.

**Расширение `/control/apply`** (`http/control/apply.rs`). Сейчас под мьютексом:
перечитывает `config.toml` (`load_config`), применяет `new_config.groups`
(`registry.apply_new_groups`). Добавляем 3-й шаг: если объявлен routing —
`RoutingTable::compile(new_routing_cfg).await` → `shared.swap_preserving_version`
→ пересоздать watchers (drop old guard → spawn new → store guard в
`ApplyHandle`). Compile async (читает файлы) под тем же мьютексом — ок. Ошибка
compile/валидации → apply возвращает ошибку, старая таблица **остаётся**
(swap не выполнен). `ApplyResponse` дополняется `routes_applied`/`routes_count`.
`ApplyHandle` (`bootstrap/mod.rs:247`) получает поля:
`shared_routing: Option<Arc<SharedRoutingTable>>` и
`route_watchers: Mutex<Option<RouteWatchersGuard>>`.

Одна кнопка Apply применяет всё, что умеет hot (группы + routing), из текущего
`config.toml` — источник один, разделение вкладок Uplinks/Routing чисто
UI-условность. Dirty-состояние — общее per-instance.

### C. Прокси в `outline-ui` (Rust)

Новые роуты в `bins/outline-ui/src/ws/mod.rs::router` + хендлеры в `ws/api.rs`
(клоны `uplinks_proxy`/`apply_proxy`):

- `GET/POST/PATCH/DELETE /ws/dashboard/api/routes` → `routes_proxy` →
  `/control/routes`. GET несёт `instance` в query; мутации — envelope
  `{ instance, body }`.
- `POST /ws/dashboard/api/routes/reorder` → `/control/routes/reorder`.
- Apply переиспользуется существующий `/ws/dashboard/api/apply` (endpoint узла
  `/control/apply` теперь применяет и routing) — новый прокси не нужен.

`backend.rs` не меняется — токен узла инъектится серверно, браузер его не видит.

### D. Фронт (Svelte 5)

- **Навигация:** пункт «Routing» в `components/layout/Sidebar.svelte` под
  группой «Client · WS» (путь `/ws/routing`); ветка в `App.svelte` и предикат в
  `lib/router.svelte.ts` (`isRouting = path.startsWith('/ws/routing')`).
- **`features/ws/Routing.svelte`** — poll `/routes`; таблица правил **в порядке
  следования** с индексами; чипы матчеров (prefixes/files/domains/domain_files/
  invert/`file_poll_secs`) и цели (`via` + fallback); в строке — ↑/↓ (reorder),
  edit, delete; «Add rule». `default`-правило помечено, держится последним
  (catch-all: любое не-default правило после него мертво) и с ограниченными
  действиями — нельзя удалить, нельзя создать второе, новые правила вставляются
  перед ним. Баннер «pending changes» + кнопка «Apply now» (как в
  `Uplinks.svelte`), dirty делится с Uplinks per-instance.
- **`features/ws/RouteDrawer.svelte`** — форма правила, сгруппированная:
  *матчеры* (prefixes/domains/files/domain_files — построчные textarea; invert;
  file_poll_secs), *цель* (`via` — `<select>`: `groups ∪ {direct, drop}`),
  *fallback* (none/via-группа/direct/drop), для create — позиция вставки
  (`at_index`).
- **`lib/routeForm.ts`** — framework-free сборка/валидация payload
  (unit-тестируемо, как `uplinkForm.ts`): `RouteFormFields`, `emptyRouteFields`,
  `fieldsFromConfig`, `validateRouteForm`, `buildRoutePayload`.
- **`lib/types.ts`** — `RouteConfig`, `RouteEntry`, `RoutesListResponse`
  (`{ routes, groups, revision }`).
- **`lib/api.ts`** — `routesList(i)`, `routesMutate(method, i, body)`,
  `routesReorder(i, from, to, revision)`; переиспользуют `mutate()`-хелпер
  (заголовок `content-type` для origin-gate).

## Поток данных

1. Оператор выбирает инстанс → poll `/ws/dashboard/api/routes?instance=X` →
   таблица правил + `revision`.
2. Add/Edit/Delete/Reorder → мутация с текущим `revision` → узел пишет
   `config.toml` (staged, `202`), возвращает новый `revision`. UI помечает
   инстанс dirty, рефетчит список (обновляет `revision`).
3. Кнопка «Apply now» → `/ws/dashboard/api/apply` → узел перечитывает
   `config.toml`, hot-применяет группы **и** routing (пересборка + атомарная
   подмена `SharedRoutingTable` + пересоздание watchers). Dirty снимается.
4. Новый трафик резолвится по новой таблице; UDP per-association кэш
   инвалидируется бампнутой version.

## Обработка ошибок и конкурентность

- Валидация правила на узле → `400` с текстом → toast.
- Рассинхрон `revision` (фоновый poll/второй оператор успел записать) → `409`
  «конфиг изменился, обновите» → UI рефетчит и просит повторить.
- Недоступный узел не роняет страницу (как topology): ошибка в поле ответа.
- Apply с несогласованным staged (нет `default`, `via`→несуществующая группа) →
  `/control/apply` возвращает ошибку валидации, **таблица не подменяется**,
  dirty остаётся, toast с причиной.

## Тестирование

- **`outline-routing`**: `swap_preserving_version` (монотонность version через
  подмену), `Router for SharedRoutingTable` (резолв читает актуальную таблицу),
  повторный `spawn_route_watchers` на подменённой таблице.
- **`outline-ws-rust`**: тесты `routes_crud` (create/patch/delete/reorder,
  локальная валидация, сохранение комментариев `toml_edit`, `revision`-guard
  `409`, отказ на удаление/порчу `default`); тест расширенного `apply`
  (routing пересобирается и подменяется; битый routing не рушит старую таблицу).
  Раскладка тестов — `<dir>/tests/<basename>.rs`, без inline `#[cfg(test)]`.
- **`outline-ui` (Rust)**: тест `routes_proxy` (envelope, форвардинг query,
  инъекция токена — как `tests/` для uplinks).
- **Frontend**: unit-тесты `routeForm` (build/validate payload,
  fields↔config), как `uplinkForm.test.ts`.
- **CI-гейт** (`AGENTS.md`, строго по порядку): `cargo fmt --check` (явный
  список пакетов) → `cargo clippy --workspace --exclude sockudo-ws
  --all-targets --no-deps -D warnings` → `cargo test`; фронт — `pnpm test`.

## Документация

- `bins/outline-ui/README.md` и `README.ru.md` — строка про вкладку Routing
  (обе стороны синхронно).
- `bins/outline-ws-rust/README.md` и `README.ru.md` — отметить, что routing
  теперь hot-apply-ится через `/control/apply` (снять формулировку «requires a
  full restart» для routing в docstring `apply.rs` и в README).

## Риски и открытые вопросы

- **TUN — критичный путь.** Смена API `TunRouting` + чтение через `.load()` на
  каждый пакет. `arc_swap::load` дешёв, но per-packet — проверить, что нет
  регресса латентности/CPU на TUN-профиле (эталон — `mac-is-the-tunnel-client`,
  gre1/L2 в памяти парка). Если `load()` на hot-path окажется дорогим —
  рассмотреть кэш `Guard` на время обработки пачки пакетов.
- **Version continuity под нагрузкой.** Гонка «кэшировал по старой версии →
  подмена → следующий резолв видит новую» разобрана (seed до publish), но
  требует теста именно на UDP per-association кэше.
- **Порядок в `/control/apply`.** Группы и routing применяются под одним
  мьютексом; если compile routing упал — группы уже применены. Приемлемо
  (config единый, группы валидны), но зафиксировать: routing-compile идёт
  **после** успешного `apply_new_groups`, ошибка routing не откатывает группы,
  а только оставляет старую таблицу. Альтернатива (compile routing до apply
  групп, чтобы упасть раньше) — обсудить на ревью плана.
- **`toml_edit` и top-level `[[route]]`.** Убедиться, что вставка/удаление/
  перестановка элементов top-level array-of-tables сохраняет соседние
  комментарии (у аплинков массив вложен в `[outline]`; здесь — верхний
  уровень).
- **Пустой routing с нуля.** Первое правило в отсутствие секции `[[route]]`:
  как `toml_edit` создаёт массив; и UX «нет default» до первого Apply.
