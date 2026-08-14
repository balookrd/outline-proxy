# Вкладка редактирования конфига `uplink_groups` в `outline-ui` (дизайн)

Дата: 2026-08-14
Статус: согласовано в чате, ждёт вычитки владельцем

## Контекст

`outline-ui` — агрегирующий web-UI парка (`bins/outline-ui/`): отдаёт два
дашборда (`/ss`, `/ws`) и лендинг, сам data plane не несёт — только проксирует
к control API каждого узла, подставляя bearer-токен на своей стороне
(`backend.rs`, браузер токена не видит). См.
[`2026-08-12-outline-ui-dashboard-extraction-design.md`](2026-08-12-outline-ui-dashboard-extraction-design.md),
[`2026-08-12-outline-ui-svelte-rewrite-design.md`](2026-08-12-outline-ui-svelte-rewrite-design.md)
и свежий образец «редактор части `config.toml` через UI» —
[`2026-08-13-outline-ui-routing-tab-design.md`](2026-08-13-outline-ui-routing-tab-design.md).

WS-панель (клиент `outline-ws-rust`) сейчас несёт три вкладки: **Topology**
(`/ws`, read-view топологии + операции activate/reselect/on-off), **Uplinks**
(`/ws/uplinks`, CRUD аплинков `[[outline.uplinks]]`) и **Routing**
(`/ws/routing`, CRUD правил `[[route]]` с hot-apply). Обе редактирующие вкладки —
модель **staged → apply**: мутации пишут в `config.toml` узла (dirty), кнопка
«Apply now» зовёт `/control/apply`, который hot-применяет изменения без рестарта.

## Проблема

**Политику самих групп** (`[[uplink_group]]`: `mode`, `routing_scope`,
`reselect_*`, `probe`, RTT/loss-скоринг, failover-окна, keepalive) сейчас нельзя
править из UI **нигде** — только руками по SSH в `config.toml`. Соседние
представления группы **не редактируют**:

- **Uplinks** (`features/ws/Uplinks.svelte`) — группирует аплинки по полю
  `group` чисто визуально и правит **сами аплинки**; имя и политику группы не
  трогает, а группа без аплинков там вообще не отображается
  (`Uplinks.svelte:33-38`).
- **Topology** (`GroupTable.svelte`) — read-only: живой статус группы
  (mode/scope/failback-чипы, active count, RTT/loss). Не редактор.

Две особенности отличают группы от routing и **упрощают** объём:

1. **Hot-apply групп уже готов и уже в контуре `/control/apply`** —
   `handle_apply` перечитывает конфиг и свопит группы в живой `UplinkRegistry`
   через `registry.apply_new_groups` (`http/control/apply.rs:151`). Data plane
   дорабатывать **не нужно** — в отличие от routing, где потребовался
   `SharedRoutingTable` и пересборка таблицы. `restart_required` для групп = лишь
   «на узле не сконфигурирован apply-handle».
2. **CRUD-эндпоинта для самих групп нет.** `/control/uplinks` правит аплинки
   *внутри уже существующих* групп (`find_group_mut` → 404, если группы нет).
   Создать/удалить/перенастроить `[[uplink_group]]` control API не умеет.

## Цель

Добавить в WS-панель вкладку **Uplink groups** (`/ws/groups`) —
структурированный CRUD-редактор секций `[[uplink_group]]` (типизированная форма:
ключевые поля сразу + свёрнутые «Advanced») с кнопкой **Apply**, применяющей
изменения **без рестарта узла**, точно как Uplinks/Routing. Нужен новый
control-эндпоинт узла `/control/uplink_groups`, прокси в `outline-ui` и Svelte-
вкладка. `/control/apply` **не трогаем** — группы уже применяются.

## Зафиксированные в брейншторме решения

- **Форма редактора** — типизированный CRUD: ключевые поля видны сразу, редкие
  ~50 полей — в свёрнутых `<details>` «Advanced». Не raw-TOML и не полная форма
  на все поля.
- **Объём CRUD** — полный (create / edit-policy / delete), как Uplinks/Routing.
- **Группа ↔ аплинки — строго (identity):**
  - имя группы **неизменяемо**: `PATCH` правит только политику, «переименование»
    = создать новую + перенести аплинки руками;
  - **delete** разрешён только для **пустой** группы (`uplink_count == 0`);
    непустую сервер отвергает (409), кнопка Delete в UI задизейблена с тултипом;
  - **create** пустой группы разрешён (стейдж) — иначе аплинк не привязать
    (`uplinks_crud` требует существующую группу); UI подсказывает добавить
    аплинки во вкладке Uplinks до Apply.
- **Применение** — модель staged → explicit **Apply now** (одна кнопка на
  инстанс), не auto-apply после каждой мутации.
- **Reorder групп** — есть (косметика порядка в конфиге; на поведение не влияет,
  группы выбираются routing-правилом `via`). Отдельный endpoint
  `/control/uplink_groups/reorder`, drag + ↑/↓ в UI — как у аплинков.
- **Конкурентность** — без `revision`-guard: адресация по `name` стабильна,
  last-write-wins на одной группе (тот же trade-off, что у `uplinks_crud`, где
  revision тоже нет). Разные группы правятся независимо.

## Модель данных: что такое `[[uplink_group]]`

Top-level массив таблиц в `config.toml` узла (не под `[outline]`). Схема
`UplinkGroupSection` (`bins/outline-ws-rust/src/config/schema.rs:538-705`,
`#[serde(deny_unknown_fields)]`). Аплинки — отдельная секция
`[[outline.uplinks]]` с полем `group` (`schema.rs:405`), ссылающимся на
`uplink_group.name`.

**Секретов группа не содержит** (в отличие от аплинков с `password`/`vless_id`)
— чистая политика LB/health/reselect; все поля можно показывать и отдавать в UI
как есть.

Enum'ы для дропдаунов (`crates/outline-uplink/src/config.rs`):
`LoadBalancingMode` (`active_active`/`active_passive`, `:1136`), `RoutingScope`
(`per_flow`/`per_uplink`/`per_client`/`global`, `:1143`).

**Ключевые поля** (видны в форме сразу):

| Поле | Назначение |
|------|-----------|
| `name` | имя группы (identity, только create) |
| `mode` | `LoadBalancingMode` |
| `routing_scope` | `RoutingScope` |
| `warm_standby_tcp` / `warm_standby_udp` | тёплый резерв |
| `shared_resume` | общий resume-id (mesh-кластер), для soft-switch |
| `reselect_at` / `reselect_interval` / `reselect_sync` | плановый перевыбор (под-секция) |

**Advanced-категории** (свёрнутые `<details>`, полный перечень полей —
`schema.rs:538-705`): *Scoring* (`rtt_ewma_*`, `loss_*`, `failure_penalty_*`);
*Failover* (`sticky_ttl_secs`, `hysteresis_ms`, `failure_cooldown_secs`,
`tcp_chunk0_failover_timeout_secs`, `mode_downgrade_secs`,
`carrier_degraded_failover_secs`, `loss_failover_ratio`, `loss_failover_secs`,
`*_failure_window_secs`, `global_udp_strict_health`, `auto_failback`,
`health_weighted_selection`, `health_weight_floor`); *Keepalive* (keepalive-
таймеры); *TUN при dead-группе* (`tun_suppress_icmp_reply_when_down`,
`tun_icmp_liveness_window_secs`, `bypass_when_down`, `tun_wire_dial`); *VLESS UDP
mux* (`vless_udp_*`); *TCP mid-session retry* (`tcp_mid_session_retry_*`,
`tcp_symmetric_replay_*`); *Probe override* (`ProbeSection` — переопределение
верхнеуровневого `[probe]`).

**Инварианты валидации** (существующие загрузчики):

- **Набор групп** (`config/load/groups.rs:40-109`): ≤64 групп
  (`MAX_UPLINK_GROUPS`), непустое `name`, `name ∉ {direct, drop}`, уникальность
  имён, ≥1 аплинк на группу, каждый аплинк ссылается на существующую группу.
- **LB/reselect одной группы** (`config/load/balancing.rs:44-75`):
  `loss_failover_ratio ∈ [0,1]`; `reselect_at` ⊕ `reselect_interval`
  (взаимоисключающи); reselect требует `mode = active_passive` И
  `routing_scope ∈ {global, per_uplink}`; `reselect_sync` требует `reselect_at`;
  `reselect_interval` ≥ 60s; `reselect_at` формата `"HH:MM"`.

Из инвариантов **внутригрупповые** (LB/reselect, имя) проверяемы на **одной**
группе → гейтятся на мутации. **Межгрупповые** (≥1 аплинк, ссылки аплинков)
проверяются при **Apply**, как у routing — это и позволяет создать пустую группу
и наполнить её аплинками отдельным шагом.

## Архитектура

Три слоя (routing-у нужен был четвёртый — data plane hot-swap; группам он не
нужен): (A) control-эндпоинт узла, (B) прокси в `outline-ui`, (C) фронт. Порядок
изложения — снизу вверх.

### A. Control API узла: `groups_crud` (Apply не трогаем)

**Новый модуль** `bins/outline-ws-rust/src/http/control/groups_crud/` по образцу
**`uplinks_crud/`** (named-entry, адресация по `name`), а не index-addressed
`routes_crud`. Файлы `mod.rs` (диспетч по методу), `list.rs`, `mutate.rs`,
`payload.rs`. Правка `config.toml` — через `toml_edit::DocumentMut` (сохраняя
комментарии/форматирование top-level `[[uplink_group]]`), атомарная запись 0600
(`write_document_atomic`), под общим `config_write_lock`. Общие хелперы —
существующий `config_edit.rs` (`read_json`, `write_document_atomic`,
`table_to_json`, `status_for_mutator_error`). Тело ≤1 MiB. Авторизация — bearer,
как у всех control-роутов. Регистрация: путь `/control/uplink_groups` в
`http/control/server.rs` (label_path + диспетч), `mod groups_crud;` в
`control/mod.rs`.

Endpoints (named-entry по `name`, без `revision`-guard — как `uplinks_crud`):

- **`GET /control/uplink_groups`** →
  ```json
  {
    "groups": [
      { "name": "main",   "uplink_count": 2, "config": { "mode": "active_active", "routing_scope": "per_flow" } },
      { "name": "backup", "uplink_count": 0, "config": { "mode": "active_passive", "routing_scope": "global" } }
    ]
  }
  ```
  `config` — TOML-таблица группы как JSON (`table_to_json`). `uplink_count` —
  число `[[outline.uplinks]]` с `group == name` (нужен фронту для строгой
  политики Delete и подсказки про пустую группу).
- **`POST /control/uplink_groups`** — создать. Body `{ group: {<поля>} }`.
  Создаётся пустая (без аплинков) группа.
- **`PATCH /control/uplink_groups`** — заменить политику по имени. Body
  `{ name, patch: {<поля>} }`. Имя не меняется (identity).
- **`DELETE /control/uplink_groups`** — Body `{ name }`. Отказ 409, если
  `uplink_count > 0` («group "X" has N uplinks; remove them first»).
- **`POST /control/uplink_groups/reorder`** — Body `{ name, to }`. Переставляет
  группу на позицию `to` в массиве (по образцу аплинков; переназначает
  `position()`-слоты toml_edit — иначе тихий no-op, фикс `01919141`).

Ответ мутаций — `202 Accepted`, `{ action, name, apply_required: true,
restart_required: bool }`, где `restart_required = state.apply.is_none()`.

**Валидация на мутации** (staged-модель): проверяем **отдельную группу** —
внутригрупповые инварианты через переиспользуемый валидатор
`load_balancing_config_from_group` (`config/load/groups.rs:176-233`; reselect/LB/
диапазоны) + имя-инварианты (непустое, `∉ {direct, drop}`, уникальность на
диске, лимит 64). Валидатор и `UplinkGroupSection` re-export'ятся за
`#[cfg(feature = "control")]` в `config/mod.rs` — ровно как `load_routing_config`
для routing (коммит `986456b2`). **Межгрупповую согласованность** (≥1 аплинк,
ссылки аплинков) на мутации НЕ требуем — она проверяется при Apply.

**Ошибки:** `400` (битый JSON/поле/внутригрупповой инвариант), `404` (нет группы
с таким именем — для PATCH/DELETE), `409` (нет `config_path`; delete непустой
группы; имя уже занято при create), `413` (тело >1 MiB), `500` (I/O). Маппинг —
как в `uplinks_crud`.

**`/control/apply` не меняется.** Группы уже свопаются
(`registry.apply_new_groups`), `ApplyResponse { applied, groups, total_uplinks,
default_group, … }` уже несёт нужные счётчики. Никакого нового поля/шага, в
отличие от routing-спеки.

### B. Прокси в `outline-ui` (Rust)

Новые роуты в `bins/outline-ui/src/ws/mod.rs::router` + хендлер в `ws/api.rs`
(клон `uplinks_proxy`):

- `GET/POST/PATCH/DELETE /ws/dashboard/api/groups` → `groups_proxy` →
  `proxy_crud(..., "/control/uplink_groups")`. GET несёт `instance` в query;
  мутации — envelope `{ instance, body }` (общий `ProxyEnvelope`).
- Apply переиспользует существующий `/ws/dashboard/api/apply` — **нового прокси
  не нужно**. `backend.rs` не меняется (токен инъектится серверно).

### C. Фронт (Svelte 5)

- **Навигация:** пункт «Uplink groups» в `components/layout/Sidebar.svelte`
  (путь `/ws/groups`, рядом с Uplinks/Routing); ветка в `App.svelte` + предикат
  `isGroups = path.startsWith('/ws/groups')`. Роутер уже относит `/ws/*` к
  секции ws.
- **`features/ws/UplinkGroups.svelte`** — poll `/groups`; таблица групп (name ·
  `N uplinks` · чипы политики mode/scope/reselect/probe · Edit/Delete); «Add
  group»; `Delete` задизейблен при `uplink_count > 0` с тултипом. Баннер
  «pending changes» + «Apply now» (см. ниже), dirty — per-instance
  `SvelteSet<string>` (как `Uplinks.svelte:63`).
- **`features/ws/GroupDrawer.svelte`** — форма группы (образец —
  `UplinkDrawer.svelte`): ключевые поля сразу (Name только create, Mode, Routing
  scope, warm_standby_tcp/udp, `shared_resume`, **Reselect** — под-секция: режим
  `at[]` ⊕ `interval` + чекбокс `sync`, клиентская валидация зависимостей);
  свёрнутые `<details>` «Advanced» по категориям из «Модель данных».
- **`lib/groupForm.ts`** (+ `groupForm.test.ts`) — framework-free сборка/
  валидация payload (unit-тестируемо, как `uplinkForm.ts`/`routeForm.ts`):
  `GroupFormFields`, `emptyGroupFields`, `fieldsFromConfig`, `validateGroupForm`
  (зеркалит серверную валидацию reselect/LB для мгновенной обратной связи),
  `buildGroupPayload` (эмитит только непустые поля).
- **`lib/types.ts`** — `GroupConfig`, `GroupEntry` (`{ name, uplink_count,
  config }`), `GroupsListResponse` (`{ groups }`), `GroupMutationResponse`.
- **`lib/api.ts`** — `groupsList(i)`, `groupsMutate(method, i, body)`
  (клоны `uplinksList`/`uplinksMutate`; используют `mutate()`-хелпер с заголовком
  `content-type` для origin-gate).

## Apply: кнопка и реализация

Модель — **staged → explicit apply**, как Uplinks/Routing (осознанно, не
auto-apply): пустая только что созданная группа не роняет процесс в момент
создания.

- **Одна кнопка `Apply now` на инстанс** (не per-group): `/control/apply`
  перечитывает весь конфиг и свопит **весь** набор групп разом
  (`apply_new_groups`) — «применить одну группу» невозможно в принципе.
  Показывается в applybar, пока инстанс dirty.
- **Новый код — только во фронте** (`applyNow`-хендлер + applybar в
  `UplinkGroups.svelte`). Прокси `apply` (`api.ts:56`, `apply_proxy`) и
  эндпоинт узла `handle_apply` **уже существуют и уже применяют группы** — их не
  трогаем.
- **Honest feedback** по `ApplyResponse`, три кейса:
  1. **успех** → toast «Applied: N groups, M uplinks live», снять dirty, refresh;
  2. **пустая группа** — `handle_apply` перечитает конфиг, `load_config` упадёт
     на инварианте «≥1 аплинк на группу» (`groups.rs:105`) → 4xx `{error}`,
     dirty **не снимается**; превентивно applybar показывает
     «Group X has no uplinks — add them in the Uplinks tab before applying» (у
     нас есть `uplink_count` из list-ответа);
  3. **restart required** — если на узле нет apply-handle, `/control/apply` →
     `409` (`server.rs:194`), toast «changes staged; node restart required». Для
     групп это **единственный** restart-кейс: нет routing-развилки «применилось
     частично» (`routes_applied != null`), живые группы свопаются всегда, когда
     apply-handle жив.

## Поток данных

1. Оператор выбирает инстанс → poll `/ws/dashboard/api/groups?instance=X` →
   таблица групп.
2. Add/Edit-policy/Delete → мутация по имени → узел пишет `config.toml`
   (staged, `202`). UI помечает инстанс dirty, рефетчит список.
3. «Apply now» → `/ws/dashboard/api/apply` → узел перечитывает `config.toml`,
   hot-применяет группы (`apply_new_groups`). Dirty снимается.
4. Наполнение новой группы аплинками — во вкладке **Uplinks**
   (`/control/uplinks`), которая теперь находит только что созданную группу на
   диске; Apply там же (dirty — общий per-instance).

## Обработка ошибок и конкурентность

- Внутригрупповой инвариант на узле (битый reselect, mode/scope) → `400` с
  текстом → toast; клиентская валидация `validateGroupForm` предупреждает
  заранее (в т.ч. «reselect требует active_passive + global/per_uplink»).
- Конкурентная правка одной группы — last-write-wins (без `revision`, как
  `uplinks_crud`); разные группы правятся независимо (адресация по `name`).
- Delete непустой группы → `409` (сервер) + задизейбленная кнопка (клиент,
  превентивно).
- Недоступный узел не роняет страницу: ошибка в поле ответа (как topology).
- Apply c несогласованным staged (пустая группа) → ошибка валидации, группы **не
  подменяются**, dirty остаётся, toast с причиной.

## Тестирование

- **`outline-ws-rust`**: тесты `groups_crud/tests/{mutate,payload}.rs`
  (create/patch-policy/delete; сохранение комментариев `toml_edit` top-level
  `[[uplink_group]]`; delete непустой → `409`; reserved-
  имя/дубликат/лимит 64; reselect-инварианты: `at ⊕ interval`, `sync` требует
  `at`, требование `active_passive` + scope). Раскладка — `<dir>/tests/<basename>.rs`,
  без inline `#[cfg(test)]`.
- **`outline-ui` (Rust)**: тест `groups_proxy` в `ws/tests/` (envelope,
  форвардинг query, инъекция токена — как для uplinks/routes).
- **Frontend**: unit-тесты `groupForm` (build/validate payload, fields↔config;
  зеркало reselect-инвариантов), как `uplinkForm.test.ts`.
- **CI-гейт** (`AGENTS.md`, строго по порядку): `cargo fmt --check` (явный
  список пакетов) → `cargo clippy --workspace --exclude sockudo-ws
  --all-targets --no-deps -- -D warnings` → `cargo test --workspace --exclude
  sockudo-ws`; фронт — `pnpm test`.

## Документация (EN/RU синхронно)

- `bins/outline-ui/README.md` / `README.ru.md` — строка про вкладку Uplink groups.
- `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md` / `.ru.md` — новый CRUD-
  эндпоинт групп `/control/uplink_groups` и модель staged → apply для групп.

## Развёртывание

- Bump тега образа в `ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml`
  (`1.0.3` → `1.0.4`; тег образа живёт отдельно от `Cargo.toml` version 0.2.0).
- **Сам деплой в кластер не входит в объём** — только код; раскатка (pnpm build →
  zigbuild → docker → push → kubectl) по отдельной команде владельца.

## Риски и открытые вопросы

- **Валидатор одиночной группы.** `load_balancing_config_from_group` берёт
  `UplinkGroupSection` и валидирует LB/reselect — подтвердить при реализации, что
  его можно вызвать на секции, собранной из `toml_edit`, без построения целого
  `ConfigFile` (routing так делает с `load_routing_config`). Имя-инварианты
  (reserved/уникальность/лимит) — вынести/продублировать в `groups_crud`, т.к.
  они живут в `load_groups`, а не в per-group валидаторе.
- **Типы `shared_resume` / `reselect_sync`.** Уточнить точную форму (bool vs
  структура) по `schema.rs:538-705` при реализации формы и payload — от этого
  зависит контрол в drawer и поле в `GroupPayload`.
- **reselect требует `active_passive`.** Форма с reselect при `active_active`
  будет отвергнута сервером; клиентская валидация обязана предупредить до
  Apply, иначе оператор застейджит невалидную группу и упрётся в ошибку Apply.
- **`toml_edit` и top-level `[[uplink_group]]`.** Убедиться, что вставка/удаление
  элементов top-level array-of-tables сохраняет соседние комментарии (у аплинков
  массив вложен в `[outline]`; здесь — верхний уровень, как `[[route]]`).
- **Пустая группа в UI.** UX «создал группу → она пустая → Apply падает» смягчён
  превентивной подсказкой и переходом в Uplinks; проверить, что подсказка
  снимается, как только `uplink_count > 0`.
- **Объём Advanced-полей.** ~50 редких полей — риск раздувания `groupForm.ts` и
  drawer; план должен разложить их по категориям и, где полей группы > разумного,
  свернуть агрессивно (числовые — с placeholder «default», пустые не эмитятся).
