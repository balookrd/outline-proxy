# Переписывание `outline-ui` на Svelte 5 (дизайн)

Дата: 2026-08-12
Статус: согласовано в чате, ждёт вычитки владельцем

## Контекст

Дашборды уже отцеплены от data plane и живут одним сервисом `bins/outline-ui`
(см. [`2026-08-12-outline-ui-dashboard-extraction-design.md`](2026-08-12-outline-ui-dashboard-extraction-design.md)).
Сервис отдаёт два дашборда и лендинг, а сам не держит состояния: он только
проксирует к control API каждого узла, подставляя bearer-токен на своей стороне.

Представление сейчас — три «ванильных» HTML-файла, вшитых через `include_str!`:

- `bins/outline-ui/src/ss/dashboard.html` (~1282 строки) — управление юзерами;
- `bins/outline-ui/src/ws/dashboard.html` (~1560) — топология аплинков, потери
  носителя, операции;
- `bins/outline-ui/src/ws/uplinks.html` (~644) — CRUD аплинков;
- плюс `bins/outline-ui/src/index.html` — лендинг.

Итого ~3.5k строк разметки, стилей и логики в одном `<script>` на файл, без
типов, компонентов и переиспользования.

## Проблема

Дашборды разрослись до операторских инструментов, а инструментов у них нет.
Топология WS несёт нетривиальную логику (`wireChain`, `groupFingerprint`,
`activeDeco`, `lossTag`, active tcp/udp) в одном инлайн-скрипте — её нельзя
разложить на компоненты, покрыть типами или переиспользовать между страницами.
Любая правка — это ручной DOM без границ и без проверок.

Цель — переписать оба дашборда на современный компонентный фронтенд (Svelte 5),
сохранив backend, его гейты и весь API-контракт, и не притащив в сервис
мониторинг, которому здесь не место.

## Границы работы

**В scope — ровно то, для чего есть данные в control API:**

- **SS-панель** (`/ss`): список и CRUD юзеров (`/control/users`), block/unblock.
- **WS-панель** (`/ws`): топология аплинков и операции
  (`activate`/`reselect`/`set_enabled`/`apply`, CRUD `uplinks`).

**Не-цели (сознательно):**

- Никакого мониторинга: KPI трафика, per-connection таблиц, аналитики трафика за
  период, live-логов, CPU/RAM по серверам. Этих данных нет в control API, а
  история и графики уже живут в Grafana + VictoriaMetrics в k3s. Дублировать их в
  `outline-ui` не будем.
- Никакого нового источника данных (Prometheus/VictoriaMetrics API в UI не
  вводим).
- Никакого WebSocket-push: backend работает опросом (fan-out к control API,
  `refresh_interval_secs`), и это остаётся моделью.
- Backend не переписываем: API-хендлеры, гейты, конфиг, клиент к control API —
  без изменений по контракту.

## Решения

**Scope — порт двух панелей.** Переписываем существующую функциональность, не
расширяя её в сторону мониторинга. Мониторинг остаётся в Grafana; ссылки на него
в UI пока не заводим (в текущих дашбордах их и нет).

**Стек — YAGNI-минимум.** Svelte 5 + TypeScript + Vite + Tailwind CSS +
shadcn-svelte + Lucide. Данные — нативный `fetch` + polling на runes
(`$state`/`$derived`/`$effect`). TanStack Table подключаем **только** там, где
реально нужны сортировка и фильтрация — в таблице юзеров. Без ECharts (нечего
рисовать — истории нет), без TanStack Query (для двух панелей опрос тривиален),
без виртуализации (юзеров десятки, не тысячи). SvelteKit не берём: SSR и файловый
роутинг не нужны, а embed усложняют без выгоды.

**Структура фронта — единый бандл.** Один Vite-проект, один `dist/`, клиентский
роутер, общий shell/тема/примитивы. Монтируется под `/`, `/ss`, `/ws`. Это даёт
максимальный шаринг кода между панелями против двух отдельных бандлов с
дублированием shell.

**Сборка — embed за feature-флагом + отдельный CI-job.** Собранный `dist/`
вшивается в бинарь через `rust-embed` за feature `embed-assets`. Дефолтная
`cargo`-сборка (текущий Rust-гейт, без node) фичу не включает и отдаёт заглушку,
поэтому гейт остаётся зелёным без node-тулчейна. Release/Docker собирается с
`--features embed-assets`. Фронтенд проверяется отдельным CI-job. Dev — Vite
dev-server с proxy на запущенный Axum.

**WS-топология — паритет операций, свобода подачи.** Сохраняем все действия и все
данные текущего WS-дашборда; визуальную подачу топологии можно переработать ради
ясности. SS-панель переносим близко к текущей.

**Замена — big-bang.** Оба дашборда переписываются в одном изменении; старые
`.html` и шаблонизатор `__BASE__` удаляются. Поэтапного «SS сейчас, WS потом» не
делаем.

## Архитектура

### Что меняется, что нет

Меняется только слой представления. Backend `outline-ui` сохраняется целиком:
Axum, два гейта (`origin` inner + `auth` outer, оба до роутинга — см.
`bins/outline-ui/src/main.rs`), per-instance токены на стороне сервера, отказ от
раскрытия `control_url` браузеру, stateless-процесс, polling-модель.

Весь API-контракт остаётся 1:1 и покрыт существующими тестами:

- SS: `GET …/api/instances`, `GET|POST …/api/users`,
  `PATCH|DELETE …/api/users/{id}`, `POST …/api/users/{id}/block|unblock`.
- WS: `GET …/api/instances`, `GET …/api/topology`, `POST …/api/activate`,
  `POST …/api/set_enabled`, `POST …/api/reselect`,
  `GET|POST|PATCH|DELETE …/api/uplinks`, `POST …/api/apply`.

### Роуты: что удаляется, остаётся, добавляется

- **Удаляются** HTML-роуты представления: `…/dashboard` (обе панели),
  `…/dashboard/uplinks`, отдельная отдача `outline-logo.png` (лого едет внутри
  бандла как обычный ассет), и шаблонизация
  `__BASE__`/`__DASHBOARD_REFRESH_MS__` в `bins/outline-ui/src/assets.rs`.
- **Остаются** все `…/dashboard/api/*` (контракт не трогаем).
- **Добавляются** только роуты отдачи SPA:
  - статические ассеты бандла на общем абсолютном префиксе (например
    `/ui-assets/*`), **вне** `nest("/ws")`/`nest("/ss")` — чтобы один `index.html`
    работал и под `/ss`, и под `/ws`. Vite собирается с `base`, указывающим на
    этот префикс;
  - SPA-fallback: любой не-API и не-asset путь (`/`, `/ss/*`, `/ws/*`) отдаёт
    `index.html`, чтобы перезагрузка вложенного маршрута не давала 404.

Оба новых роута отдают контент из `rust-embed` за feature `embed-assets`; без
фичи — заглушка (короткий `index` с явным сообщением «assets not embedded»),
которая не паникует.

### Capability

Никакого нового backend-эндпоинта. «Доступность панели» определяется так же, как
сейчас, — непустыми `[[ws.instances]]`/`[[ss.instances]]` в конфиге
(`bins/outline-ui/src/config.rs`). Лендинг `/` опрашивает
`/ss/dashboard/api/instances` и `/ws/dashboard/api/instances`; успешный непустой
ответ → панель показывается. Интервал опроса SPA берёт из `refresh_interval_secs`,
который эти эндпоинты уже отдают.

### Поток данных

REST = состояние, polling = обновление. Каждая мутация (создать юзера, activate,
apply и т.д.) → повторный `fetch` затронутого ресурса. Инвариант «один мёртвый
узел не гасит страницу» сохраняется: `topology` уже отдаёт пофайловый
`{ok:false, error}`, UI показывает, какой узел отвалился.

## Структура проекта

```
bins/outline-ui/
├── Cargo.toml                # + rust-embed (optional), feature "embed-assets"
├── Dockerfile                # multi-stage: node(vite build) → rust(zigbuild) → scratch
├── frontend/                 # новый Vite + Svelte 5 проект
│   ├── package.json, vite.config.ts, tsconfig.json, svelte.config.js
│   ├── tailwind.config / postcss
│   ├── index.html
│   ├── dist/                 # билд-артефакт — .gitignore
│   └── src/
│       ├── app/              # Shell (Sidebar + Header), тема, маунт роутера
│       ├── routes/           # / (лендинг-capability), /ss, /ws, /ws/uplinks
│       ├── lib/
│       │   ├── api.ts        # тонкий REST-клиент к …/dashboard/api/* (обе базы)
│       │   ├── poll.svelte.ts# runes-поллер: интервал из refresh, пауза по visibility
│       │   ├── types.ts      # типы ответов (User, Topology, Uplink, …)
│       │   └── format.ts     # rtt / loss% / времена
│       ├── components/
│       │   ├── ui/           # shadcn-svelte примитивы
│       │   └── layout/       # InstanceSelector, StatusDot, ErrorBanner
│       └── features/
│           ├── ss/           # UsersTable, UserForm, block/unblock, delete-confirm
│           └── ws/           # Topology, операции, UplinksCrud
└── src/                      # Rust: без изменений по контракту, кроме assets.rs
```

## Компоненты фронта

Каждый юнит — одна ответственность, тестируется изолированно.

- **`lib/api.ts`** — знает только пути `…/dashboard/api/*` и базу (`/ss` или
  `/ws`); возвращает типизированные ответы или ошибку. Ничего не рендерит.
- **`lib/poll.svelte.ts`** — оборачивает fetch в интервал из
  `refresh_interval_secs`, ставит опрос на паузу, когда вкладка скрыта.
- **`components/ui/*`** — примитивы shadcn-svelte (Button, Badge, Card, Dialog,
  Table, Toast, Tooltip, DropdownMenu, Select, Skeleton).
- **`features/ss`** — `UsersTable` (TanStack Table: сортировка/фильтр), `UserForm`
  в Dialog (create/edit), block/unblock, delete с подтверждением,
  инстанс-селектор.
- **`features/ws`** — представление топологии (группы → аплинки → wire, active
  tcp/udp, потери носителя, rtt, probe), операции
  `activate(soft)`/`reselect`/`set_enabled`/`apply`, `UplinksCrud` (перенос
  `uplinks.html`), инстанс-селектор.

## Сборка, CI, Dockerfile

**Cargo.** `rust-embed` — optional-зависимость под feature `embed-assets`.
`assets.rs` за фичей отдаёт embedded `frontend/dist`, без фичи — заглушку.

**Dev.** Vite dev-server отдаёт фронт с HMR и проксирует `/ss`, `/ws`,
`/ui-assets` на локально запущенный `cargo run -p outline-ui`.

**CI.** Новый job `frontend`: `pnpm install` → `svelte-check` (типы, обязателен) →
lint (prettier/eslint) → `vite build`. Существующие Rust-джобы не трогаем: они
собирают без node, потому что embed за фичей, а дефолт её не включает.

**Dockerfile** (остаётся `FROM scratch` на выходе):

1. node-stage: `pnpm install && pnpm build` → `frontend/dist`;
2. rust-stage:
   `cargo zigbuild --release -p outline-ui --features embed-assets --target aarch64-unknown-linux-musl`
   с `dist/` из stage 1;
3. `FROM scratch`: копируется только бинарь — образ по-прежнему = сервис.

**`.gitignore`:** `frontend/dist`, `frontend/node_modules`.

## Обработка ошибок

- Сетевые/502 от backend → toast + `ErrorBanner`, без обнуления страницы.
- Пофайловая ошибка узла в `topology` → значок и текст «узел недоступен» рядом с
  узлом.
- Вход остаётся браузерным (гейт `auth`, `Basic`/`Bearer`); SPA ходит с уже
  установленными кредами. На 401 показываем понятное сообщение, а не пустой
  экран.

## Тестирование

- **Rust.** Существующие тесты API/routing/origin/auth/config остаются зелёными
  (контракт не меняем). Добавляем: тест asset-роута и SPA-fallback; тест
  поведения **без** `embed-assets` (заглушка не паникует, отдаёт понятный ответ).
  Тест-на-плейсхолдеры (`__BASE__` не доживает до ответа) удаляется вместе с
  шаблонизатором.
- **Фронт.** `svelte-check` в гейте обязателен. `vitest` — только на `format.ts`
  и `api.ts`; без тяжёлого компонентного слоя (YAGNI).
- **Приёмка — чек-лист паритета операций:** SS `create/edit/delete/block/unblock`;
  WS `activate(soft)/reselect/set_enabled/apply/uplinks CRUD`. Ни одна операция не
  теряется.

## Выкатка и миграция

Big-bang в одном изменении: 4 старых `.html` удаляются, шаблонизатор `__BASE__`
уходит. Версия крейта бампается. Деплой — по существующей процедуре:
`cargo zigbuild --release -p outline-ui --features embed-assets --target aarch64-unknown-linux-musl`
→ `docker build`/`push` → `kubectl -n monitoring rollout restart deploy/outline-ui`.
Конфиг ConfigMap и секреты не меняются.

## Документация

Обновляем обе стороны EN/RU (`bins/outline-ui/README.md` и `README.ru.md`):
dev-режим (Vite dev-server + proxy), сборка с `--features embed-assets`, новый
CI-job, multi-stage Dockerfile. Спека и план — по-русски в `docs/superpowers/`.

## Инварианты (не нарушать)

- Два гейта (`origin` + `auth`) до маршрутизации; новые роуты отдачи ассетов
  сидят **под** обоими слоями, как и всё остальное.
- Per-instance токены только на стороне сервера; `control_url` браузеру не
  раскрывается; `list_instances` отдаёт лишь имена.
- Процесс stateless: на диск не пишем, своих секретов не храним.
- Единый self-contained musl-бинарь на `scratch`: фронт **вшит** в бинарь, не
  отдаётся с диска, образ не обрастает файловой системой.
- Bounded resources: поллер имеет интервал и паузу по visibility; никаких
  неограниченных таймеров/сокетов на фронте.
- Документация EN/RU обновляется в одном изменении; спеки/планы —
  по-русски.

## Дизайн-токены (согласовано прототипом 2026-08-12)

Визуальный эталон — [`2026-08-12-outline-ui-svelte-rewrite-prototype.html`](2026-08-12-outline-ui-svelte-rewrite-prototype.html)
(статический мокап всех четырёх экранов). Токены выведены через `ui-ux-pro-max`
(dark-ops) и одобрены в чате.

- **Тема.** Тёмная по умолчанию, светлая — переключателем; системная через
  `prefers-color-scheme`. Один акцент.
- **Палитра (dark).** Фон `#020617`, поверхности `#0b1220`/`#0f172a`/`#1e293b`,
  border `#26324a`/`#1c2740`, текст `#f8fafc`/`#94a3b8`/`#64748b`. Семантика:
  accent/healthy `#22c55e`, warn `#f59e0b`, danger/down/blocked `#ef4444`,
  info `#38bdf8`, wire-xhttp `#a78bfa`. Светлая тема — параллельный набор тех же
  ролей (см. `:root[data-theme="light"]` в прототипе).
- **Типографика.** UI — Fira Sans; моно — Fira Code (IP, RTT, wire-chain, ключи,
  веса; `tabular-nums`). Шрифты **вшиваются** в бандл (woff2-subset, лицензия
  OFL) — в проде не Google CDN, чтобы не пробивать self-contained-модель и CSP.
- **Плотность.** Density 8 (дашборд): шкала отступов 4/8/12/16/24/32px.
- **Подача WS-топологии** (закрывает «свободу подачи»): карточка инстанса →
  группа (чипы конфигурации `cluster`/`padding` + «N active» + «Reselect») →
  строки аплинков в **жёстком grid** (единый шаблон колонок для заголовка и
  строк, крайние колонки фиксированной ширины — иначе `auto`-хвост разъезжается).
  Колонки: Uplink/endpoint, Role, Status (`Active`/`Ready`/`Down`/`Disabled`),
  TCP wire chain, UDP wire chain, RTT, Loss·Weight, Action. Wire-chain — цветные
  моно-пилюли (`h3`/`h2`/`ws`/`xhttp`/`direct`) со стрелками и подсветкой
  активного сегмента. Числовые колонки выровнены вправо.
- **Компоненты-подача.** Правый дровер для create/edit юзера; toast на успех;
  жёлтый apply-bar с pending-изменениями на экране Uplinks; SVG-иконки (не
  эмодзи); hover-переходы 150–300ms; видимый focus-ring; `prefers-reduced-motion`.

## Открытые вопросы (до фазы плана, спеку не блокируют)

- Точные схемы `users` и `topology` — снять из `dashboard.html` (эталон паритета,
  жив до cutover) и реальных ответов control API при реализации.
- Клиентский роутер — минимальный самописный на `location.pathname` +
  `history.pushState` (4 маршрута; без внешней зависимости ради совместимости с
  Svelte 5).
