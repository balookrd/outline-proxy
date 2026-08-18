# outline-ui

Агрегирующий web-UI парка. Отдаёт оба дашборда и больше ничего — ни аплинков, ни
листенеров, ни трафика.

English version: [README.md](README.md).

## Что это

Клиентский и серверный дашборды никогда по-настоящему не были частью data plane:
оба — HTTP-клиенты, которые разлетаются по control API каждого инстанса и рисуют
ответы. Этот бинарь — те же два дашборда, отцепленные от data plane.

| Путь | Дашборд | Источник |
|---|---|---|
| `/ws` | аплинки, маршрутизация, топология, потери носителя | control API клиента (`:9191`) |
| `/ss` | управление юзерами | control API сервера (`:9190`) |
| `/` | страница со ссылками на оба | — |

Состояния не держит, на диск ничего не пишет и своих секретов не хранит — только
то, на что указывает конфиг.

Вкладка «Uplink groups» дашборда `/ws` (`/ws/groups`) — CRUD-редактор политики `[[uplink_group]]`
(mode, routing scope, reselect, тёплый резерв, cluster resume и продвинутые
ручки scoring/failover/keepalive). Staged → **Apply now**, применяется без
рестарта узла. Группа создаётся пустой; аплинки добавляются во вкладке Uplinks.
Удаление разрешено только для группы без аплинков.

Вкладка «Routing» дашборда `/ws` позволяет создавать, править, удалять и
переставлять правила маршрутизации (`[[route]]`) инстанса — при
first-match-wins порядок правил определяет, какое из них сработает первым, —
и применяет изменения той же кнопкой «Apply now», что и вкладка «Uplinks».

## Зачем он появился

Три проблемы, и все они следствие того, что UI жил внутри бинарей, везущих
трафик:

- **Web-поверхность на боевых узлах.** Достучаться до листенера дашборда
  равносильно владению всеми токенами инстансов, с которыми он настроен, — токены
  подставляются на стороне сервера при каждом проксируемом запросе. Эти
  полномочия висели на том же процессе, что и data plane.
- **Правка UI стоила рестарта.** Раньше HTML дашборда попадал прямо в
  `outline-ws-rust`/`outline-ss-rust` через `include_str!`, поэтому
  косметическая правка означала пересборку и раскатку боевого бинаря с
  рестартом — а это все флоу узла.
- **UI не мог переехать в кластер**, где уже живут Grafana и VictoriaMetrics.

## Два гейта, оба до маршрутизации

Ни один не заменяет другой, и оба стоят перед матчингом маршрутов — чтобы
добавленный позже маршрут не мог оказаться вне проверки, просто её не запросив.

**Credentials** (`auth.rs`) — *кто* может управлять панелью. `Bearer` для
скриптов, `Basic` для браузера (имя любое, токен в пароле), сравнение
constant-time. Заголовок `WWW-Authenticate` отправляется, чтобы браузер показал
форму входа, а не голый 401.

**Origin policy** (`origin.rs`) — *откуда* пришёл запрос. Одних credentials
против CSRF мало: браузер сам прикладывает закэшированные Basic-креды к
межсайтовому запросу. Три проверки — `Host` называет этот листенер, `Origin`
(если есть) принадлежит самой панели, и любой метод с телом объявляет
`Content-Type: application/json`. Отсутствующий `Origin` разрешён намеренно: curl
его не шлёт вовсе, а страница подавить его не может.

`[server].token` **обязателен**. В поде листенер на `0.0.0.0`, и без токена он
отдал бы весь парк любому, кто до него дотянется.

## Конфигурация

```toml
[server]
listen = "0.0.0.0:9000"
# token_file лучше inline-токена: секрет приезжает смонтированным файлом, поэтому
# ConfigMap остаётся без секретов, а ротация не требует правки конфига.
token_file = "/etc/outline-ui/secrets/ui-token"
# За ingress браузерный Host — публичное имя, а не адрес, на котором слушает под.
# Service-DNS тоже нужен, иначе любая проверка изнутри кластера получит 403 от
# origin policy.
allowed_hosts = ["ui.k3s.beerloga.su", "outline-ui.monitoring"]
request_timeout_secs = 10   # необязательно, по умолчанию 10
refresh_interval_secs = 5   # необязательно, по умолчанию 5

[[ws.instances]]
name = "beelink102"
control_url = "http://198.18.1.102:9191"
token_file = "/etc/outline-ui/secrets/ws-beelink102"

[[ss.instances]]
name = "cloud1"
control_url = "https://cloud1.beerloga.su/rust-ss-exporter"
token_file = "/etc/outline-ui/secrets/ss-cloud1"
```

Любой токен задаётся либо строкой `token`, либо файлом `token_file` — но не
обоими сразу. Хвостовой перевод строки из файла срезается: секрет-маунты и `echo`
его добавляют, а попав в заголовок `Authorization`, он превращает каждый запрос
в необъяснимый 401.

Базовый путь из `control_url` сохраняется, поэтому инстанс за reverse-proxy
(`https://host/rust-ws-exporter`) достижим корректно.

## Запуск локально

```bash
mkdir -p /tmp/ui && printf '%s' 'devtoken' > /tmp/ui/token
cat > /tmp/ui/config.toml <<'EOF'
[server]
listen = "127.0.0.1:9500"
token_file = "/tmp/ui/token"
allowed_hosts = ["127.0.0.1:9500"]
EOF
cargo run -p outline-ui -- --config /tmp/ui/config.toml
```

Дальше `curl -H 'Authorization: Bearer devtoken' http://127.0.0.1:9500/`. Без
заголовка ответ — 401; с ним `/` отдаёт оболочку SPA — заглушку «assets not
embedded», если бинарь не собран с `--features embed-assets` поверх
`pnpm build`-нутого `frontend/dist` (см. «Разработка фронтенда» ниже). Те же
JSON API, которыми пользуются оба дашборда, доступны так же, например
`/ws/dashboard/api/instances`.

Для разработки UI с горячей перезагрузкой против этого бэкенда — см.
«Разработка фронтенда» ниже.

## Разработка фронтенда

UI дашборда — SPA на Svelte 5 + TypeScript в [`frontend/`](frontend), собран
на Vite и Tailwind, тестируется `svelte-check`/Vitest. `frontend/README.md` —
типовой шаблон Vite/Svelte без правок; всё ниже специфично именно для
встраивания в этот бинарь.

Два процесса рядом:

```bash
# терминал 1: JSON API — «Запуск локально» выше, слушает :9500
cargo run -p outline-ui -- --config /tmp/ui/config.toml

# терминал 2: SPA с горячей перезагрузкой
cd bins/outline-ui/frontend
pnpm install
pnpm dev   # http://localhost:5173
```

`vite.config.ts` проксирует `/ss/dashboard/api` и `/ws/dashboard/api` на
`127.0.0.1:9500` — dev-сервер отдаёт SPA со своего origin, а её запросы к API
уходят в настоящий бэкенд-процесс и дальше — туда, куда указывают
`control_url` в его `config.toml`. Запросы всё так же требуют
`Bearer`/`Basic` credentials — их требуют оба гейта: dev-сервер не
освобождён от `auth.rs`/`origin.rs`.

`pnpm build` собирает SPA в `frontend/dist/`: хэшированные имена под
`/ui-assets/*`, `index.html` ссылается на них абсолютным путём (`base:
'/ui-assets/'` в `vite.config.ts`). Rust-сборка не читает этот каталог, пока
не включена cargo-фича `embed-assets` — обычным `cargo build`/`cargo test`
Node вообще не нужен, поэтому дефолтные Rust-джобы остаются без Node. Про
релизную сборку с включённой фичей — «Раскатка» ниже.

Джоб `frontend` в `.github/workflows/ci.yml` гоняет `svelte-check`, `vitest
run` и `pnpm build` на каждый PR и пуш в `main` — отдельный гейт фронтенда,
независимый от Rust-джобов.

## Раскатка

Живёт в k3s, namespace `monitoring`, за `ui.k3s.beerloga.su`. Манифесты:
[`ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml`](../../ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml),
запись ingress — в
[`apps/ingress/ingress-routes.yaml`](../../ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml).

Релизный бинарь несёт собранный SPA внутри, поэтому фронтенд собирается
*первым*, а Rust-сборка должна явно попросить встроить результат — простой
`cargo build` его не встраивает:

```bash
pnpm -C bins/outline-ui/frontend install
pnpm -C bins/outline-ui/frontend build                        # → frontend/dist/
cargo zigbuild --release -p outline-ui --features embed-assets \
  --target aarch64-unknown-linux-musl
# --provenance=false --sbom=false: без них buildx кладёт образ как
# OCI-image-index (arch-манифест + attestation-манифест), и тогда weekly
# registry-gc --delete-untagged сносит дочерние манифесты (на них нет тегов)
# → образ перестаёт пуллиться на нодах без локального кеша.
docker build --provenance=false --sbom=false --platform linux/arm64 \
  -f bins/outline-ui/Dockerfile \
  -t registry.k3s.beerloga.su/outline-ui:0.2.0 .
docker push registry.k3s.beerloga.su/outline-ui:0.2.0
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml
kubectl -n monitoring rollout restart deploy/outline-ui
```

`Dockerfile` — простой `COPY` в `scratch`, не multi-stage: бинарь
кросс-компилируется вне Docker (`cargo zigbuild`, как и
`outline-ss-rust`/`outline-ws-rust`), и единственная задача Docker —
упаковать уже готовый бинарь, вместе со встроенными assets. Ничего не
проверяет на этапе сборки, что `frontend/dist` свежий или что был передан
`--features embed-assets`, поэтому пропущенный шаг не мешает сборке образа:
`/` в этом случае просто отдаёт заглушку «assets not embedded» вместо
дашборда.

`ops/deploy/deploy-binary.sh` этот бинарь не покрывает: скрипт пушит в
systemd-юнит на узле парка (только `outline-ws-rust`/`outline-ss-rust`) и
рестартует его на месте — а `outline-ui` раскатывается иначе: без
systemd-юнита, без узла парка, образом контейнера в k3s. Пять команд выше —
вся процедура раскатки целиком.

Ноды кластера — aarch64 (NanoPi R5C), отсюда таргет и `--platform`.

Конфиг читается один раз при старте, поэтому правка ConfigMap применяется только
рестартом пода.

### Грабли, пойманные при раскатке

- **Реестр за basic-auth.** Без `imagePullSecrets` образ не тянется:
  `no basic auth credentials`, под висит в `ImagePullBackOff`. Секрет
  `registry-creds` должен существовать в этом namespace.
- **`allowed_hosts` обязан включать Service-DNS**, а не только публичное имя,
  иначе запрос изнутри кластера с валидным токеном получает 403 — что читается
  как отказ авторизации, хотя дело не в ней.
- **Liveness-пробы намеренно нет.** Все маршруты за гейтом credentials, поэтому
  неаутентифицированная проба получала бы 401, и kubelet крутил бы здоровый под в
  цикле. Для пробы нужен осознанно добавленный health-роут без авторизации.

## Как два UI уживаются на одном порту

Один бинарь отвечает на три вида запросов, все через один `Router`
(`main.rs`), за одним и тем же гейтом ещё до матчинга маршрута:

- `/ui-assets/*` — хэшированные JS/CSS/шрифты (`assets::asset`), префикс,
  который Vite настроен отдавать (`base: '/ui-assets/'` в `vite.config.ts`)
  именно для того, чтобы он не мог столкнуться ни с одним API-деревом
  дашбордов.
- `/ws/dashboard/api/...` и `/ss/dashboard/api/...` — JSON API обоих
  дашбордов, форма не изменилась, каждое `.nest`-ится под `/ws`/`/ss`
  (`ws::router`/`ss::router`).
- Всё остальное — `/`, глубокая ссылка вроде `/ws/uplinks`, опечатка — отдаёт
  ту же оболочку `index.html` (`assets::spa_index`), включая `.fallback`
  внутри самих вложенных роутеров `/ws` и `/ss`.

После загрузки оболочки
[`router.svelte.ts`](frontend/src/lib/router.svelte.ts) сам читает
`location.pathname` на клиенте и выбирает вид `ws`/`ss`/`landing` —
подстановки на стороне сервера больше нет и синхронизировать с ней нечего:
один и тот же `index.html` отдаётся на любой маршрут, а своих отдельных
страниц у дашбордов, которые могли бы столкнуться, больше нет.

## Текущее состояние

Дашборды **удалены из `outline-ws-rust` и `outline-ss-rust`**. Теперь этот
сервис — единственное место, где они работают, и с версии `0.2.0` — как SPA
на Svelte, а не серверный HTML. Бинари отдают только свои листенеры метрик и
control-плоскости.

Дизайн и план вынесения из боевых бинарей:
[спека](../../docs/superpowers/specs/2026-08-12-outline-ui-dashboard-extraction-design.md),
[план](../../docs/superpowers/plans/2026-08-12-outline-ui.md); переписывание
на Svelte:
[спека](../../docs/superpowers/specs/2026-08-12-outline-ui-svelte-rewrite-design.md),
[план](../../docs/superpowers/plans/2026-08-12-outline-ui-svelte-rewrite.md).
