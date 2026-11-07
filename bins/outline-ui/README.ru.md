# outline-ui

English version: [README.md](README.md).

Реальные имена узлов, домены и адреса парка в этом документе заменены условными: `fleet.example` — домен парка; `relay-a`…`relay-d` — промежуточные cloud-узлы; `198.51.100.0/24` — домашняя сеть (`.102`, `.104` и т. д. — последний октет). Соответствие — в локальном некоммитируемом `FLEET.local.md`.

Web-UI парка. Отдаёт клиентский и серверный дашборды и больше ничего: ни
аплинков, ни листенеров для проксируемого трафика, ни трафика.

Оба дашборда — HTTP-клиенты control API инстансов: браузер обращается к
`outline-ui`, а `outline-ui` пересылает каждый вызов API на `control_url`
инстанса с токеном этого инстанса.

| Путь | Дашборд | Источник |
|---|---|---|
| `/ws` | аплинки, маршрутизация, группы, настройки, топология, потери носителя | control API клиента (`:9191` на парке) |
| `/ss` | пользователи, mesh-кластер, настройки сервера | control API сервера (`:9190` на парке) |
| `/` | страница со ссылками на оба | — |

Состояния сервис не держит и на диск ничего не пишет. Из секретов у него только
собственный токен и токены инстансов, на которые указывает конфиг.

## Дашборд сервера (`/ss`)

- Пользователи (`/ss`): создание, правка, блокировка, клонирование и удаление
  ключей доступа (Shadowsocks AEAD / VLESS), генерация учётных данных.
- Mesh-кластер (`/ss/cluster`): секция `[cluster]` — локальный shard ID
  (0..15), адрес прослушивания mesh, бюджет релея (мс), PSK кластера (из него
  через BLAKE3 выводятся mTLS-идентичность mesh и ключ обфускации шарда),
  список пиров.
- Настройки сервера (`/ss/settings`): адреса прослушивания TCP/TLS и HTTP/3,
  `h3_initial_mtu`, пути к TLS-сертификату и ключу; возобновление сессий (TTL
  для TCP/UDP, лимиты на пользователя и общий, буфер downlink); исходящая
  политика (приоритет IPv4, sticky-сессии IPv6, пул префиксов IPv6, интерфейс
  динамического префикса и интервал его обновления, исходящий интерфейс);
  профиль тюнинга (`large`, `medium`, `small`); `[padding]` (min/max байт,
  джиттер cover-трафика, детект троттлинга); маршрутизация по SNI
  (`match_sni`); `[http_fallback]`; список эндпоинтов носителей.

## Дашборд клиента (`/ws`)

- Топология (`/ws`): активные пути (wires), RTT, доля потерь пакетов носителя
  по каждому плечу, ручной выбор активного аплинка.
- Аплинки (`/ws/uplinks`): редактор `[[outline.uplinks]]` и их цепочек
  резервных путей (fallbacks): порядок, `ipv4_only` / `ipv6_first` на уровне
  пути (не задано / true / false), `shuffle_wires`, `shuffle_timer`,
  переопределение `padding` на уровне аплинка.
- Маршрутизация (`/ws/routing`): правила `[[route]]` — создание, правка,
  удаление, перестановка (first match wins); применяются без рестарта.
- Группы аплинков (`/ws/groups`): редактор `[[uplink_group]]` (mode, routing
  scope, reselect, тёплый резерв, cluster resume, параметры
  scoring/failover/keepalive).
- Настройки клиента (`/ws/settings`):
  - `[probe]`: интервалы, таймауты, порог сбоев (min failures), попытки, лимит
    параллельных проб, предпроверка эндпоинта, HTTP URL, TLS-цели, DNS/TCP-тесты.
  - Сеть: глобальные `ipv4_only`, `ipv6_first`, `direct_ipv6_prefix_interface`,
    буферы UDP-сокетов носителя (`udp_recv_buf_bytes`, `udp_send_buf_bytes`).
  - Вход: адрес прослушивания и учётные данные `[socks5]` (один пользователь
    или `[[socks5.users]]`); устройство `[tun]`, MTU, лимит флоу, маршрутизация
    по SNI, сниффинг QUIC, обход IPsec, PMTUD, offload Linux GSO/GRO/USO;
    `[tun.tcp]` (сниффинг полезной нагрузки, direct re-resolve, миграция
    носителя, лимиты скорости downlink, буферы).
  - Дозвон и отпечаток: таймаут `[dial]`, профиль TLS-отпечатка (`off`,
    `stable`, `random`), direct fwmark, приоритет публичного IPv6-источника,
    `[padding]` (min/max байт, джиттер cover-трафика, реакция на троттлинг).
  - Транспорт: окна приёма и keepalive `[quic]`, размеры окон и ping keepalive
    `[h2]`, `[tcp_timeouts]`.
  - **Apply now** применяет изменения на месте; если изменился параметр сокета
    или TUN-устройства, страница вместо этого сообщает, что нужен рестарт.

## Вынос UI из боевых бинарей

Раньше дашборды жили внутри `outline-ws-rust` и `outline-ss-rust`. Это давало
три проблемы:

- Web-поверхность на боевых узлах. Достучаться до листенера дашборда
  равносильно владению всеми токенами инстансов, с которыми он настроен: токены
  подставляются на стороне сервера при каждом проксируемом запросе. Эти
  полномочия висели на том же процессе, что и data plane.
- Правка UI стоила рестарта. HTML дашборда попадал в бинари через
  `include_str!`, поэтому косметическая правка означала пересборку и раскатку
  боевого бинаря с рестартом, а рестарт рвёт все флоу узла.
- UI не мог переехать в кластер k3s, где работают Grafana и VictoriaMetrics.

Теперь дашборды из обоих бинарей удалены; бинари отдают только листенеры метрик
и control. С версии `0.2.0` UI — SPA на Svelte, а не серверный HTML.

Дизайн и план выноса:
[спека](../../docs/superpowers/specs/2026-08-12-outline-ui-dashboard-extraction-design.md),
[план](../../docs/superpowers/plans/2026-08-12-outline-ui.md); переписывание
на Svelte:
[спека](../../docs/superpowers/specs/2026-08-12-outline-ui-svelte-rewrite-design.md),
[план](../../docs/superpowers/plans/2026-08-12-outline-ui-svelte-rewrite.md).

## Два гейта, оба до маршрутизации

Оба гейта — middleware-слои на весь `Router` (`main.rs`), поэтому срабатывают
до матчинга маршрутов, и добавленный позже маршрут обойти их не может. Ни один
не заменяет другой.

Credentials (`auth.rs`) решают, кто может работать с панелью. `Bearer <токен>`
для скриптов, `Basic` для браузера (имя любое, пароль — токен); сравнение
constant-time. Отклонённый запрос получает `401` с
`WWW-Authenticate: Basic realm="outline-ui"`, и браузер показывает форму входа.

Origin policy (`origin.rs`) решает, откуда может прийти запрос. Одних
credentials против CSRF мало: браузер сам прикладывает закэшированные
Basic-креды к межсайтовому запросу. Три проверки:

1. `Host` входит в `allowed_hosts`; иначе `403`.
2. `Origin`, если есть, принадлежит самой панели; иначе `403`.
3. Любой метод с телом объявляет `Content-Type: application/json`; иначе
   `415`.

Отсутствующий `Origin` разрешён намеренно: curl его не шлёт, а страница
подавить его не может.

`[server].token` (или `token_file`) обязателен: без него бинарь не стартует. В
поде листенер на `0.0.0.0`, и без токена он отдал бы все настроенные токены
инстансов любому, кто до него дотянется.

## Конфигурация

Путь к конфигу — `--config` или `OUTLINE_UI_CONFIG`, по умолчанию
`/etc/outline-ui/config.toml`.

```toml
[server]
listen = "0.0.0.0:9000"
# token_file лучше inline-токена: секрет приезжает смонтированным файлом, поэтому
# ConfigMap остаётся без секретов, а ротация не требует правки конфига.
token_file = "/etc/outline-ui/secrets/ui-token"
# За ingress браузерный Host — публичное имя, а не адрес, на котором слушает под.
# Service-DNS тоже нужен, иначе любая проверка изнутри кластера получит 403 от
# origin policy.
allowed_hosts = ["ui.k3s.fleet.example", "outline-ui.monitoring"]
request_timeout_secs = 10   # необязательно, по умолчанию 10
refresh_interval_secs = 5   # необязательно, по умолчанию 5

[[ws.instances]]
name = "beelink102"
control_url = "http://198.51.100.102:9191"
token_file = "/etc/outline-ui/secrets/ws-beelink102"

[[ss.instances]]
name = "relay-a"
control_url = "https://relay-a.fleet.example/rust-ss-exporter"
token_file = "/etc/outline-ui/secrets/ss-relay-a"
```

| Ключ | По умолчанию | Что делает |
|---|---|---|
| `[server] listen` | — (обязателен) | Адрес прослушивания |
| `[server] token` / `token_file` | — (нужен один из них) | Токен панели для `Bearer`/`Basic` |
| `[server] allowed_hosts` | `[]` | Значения `Host`, которые принимает origin policy |
| `[server] request_timeout_secs` | `10` | Таймаут вызова control API инстанса |
| `[server] refresh_interval_secs` | `5` | Интервал опроса в дашбордах |
| `[[ws.instances]]` / `[[ss.instances]]` `name`, `control_url` | — (обязательны) | Имя инстанса и базовый URL его control API |
| `[[ws.instances]]` / `[[ss.instances]]` `token` / `token_file` | — (нужен один из них) | Control-токен инстанса |

Любой токен задаётся либо строкой `token`, либо файлом `token_file`, но не
обоими сразу. Хвостовые пробельные символы из файла срезаются: секрет-маунты и
`echo` добавляют перевод строки, а попав в заголовок `Authorization`, он
превращает каждый запрос в 401.

Базовый путь из `control_url` сохраняется, поэтому инстанс за reverse-proxy
(`https://host/rust-ws-exporter`) доступен по этому пути.

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

Проверьте:

```bash
curl -H 'Authorization: Bearer devtoken' http://127.0.0.1:9500/
```

Без заголовка ответ — 401. С ним `/` отдаёт оболочку SPA: заглушку «assets not
embedded», если бинарь не собран с `--features embed-assets` поверх
`pnpm build`-нутого `frontend/dist` (см. «Разработка фронтенда»). JSON API
обоих дашбордов доступны так же, например `/ws/dashboard/api/instances`.

## Разработка фронтенда

UI дашборда — SPA на Svelte 5 + TypeScript в [`frontend/`](frontend), собирается
Vite и Tailwind, тестируется `svelte-check` и Vitest.

Запустите два процесса рядом:

```bash
# терминал 1: JSON API, слушает :9500 (см. «Запуск локально»)
cargo run -p outline-ui -- --config /tmp/ui/config.toml

# терминал 2: SPA с горячей перезагрузкой
cd bins/outline-ui/frontend
pnpm install
pnpm dev   # http://localhost:5173
```

`vite.config.ts` проксирует `/ss/dashboard/api` и `/ws/dashboard/api` на
`127.0.0.1:9500`: dev-сервер отдаёт SPA со своего origin, а её запросы к API
уходят в бэкенд-процесс и через него — на `control_url` из его `config.toml`.
Запросам по-прежнему нужны `Bearer`/`Basic` credentials: dev-сервер не обходит
`auth.rs`/`origin.rs`.

`pnpm build` собирает SPA в `frontend/dist/`: хэшированные имена файлов,
`index.html` ссылается на них под абсолютным префиксом `/ui-assets/`
(`base: '/ui-assets/'` в `vite.config.ts`). Rust-сборка читает этот каталог,
только если включена cargo-фича `embed-assets`, поэтому обычным `cargo build` и
`cargo test` Node не нужен, и Rust-джобы CI работают без него.

Джоб `frontend` в `.github/workflows/ci.yml` запускается на каждый pull request
и push в `main`: `pnpm install --frozen-lockfile`, `svelte-check`, `vitest run`,
`pnpm build`, затем `cargo build -p outline-ui --features embed-assets` поверх
свежего `dist`. Это единственный джоб CI, который собирает эту фичу.

## Как два UI уживаются на одном порту

Один `Router` (`main.rs`) отвечает на три вида запросов, все за одними и теми же
двумя гейтами:

- `/ui-assets/*` — хэшированные JS/CSS/шрифты (`assets::asset`). Vite кладёт
  ресурсы под этот префикс, чтобы они не пересекались с API-деревом ни одного
  из дашбордов.
- `/ws/dashboard/api/...` и `/ss/dashboard/api/...` — JSON API обоих
  дашбордов, каждое `.nest`-ится под `/ws`/`/ss` (`ws::router`/`ss::router`).
- Всё остальное — `/`, глубокая ссылка вроде `/ws/uplinks`, опечатка — отдаёт
  ту же оболочку `index.html` (`assets::spa_index`), включая `.fallback`
  внутри вложенных роутеров `/ws` и `/ss`.

После загрузки оболочки
[`router.svelte.ts`](frontend/src/lib/router.svelte.ts) читает
`location.pathname` и выбирает вид `ws`, `ss` или `landing`. Серверной
подстановки нет: один и тот же `index.html` отдаётся на любой маршрут.

## Раскатка

Живёт в k3s, namespace `monitoring`, за `ui.k3s.fleet.example`. Манифесты:
[`ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml`](../../ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml),
запись ingress — в
[`apps/ingress/ingress-routes.yaml`](../../ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml).
Ноды кластера — aarch64 (NanoPi R5C), отсюда таргет и `--platform`.

Релизный бинарь несёт собранный SPA внутри, поэтому соберите фронтенд первым и
явно попросите Rust-сборку встроить результат. `<version>` ниже — `version` из
`bins/outline-ui/Cargo.toml`; тот же тег пропишите в поле `image:` в
`outline-ui.yaml` до `kubectl apply`.

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
  -t registry.k3s.fleet.example/outline-ui:<version> .
docker push registry.k3s.fleet.example/outline-ui:<version>
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml
kubectl -n monitoring rollout restart deploy/outline-ui
```

Проверка: `kubectl -n monitoring rollout status deploy/outline-ui`, затем
откройте `https://ui.k3s.fleet.example/`. Заглушка «assets not embedded» на
странице значит, что бинарь собран без фронтенда.

`Dockerfile` — один `COPY` файла
`target/aarch64-unknown-linux-musl/release/outline-ui` в `scratch` с запуском от
`65534:65534`, не multi-stage: бинарь кросс-компилируется вне Docker
(`cargo zigbuild`, как и `outline-ss-rust`/`outline-ws-rust`). На этапе сборки
ничего не проверяет, что `frontend/dist` свежий или что передан
`--features embed-assets`; пропустите любой из шагов — образ всё равно
соберётся, но на `/` будет заглушка.

Cargo-алиас `cargo ui-release-musl-aarch64` не передаёт
`--features embed-assets`; используйте полную команду выше.

`ops/deploy/deploy-binary.sh` этот бинарь не покрывает: скрипт заменяет бинарь
systemd-юнита на узле парка и рестартует его, а `outline-ui` раскатывается
образом контейнера в k3s. Команды выше — вся процедура раскатки.

Конфиг читается один раз при старте, поэтому правка ConfigMap применяется только
после рестарта пода.

### Известные проблемы

- Реестр за basic-auth. Без `imagePullSecrets` образ не тянется:
  `no basic auth credentials`, под висит в `ImagePullBackOff`. Секрет
  `registry-creds` должен существовать в namespace `monitoring`.
- `allowed_hosts` обязан включать Service-DNS, а не только публичное имя. Иначе
  запрос изнутри кластера с валидным токеном получает 403 — выглядит как отказ
  авторизации, но приходит от origin policy.
- Liveness-пробы намеренно нет. Все маршруты за гейтом credentials, поэтому
  неаутентифицированная проба получала бы 401, и kubelet перезапускал бы
  здоровый под в цикле. Для пробы сначала нужен health-роут без авторизации.
- Алиасы `ui-release-musl-*` в `.cargo/config.toml` не включают
  `embed-assets`. Бинарь, собранный голым алиасом, отдаёт заглушку «assets not
  embedded»; после `pnpm build` передавайте `--features embed-assets`, как это
  делают релизный workflow (`.github/workflows/_ui-release-build.yml`) и
  процедура выше.
