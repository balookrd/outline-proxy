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
| `/ws` | аплинки, топология, потери носителя | control API клиента (`:9191`) |
| `/ss` | управление юзерами | control API сервера (`:9190`) |
| `/` | страница со ссылками на оба | — |

Состояния не держит, на диск ничего не пишет и своих секретов не хранит — только
то, на что указывает конфиг.

## Зачем он появился

Три проблемы, и все они следствие того, что UI жил внутри бинарей, везущих
трафик:

- **Web-поверхность на боевых узлах.** Достучаться до листенера дашборда
  равносильно владению всеми токенами инстансов, с которыми он настроен, — токены
  подставляются на стороне сервера при каждом проксируемом запросе. Эти
  полномочия висели на том же процессе, что и data plane.
- **Правка UI стоила рестарта.** `dashboard.html` попадает в бинарь через
  `include_str!`, поэтому косметическая правка означала пересборку и раскатку
  боевого бинаря с рестартом — а это все флоу узла.
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

Дальше `curl -H 'Authorization: Bearer devtoken' http://127.0.0.1:9500/ws/dashboard`.
Без заголовка ответ — 401.

## Раскатка

Живёт в k3s, namespace `monitoring`, за `ui.k3s.beerloga.su`. Манифесты:
[`ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml`](../../ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml),
запись ingress — в
[`apps/ingress/ingress-routes.yaml`](../../ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml).

```bash
cargo zigbuild --release -p outline-ui --target aarch64-unknown-linux-musl
docker build --platform linux/arm64 -f bins/outline-ui/Dockerfile \
  -t registry.k3s.beerloga.su/outline-ui:0.1.0 .
docker push registry.k3s.beerloga.su/outline-ui:0.1.0
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/outline-ui.yaml
kubectl -n monitoring rollout restart deploy/outline-ui
```

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

Оба дашборда обращаются к своим API абсолютно (`/dashboard/api/...`). Под
префиксами `/ws` и `/ss` такие URL промахнулись бы, а сами дашборды столкнулись
бы на общих путях. Поэтому каждая страница объявляет

```js
const API_BASE = "__BASE__";
```

а хендлер подставляет `/ws` или `/ss` в момент ответа (`assets::render` — тот же
механизм, которым дашборды уже подменяли интервал обновления). Тест проверяет,
что ни один плейсхолдер не доживает до ответа.

`<base href>` отвергнут: он молча переписывает все относительные URL и якоря на
странице, то есть чинит fetch ценой того, чего никто не проверял.

## Текущее состояние

Дашборды **удалены из `outline-ws-rust` и `outline-ss-rust`** — теперь этот
сервис единственное место, где они работают. Бинари отдают только свои
листенеры метрик и control-плоскости.

Дизайн и план:
[спека](../../docs/superpowers/specs/2026-08-12-outline-ui-dashboard-extraction-design.md),
[план](../../docs/superpowers/plans/2026-08-12-outline-ui.md).
