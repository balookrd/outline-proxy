# Grafana

Как устроена и раскатывается Grafana парка: дашборды из этого каталога и из
`bins/*/grafana/`, алертинг из [`alerting/`](alerting/), бэкап, SMTP.

Реальные имена узлов, домены и адреса парка в этом документе заменены условными: `fleet.example` — домен парка; `relay-a`…`relay-d` — промежуточные cloud-узлы; `exit-a`…`exit-e` — выходные узлы; `198.51.100.0/24` — домашняя сеть (`.102`, `.104` и т. д. — последний октет). Соответствие — в локальном некоммитируемом `FLEET.local.md`.

Grafana OSS живёт в k3s-кластере (Deployment `monitoring/grafana`, манифест
[`apps/monitoring/grafana.yaml`](../nanopi-r5c-k3s/apps/monitoring/grafana.yaml),
образ `grafana/grafana` v13.3.0 по комментарию к digest), снаружи —
`https://grafana.k3s.fleet.example`. До 2026-08-09 она работала в docker на
`198.51.100.102`; там всё оставлено как путь отката: `/opt/grafana` нетронут,
контейнер остановлен и снят с автозапуска (`docker update --restart=no`).

Датасорс `prometheus` (uid `adnsc1wi03doga`) указывает на кластерную
VictoriaMetrics — `http://victoria-metrics.monitoring:8428`, а не на `.102`
(ConfigMap `grafana-datasources` в
[`apps/monitoring/grafana-provisioning.yaml`](../nanopi-r5c-k3s/apps/monitoring/grafana-provisioning.yaml)).
По этому же источнику считаются и алерты. UID менять нельзя: дашборды ссылаются
на датасорс именно по нему, и с другим UID все панели окажутся пустыми.

Состояние — SQLite на `local-path` (PVC `grafana-data`, под закреплён за
`k3s-1`). Кроме провижиненных, в базе живут семь дашбордов, заведённых руками и
отсутствующих в git (`Power`, `Temperature`, `Node Exporter Full`, `Tunnels`,
`Outline`, `VictoriaMetrics`, `Xray Dashboard`); их копия есть только в ночном
бэкапе.

## Раскатка

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
./ops/grafana/dashboards/deploy.sh --k3s   # ConfigMap на каждый дашборд
./ops/grafana/alerting/deploy.sh --k3s     # Secret grafana-alerting: rules/policies/contact-points
kubectl -n monitoring rollout restart deploy/grafana
```

Без рестарта изменения не применяются. Провижининг и дашбордов, и алертинга
выполняется только при старте: `updateIntervalSeconds` ничего не перечитывает
(проверено 2026-08-09 на 13.0.2 — три дашборда, обновлённых в 08:51, продолжали
отдавать старые версии, потому что контейнер стартовал накануне). Рестарт пода —
действие на проде, согласуйте его с владельцем. Что провижининг прошёл, видно в
логе:

```bash
kubectl -n monitoring logs deploy/grafana --since=2m | grep "provision"
```

Особенности режима `--k3s`:

- Дашборды собираются из трёх мест. Кроме этого каталога, скрипт забирает
  `bins/outline-ss-rust/grafana/` и `bins/outline-ws-rust/grafana/` (если файлы
  не переданы аргументами). Провайдер стоит с `disableDeletion: false`, и
  дашборд, не попавший в смонтированный каталог, будет удалён из БД при
  следующем старте.
- Применение только `--server-side`. Обычный `kubectl apply` пишет весь объект
  в аннотацию `last-applied-configuration`, а у аннотаций лимит 256 КБ —
  `outline-ws-rust-dashboard.json` (252 КБ) его пробивает, хотя в сам ConfigMap
  (лимит 1 МиБ) помещается.
- Новый дашборд надо примонтировать. Один ConfigMap на файл
  (`grafana-dashboard-<имя файла без .json>`), список источников — в projected
  volume `dashboards` в
  [`apps/monitoring/grafana.yaml`](../nanopi-r5c-k3s/apps/monitoring/grafana.yaml);
  скрипт печатает строки, которые туда добавить.
- Невалидный JSON скрипт не раскатывает (проверка `python3 -c json.load`):
  провижинер пропустил бы такой файл молча, оставив на экране старую версию.

## Бэкап

CronJob `grafana-backup`
([`apps/monitoring/grafana-backup.yaml`](../nanopi-r5c-k3s/apps/monitoring/grafana-backup.yaml))
по расписанию `30 3 * * *` [проверить: часовой пояс CronJob — `timeZone` в
манифесте не задан] снимает консистентный снимок БД и кладёт
`grafana-YYYYmmdd-HHMM.db.gz` на NAS
(`198.51.100.125:/mnt/HD/HD_a2/k8s/backup/grafana`), хранит семь последних. Снимок
делается модулем `sqlite3` из образа `python:3.12-alpine` (backup API захватывает
и WAL), а не утилитой `sqlite3`: под работает под uid 472, а `apk add` требует
root.

## Legacy: docker на .102

Прежний путь раскатки (те же скрипты без `--k3s`) остался рабочим на случай
отката:

```bash
./ops/grafana/dashboards/deploy.sh
./ops/grafana/alerting/deploy.sh
ssh mmv@198.51.100.102 'sudo docker update --restart=unless-stopped grafana && sudo docker start grafana'
```

Без `--k3s` скрипты копируют файлы на `mmv@198.51.100.102` (переопределяется
переменной `GRAFANA_HOST`): дашборды — в `/opt/grafana/data/dashboards`,
алертинг — в `/opt/grafana/provisioning/alerting/`. Применяются они
`docker restart grafana`.

## Дашборды

Дашборды, не привязанные к бинарю, лежат в [`dashboards/`](dashboards/);
дашборды бинарей — в `bins/outline-ws-rust/grafana/` и
`bins/outline-ss-rust/grafana/`. Раскатывайте их все разом
(`./dashboards/deploy.sh --k3s` собирает все три каталога) — см. «Раскатка».

### Дашборд `outline alerting`

[`dashboards/outline-alerting.json`](dashboards/outline-alerting.json) — история
и здоровье самого алертинга: сколько правил взял планировщик, были ли ошибки
вычисления, сколько уведомлений ушло по каждому каналу, и по одной панели на
правило — метрика с пороговой линией, по которой видно, когда условие было
истинным. При 90-дневном хранении VictoriaMetrics (`-retentionPeriod=90d`) по
этим панелям видно и то, как правило вело бы себя в прошлом, до того как его
завели.

Историю срабатываний внутри дашборда показать нельзя. Панель Annotations list
(`annolist`) запрашивает только обычные аннотации: в её бандле зашито
`type:"annotation"`, а вся история алертов пишется с `alert_id != 0` и в эту
выборку не попадает. Строки `type:"alert"` во фронтенде Grafana 13.0.2 нет
вообще, поэтому и annotation-запрос дашборда не даёт вертикальных полос на
графиках — он удалён.

Проверено 2026-08-11 на живой базе: 1340 аннотаций, все с `alert_id != 0`,
панель показывала «No annotations found». Индексная таблица `annotation_tag`,
по которой идёт фильтрация по тегам, для этих аннотаций почти не заполняется
(одна связь на 1340), так что фильтр по `grafana_folder:Alerts` тоже ничего не
находит.

Что работает вместо этого: панель «Состояние правил» (`alertlist`) — текущее
состояние каждого правила; панель «Переходы состояний» — динамика по метрике
`grafana_alerting_state_history_transitions_total`; полная история по каждому
правилу — на странице **Alerting → History** в UI, она ходит другим API.

Метрики `grafana_alerting_*` берутся из самой Grafana: job `grafana` в
scrape-конфиге VictoriaMetrics. В кластере он ходит на ClusterIP
`grafana.monitoring:3000`, а не на ingress: обращение из пода на MetalLB-VIP
своего же кластера уходит наружу и возвращается (hairpin), и Traefik отвечает
5xx.

Scrape-конфиг: источник —
[`ops/nanopi-r5c-k3s/apps/monitoring/scrape.yaml`](../nanopi-r5c-k3s/apps/monitoring/scrape.yaml),
VictoriaMetrics читает его из своего PVC
(`-promscrape.config=/victoria-metrics-data/scrape.yaml`). Перечитывается он без
рестарта — `POST /-/reload` на порт 8428 [проверить: как в k3s доставить файл в
PVC и вызвать reload]. Флаг `-promscrape.configCheckInterval` в манифесте
[`victoria-metrics.yaml`](../nanopi-r5c-k3s/apps/monitoring/victoria-metrics.yaml)
не задан [проверить: по умолчанию автоперечитывание выключено].

### Как забрать дашборд, заведённый руками в UI

Начиная с Grafana 12 дашборды хранятся в unified storage — таблица `resource` в
`grafana.db` (в k3s — `/var/lib/grafana/grafana.db` в PVC `grafana-data`, в
legacy — `/opt/grafana/data/grafana.db`), а не в старой таблице `dashboard`
(она осталась и содержит устаревший срез, поэтому заведённого в UI дашборда там
может не быть). `uid` лежит в `metadata.name`, тело — в `spec`; для
provisioning-файла `uid` нужно перенести внутрь JSON. Таблица
`dashboard_provisioning` в этой схеме тоже не заполняется — признак управления
провижинингом ищите в `metadata.annotations`:
`grafana.app/managedBy: classic-file-provisioning` и `grafana.app/sourcePath`.
Если положить файл с тем же `uid`, провайдер перехватывает существующий дашборд,
а не создаёт дубль.

### Unbound

[`dashboards/unbound-dashboard.json`](dashboards/unbound-dashboard.json)
(uid `9FQf4fEWz`) — 21 панель по метрикам `unbound_exporter` (`:9167`) с узлов
`relay-a`, `relay-b` (вход) и `exit-a`, `exit-b` (выход).

13 из 21 панели требуют `extended-statistics: yes` в `unbound.conf`. Без неё
`unbound-control stats_noreset` отдаёт 93 строки базовой статистики, и панели
Queries by type / Answers by response code / Memory, а также свёрнутые ряды
Queries detail, Answers detail и часть Misc остаются пустыми — метрик
`num.query.type.*`, `num.answer.rcode.*`, `mem.*`, `msg.cache.count`,
`unwanted.*` в выводе нет. С включённой опцией выводится 195 строк, exporter
отдаёт 56 семейств `unbound_*` вместо 27. Включено на всех четырёх узлах
2026-08-08.

`statistics-cumulative` при этом не нужна: exporter опрашивает `stats_noreset`,
счётчики в VictoriaMetrics растут монотонно.

`unbound.conf` руками не правится: его источник —
[`ops/provision-node/assets/unbound/unbound.conf`](../provision-node/assets/unbound/unbound.conf),
оттуда его кладёт `install.sh` на каждый узел (см. «Что принадлежит
репозиторию, а не эталону» в
[README провижининга](../provision-node/README.ru.md)). Меняете требования
дашборда к статистике — меняйте ассет, а не узел, иначе следующая переустановка
вернёт панели в пустое состояние. Новый узел в job `unbound-exporter`
scrape-конфига сам не попадает — его добавляют руками в
[`scrape.yaml`](../nanopi-r5c-k3s/apps/monitoring/scrape.yaml) и в живую копию
в PVC.

## Алертинг

Правила, контакт-пойнты и дерево маршрутов лежат в [`alerting/`](alerting/) и
раскатываются скриптом:

```bash
./ops/grafana/alerting/deploy.sh --k3s
```

Скрипт подставляет в файлы три секрета с машины разработчика:
`~/.config/outline/heartbeat-token`, `~/.config/outline/telegram-bot-token` и
`~/.config/outline/telegram-chat-id` (каталог переопределяется
`OUTLINE_SECRETS_DIR`), проверяет YAML (PyYAML, иначе ruby psych; без парсера
отказывается раскатывать) и применяет Secret `grafana-alerting` в namespace
`monitoring`. Без `--k3s` — legacy-путь на `.102`, см. выше.

После раскатки Grafana нужно перезапустить. Провижининг выполняется один раз
при старте (`starting to provision alerting` в логе), и файлы, положенные позже,
не применяются до следующего запуска. Проверено 2026-08-07: файлы легли на
27 секунд позже старта — в БД не появилось ни одного правила.

С дашбордами то же самое (см. выше): `updateIntervalSeconds` не помогает ни
тем, ни другим. На ходу применяются только доменные файлы маршрутизации и
scrape-конфиг VictoriaMetrics через `/-/reload`.

```bash
kubectl -n monitoring rollout restart deploy/grafana
```

| Что поменяли | Чем применять |
|-------------|---------------|
| `alerting/*.yaml` | `./alerting/deploy.sh --k3s` + `rollout restart` |
| дашборд | `./dashboards/deploy.sh --k3s` + `rollout restart` |
| переменные окружения (SMTP и прочее) | правка `apps/monitoring/grafana.yaml` + `kubectl apply` |

Legacy-путь на `.102` жил по тем же правилам, но там `docker restart` не видел
правок `grafana.sh`: контейнер перезапускался со старым окружением, и новый
`GF_SMTP_USER` не подхватывался — требовалось пересоздание через
`sh /opt/grafana/grafana.sh`. В кластере `kubectl apply` изменённого Deployment
пересоздаёт под.

## Каналы доставки

| Contact point | Каналы | Что получает |
|---|---|---|
| `owner` | email + Telegram | все алерты по умолчанию (`group_by: [alertname, instance]`, `repeat_interval: 12h`) |
| `owner-events` | email + Telegram, без уведомления о resolved (`disableResolveMessage: true`) | `ClientRestarted` и `NodeRebooted`, `repeat_interval: 24h` |
| `heartbeat-observers` | два webhook'а на `relay-a` и `relay-b` | `DeadMansSwitch`, `repeat_interval: 5m` |

Маршруты — в [`alerting/policies.yaml`](alerting/policies.yaml). Telegram
доводит сигнал до телефона; почта остаётся на случай блокировки Telegram или
отозванного токена бота.

Dead-man идёт только через почту наблюдателей. `api.telegram.org` доступен с
`.102` (проверено и изнутри legacy-контейнера Grafana) [проверить: из пода
Grafana в k3s], но с `relay-a` и `relay-b` уходит в таймаут — а наблюдатели
живут именно там. Пускать их в Telegram через туннель узла означало бы
поставить алерт о смерти мониторинга в зависимость от того, что он проверяет.

Секреты Telegram лежат на машине разработчика, а не на узле: `deploy.sh` берёт
`~/.config/outline/telegram-bot-token` и `~/.config/outline/telegram-chat-id` и
подставляет их вместо плейсхолдеров `__TELEGRAM_BOT_TOKEN__` /
`__TELEGRAM_CHAT_ID__`. В отличие от SMTP-пароля, который Grafana читает сама
через `GF_SMTP_PASSWORD__FILE`, токен бота она умеет брать только значением
настройки — поэтому он попадает внутрь `contact-points.yaml`: в k3s — в Secret
`grafana-alerting`, в legacy — в `/opt/grafana/provisioning/alerting/contact-points.yaml`
(0640, владелец 1000).

Чтобы получить `chat_id`, пользователь должен сам написать боту: Telegram не
отдаёт id до первого сообщения и запрещает боту писать первым.

Удаление правила требует отдельной секции. Провижининг алертинга только
добавляет и обновляет: если убрать правило из `rules.yaml`, оно продолжит жить в
БД и слать уведомления. Из UI provisioned-правило тоже не удаляется. Нужен явный
блок:

```yaml
deleteRules:
  - orgId: 1
    uid: uplink-selftest
```

С дашбордами иначе: удалённый файл убирает дашборд.

## Правила

Все правила — в папке `Alerts`, интервал вычисления `1m`
([`alerting/rules.yaml`](alerting/rules.yaml)).

| Правило | Условие | `for` | Класс |
|---------|---------|-------|-------|
| `TargetDown` | `up` = 0 для `rust-ws-exporter`, `rust-ss-exporter`, `unbound-exporter` | 5m | critical |
| `AllUplinksDown` | `sum by (instance) (outline_ws_uplink_health_effective)` = 0 | 3m | critical |
| `UplinkCarrierLossHigh` | `outline_ws_uplink_carrier_loss_ratio` > 0.05 на активном плече | 10m | warning |
| `UplinkFailoverStorm` | > 20 failover за 15 мин, без плановых `*_shuffle_timer` | 0s | warning |
| `UplinkCertExpiringSoon` | сертификат истекает через < 14 дней | 1h | info |
| `ClientRestarted` | процессу `outline-ws-rust` меньше 180 с (`outline_ws_start_time_seconds`) | 0s | info |
| `NodeRebooted` | ядру узла `k3s-N` меньше 600 с (`node_boot_time_seconds`) | 0s | warning |
| `DeadMansSwitch` | `count(up) >= 1` — firing всегда, это пульс | 0s | none |

Пороги выбраны прогоном семи суток истории; обоснование каждого числа — в
[спеке](../../docs/superpowers/specs/2026-08-07-uplink-email-alerting-design.md).

`UplinkCarrierLossHigh` алертит только по активному плечу. Условие сужено до
`... and on (instance, uplink) outline_ws_global_active_uplink_info == 1`.
Резервная нога может часами терять пакеты, никого не задевая (exit-c держал 44%
на 2026-08-11, пока трафик шёл через exit-b), а `carrier_loss_ratio` публикуется
для всех сконфигурированных плеч — без фильтра правило слало уведомления из-за
резерва при исправном рабочем пути. Фильтр по активному плечу заодно заменил
прежнее условие `uplink_enabled == 1`: отключённое плечо не активно, и его
замёрзший на последнем значении gauge больше не держит алерт (так было
2026-08-10, когда exit-b выключили на ~50%). Потери резервных плеч видны на
дашборде ws-rust — таблица «Uplink Comparison» красит их красным с пометкой
`standby`.

`DeadMansSwitch` уходит webhook'ами на `relay-a` и `relay-b` — см.
[`ops/heartbeat/README.md`](../heartbeat/README.md).

## SMTP

В k3s почта настраивается переменными окружения в
[`apps/monitoring/grafana.yaml`](../nanopi-r5c-k3s/apps/monitoring/grafana.yaml):

| Переменная | Значение |
|---|---|
| `GF_SMTP_ENABLED` | `true` |
| `GF_SMTP_HOST` | `smtp.gmail.com:587` |
| `GF_SMTP_USER` | Gmail-адрес |
| `GF_SMTP_PASSWORD__FILE` | `/etc/grafana/secrets/smtp` (Secret `grafana-smtp`, ключ `smtp`) |
| `GF_SMTP_FROM_ADDRESS` | тот же Gmail-адрес: `smtp.gmail.com` отправляет только от имени аутентифицированного пользователя |
| `GF_SMTP_FROM_NAME` | `Grafana - fleet.example` |

Пароль — app-password Google (16 символов, требует включённой двухэтапной
аутентификации), подключён файлом, а не значением переменной: значение видно в
описании пода и в `ps`, файл — нет. Суффикс `__FILE` Grafana понимает для любой
настройки.

Записывайте пароль строго без перевода строки. 17 байт вместо 16 означают, что
затесался `\n`: SMTP-аутентификация упадёт с «username and password not
accepted».

```bash
printf '%s' '<app-password>' > /tmp/smtp && chmod 0600 /tmp/smtp
wc -c < /tmp/smtp    # 16
kubectl -n monitoring create secret generic grafana-smtp --from-file=smtp=/tmp/smtp \
  --dry-run=client -o yaml | kubectl apply -f -
rm -f /tmp/smtp
kubectl -n monitoring rollout restart deploy/grafana
```

Legacy-контейнер на `.102` задавал те же переменные через `-e` в
`/opt/grafana/grafana.sh`, а пароль читал из `/opt/grafana/secrets/smtp`
(0600, владелец `1000:1000` — под этим uid работает контейнер; проверка
`stat -c '%a %s' /opt/grafana/secrets/smtp` → `600 16`). Применение там
требовало пересоздания контейнера (`sudo sh /opt/grafana/grafana.sh`); скрипт
делает `docker pull`, так что заодно могла приехать новая версия Grafana —
проверяйте `grafana server -v` после.

## Известные проблемы

- Legacy: копия JSON дашборда в каталоге провижининга (`/opt/grafana/data/dashboards`)
  блокирует Grafana целиком. Держите копии в
  `/opt/grafana/dashboard-backups/`.
- Пароль admin в этом репозитории не хранится и через окружение не задаётся
  (`GF_SECURITY_ADMIN_PASSWORD` сбрасывал бы его на каждом старте пода). Если он
  утерян, сбрасывается командой `grafana cli admin reset-admin-password` внутри
  контейнера:
  `kubectl -n monitoring exec deploy/grafana -- grafana cli admin reset-admin-password '<пароль>'`.
