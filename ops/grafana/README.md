# Grafana

Grafana OSS 13.0.2 живёт **в k3s-кластере** (`monitoring/grafana`), снаружи —
`https://grafana.k3s.beerloga.su`. До 2026-08-09 она работала в docker на
`198.18.1.102`; там всё оставлено как путь отката: `/opt/grafana` нетронут,
контейнер остановлен и снят с автозапуска (`docker update --restart=no`).

VictoriaMetrics осталась на `.102` (`:8428`) — датасорс `prometheus`
(uid `adnsc1wi03doga`) ходит туда по сети. **UID менять нельзя:** дашборды
ссылаются на датасорс именно по нему, и с чужим UID все панели окажутся пустыми.

Состояние — SQLite на `local-path` (NVMe ноды). Кроме провижиненных, в ней живут
семь дашбордов, заведённых руками и отсутствующих в git (`Power`, `Temperature`,
`Node Exporter Full`, `Tunnels`, `Outline`, `VictoriaMetrics`, `Xray Dashboard`),
поэтому ночной бэкап здесь не формальность.

## Раскатка

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
./ops/grafana/dashboards/deploy.sh --k3s   # ConfigMap на каждый дашборд
./ops/grafana/alerting/deploy.sh --k3s     # Secret с rules/policies/contact-points
kubectl -n monitoring rollout restart deploy/grafana
```

**Рестарт обязателен.** Провижининг и дашбордов, и алертинга выполняется только
при старте: `updateIntervalSeconds` на 13.0.2 ничего не перечитывает. Проверено
2026-08-09 — три дашборда, обновлённых в 08:51, продолжали отдавать старые
версии, потому что контейнер стартовал накануне.

Грабли режима `--k3s`:

- **Дашборды собираются из трёх мест.** Кроме этого каталога, скрипт забирает
  `bins/outline-ss-rust/grafana/` и `bins/outline-ws-rust/grafana/`. Так и надо:
  провайдер стоит с `disableDeletion: false`, и дашборд, не попавший в
  смонтированный каталог, будет удалён из БД при следующем старте.
- **Применение только `--server-side`.** Обычный `kubectl apply` пишет весь
  объект в аннотацию `last-applied-configuration`, а у аннотаций лимит 256 КБ —
  `outline-ws-rust-dashboard.json` (252 КБ) его пробивает, хотя в сам ConfigMap
  (лимит 1 МиБ) влезает свободно.
- **Новый дашборд надо примонтировать.** Один ConfigMap на файл, список
  источников — в projected volume в
  [`apps/monitoring/grafana.yaml`](../nanopi-r5c-k3s/apps/monitoring/grafana.yaml);
  скрипт печатает строку, которую туда добавить.

## Бэкап

CronJob `grafana-backup` в 03:30 снимает консистентный снимок БД и кладёт
`grafana-YYYYmmdd-HHMM.db.gz` на NAS
(`198.18.1.125:/mnt/HD/HD_a2/k8s/backup/grafana`), хранит семь последних. Снимок
делается модулем `sqlite3` из `python:alpine`, а не утилитой `sqlite3`: под
работает под uid 472, а `apk add` требует root.

## Legacy: docker на .102

Прежний путь раскатки (те же скрипты без `--k3s`) остался рабочим на случай
отката:

```bash
./ops/grafana/dashboards/deploy.sh
./ops/grafana/alerting/deploy.sh
ssh mmv@198.18.1.102 'sudo docker update --restart=unless-stopped grafana && sudo docker start grafana'
```

### Дашборд `outline alerting`

[`dashboards/outline-alerting.json`](dashboards/outline-alerting.json) — история
и здоровье самого алертинга: сколько правил взял планировщик, были ли ошибки
вычисления, сколько уведомлений ушло по каждому каналу, и по одной панели на
правило — метрика с пороговой линией, по которой видно, когда условие было
истинным.

Смысл раскладки в том, что видно не только «правило сработало», но и что
происходило с метрикой до и после, — а благодаря 90-дневной истории VM можно
посмотреть, как правило вело бы себя в прошлом, до того как его завели.

**Историю срабатываний внутри дашборда показать нельзя — не пытайтесь снова.**
Панель Annotations list (`annolist`) запрашивает только обычные аннотации:
в её бандле зашито `type:"annotation"`, а вся история алертов пишется с
`alert_id != 0` и в эту выборку не попадает. Строки `type:"alert"` во фронтенде
Grafana 13.0.2 нет вообще, поэтому и annotation-запрос дашборда не даст
вертикальных полос на графиках — он удалён, чтобы не создавать видимость работы.

Проверено 2026-08-11 на живой базе: 1340 аннотаций, все с `alert_id != 0`,
панель показывала «No annotations found». Попутно выяснилось и другое: индексная
таблица `annotation_tag`, по которой идёт фильтрация по тегам, для этих
аннотаций почти не заполняется (одна связь на 1340), так что фильтр по
`grafana_folder:Alerts` бесполезен вдвойне.

Что работает вместо этого: панель «Состояние правил» (`alertlist`) — текущее
состояние каждого правила; панель «Переходы состояний» — динамика по метрике
`grafana_alerting_state_history_transitions_total`; полная история по каждому
правилу — на странице **Alerting → History** в UI, она ходит другим API.

Метрики `grafana_alerting_*` берутся из самой Grafana: в `scrape.yaml` на `.102`
добавлен job `grafana`. После переезда в кластер он ходит на
`https://grafana.k3s.beerloga.su/metrics` (`scheme: https` — ingress редиректит
http на TLS, и без схемы scrape ловил бы `308`). Конфиг VictoriaMetrics перечитывается
без рестарта — `curl -X POST http://127.0.0.1:8428/-/reload` (автоперечитывание
выключено: `promscrape.configCheckInterval=0s`).

Дашборды, не привязанные к бинарю, лежат в [`dashboards/`](dashboards/);
дашборды бинарей — рядом с ними, в `bins/outline-ws-rust/grafana/` и
`bins/outline-ss-rust/grafana/`. Раскатывать их надо все разом
(`./dashboards/deploy.sh --k3s` собирает все три каталога) — см. «Раскатка».

**Как забрать дашборд, заведённый руками в UI.** Начиная с Grafana 12 дашборды
хранятся в unified storage — таблица `resource` в `/opt/grafana/data/grafana.db`,
а НЕ старая таблица `dashboard` (она осталась и содержит устаревший срез, из-за
чего заведённого в UI дашборда там может просто не быть). `uid` лежит в
`metadata.name`, тело — в `spec`; для provisioning-файла `uid` нужно перенести
внутрь JSON. Таблица `dashboard_provisioning` в этой схеме тоже не заполняется —
признак управления провижинингом ищи в `metadata.annotations`:
`grafana.app/managedBy: classic-file-provisioning` и `grafana.app/sourcePath`.
Если положить файл с тем же `uid`, провайдер перехватывает существующий дашборд,
а не плодит дубль.

### Unbound

[`dashboards/unbound-dashboard.json`](dashboards/unbound-dashboard.json)
(uid `9FQf4fEWz`) — 21 панель по метрикам `unbound_exporter` (`:9167`) с
exit-узлов `cloud1`, `cloud2`, `nuxt`, `nuxt2`.

**13 из 21 панели требуют `extended-statistics: yes` в `unbound.conf`.** Без неё
`unbound-control stats_noreset` отдаёт 93 строки базовой статистики, и панели
Queries by type / Answers by response code / Memory, а также свёрнутые ряды
Queries detail, Answers detail и часть Misc остаются пустыми — метрик
`num.query.type.*`, `num.answer.rcode.*`, `mem.*`, `msg.cache.count`,
`unwanted.*` в выводе просто нет. С включённой опцией выводится 195 строк,
exporter отдаёт 56 семейств `unbound_*` вместо 27. Включено на всех четырёх
узлах 2026-08-08.

`statistics-cumulative` при этом не нужна: exporter опрашивает `stats_noreset`,
счётчики в VictoriaMetrics растут монотонно.

Сам `unbound.conf` руками больше не правится: его источник —
[`ops/provision-node/assets/unbound/unbound.conf`](../provision-node/assets/unbound/unbound.conf),
оттуда его кладёт `install.sh` на каждый узел (см. «Что принадлежит
репозиторию, а не эталону» в
[README провижининга](../provision-node/README.ru.md)). Меняешь требования
дашборда к статистике — меняй ассет, а не узел, иначе следующая переустановка
вернёт панели в пустое состояние. Новый узел, кроме того, не попадает в
`unbound-exporter` job в `/opt/victoria-metrics/data/scrape.yaml` на .102 сам —
его туда добавляют руками.

## Алертинг

Правила, контакт-пойнты и дерево маршрутов лежат в
[`alerting/`](alerting/) и раскатываются скриптом:

```bash
./ops/grafana/alerting/deploy.sh
```

Скрипт подставляет heartbeat-токен из `~/.config/outline/heartbeat-token`,
проверяет YAML и копирует три файла в `/opt/grafana/provisioning/alerting/`.

**После раскатки Grafana нужно перезапустить.** Провижининг выполняется один раз
при старте (`starting to provision alerting` в логе), и файлы, положенные позже,
лежат мёртвым грузом до следующего запуска. Проверено 2026-08-07: файлы легли на
27 секунд позже старта — в БД не появилось ни одного правила.

Это ровно то же, что и с дашбордами (см. выше): `updateIntervalSeconds` не
спасает ни тех, ни других. Единственное, что применяется на ходу, — доменные
файлы маршрутизации и конфиг VictoriaMetrics через `/-/reload`.

```bash
kubectl -n monitoring rollout restart deploy/grafana
```

| Что поменял | Чем применять |
|-------------|---------------|
| `alerting/*.yaml` | `./alerting/deploy.sh --k3s` + `rollout restart` |
| дашборд | `./dashboards/deploy.sh --k3s` + `rollout restart` |
| переменные окружения (SMTP и прочее) | правка `apps/monitoring/grafana.yaml` + `kubectl apply` |

Legacy-путь на `.102` жил по тем же правилам, но там `docker restart` не видел
правок `grafana.sh`: контейнер перезапускался со старым окружением, и новый
`GF_SMTP_USER` не подхватывался — требовалось пересоздание через
`sh /opt/grafana/grafana.sh`. В кластере этой ловушки нет: `kubectl apply`
пересоздаёт под целиком.

## Каналы доставки

Алерты идут в два канала сразу — почта и Telegram, оба в contact point `owner`.
Telegram — тот, что реально доводит сигнал до телефона; почта остаётся на случай
блокировки Telegram или отозванного токена бота. Ни один не считается
достаточным в одиночку.

**Dead-man остался только на почте, и это вынужденно.** `api.telegram.org`
доступен с `.102` (в том числе изнутри контейнера Grafana), но с `cloud1` и
`cloud2` уходит в таймаут — а наблюдатели живут именно там. Пускать их в Telegram
через туннель узла означало бы поставить самый важный алерт в зависимость от
того, что он и проверяет.

Секреты Telegram лежат на машине разработчика, а не на узле: `deploy.sh` берёт
`~/.config/outline/telegram-bot-token` и `~/.config/outline/telegram-chat-id` и
подставляет их вместо плейсхолдеров. В отличие от SMTP-пароля, который Grafana
читает сама через `GF_SMTP_PASSWORD__FILE`, токен бота она умеет брать только
значением настройки — поэтому он попадает внутрь
`/opt/grafana/provisioning/alerting/contact-points.yaml` (0640, владелец 1000).

Чтобы получить `chat_id`, пользователь обязан сам написать боту: Telegram не
отдаёт id до первого сообщения и запрещает боту писать первым.

**Удалить правило = отдельная секция.** Провижининг алертинга только добавляет и
обновляет: убрать правило из `rules.yaml` недостаточно, оно продолжит жить в БД и
слать письма. Из UI provisioned-правило тоже не удаляется. Нужен явный блок:

```yaml
deleteRules:
  - orgId: 1
    uid: uplink-selftest
```

Это отличается от дашбордов, где удалённый файл убирает дашборд.

Что настроено:

| Правило | Порог | Класс |
|---------|-------|-------|
| `TargetDown` | нет скрейпа 5 мин | critical |
| `AllUplinksDown` | сумма `health_effective` = 0, 3 мин | critical |
| `UplinkCarrierLossHigh` | потери > 5% в течение 10 мин | warning |
| `UplinkFailoverStorm` | > 30 failover за 15 мин | warning |
| `UplinkCertExpiringSoon` | сертификат < 14 дней | info |
| `ClientRestarted` | сброс счётчика `selected_total` | info |
| `DeadMansSwitch` | всегда firing — это пульс, не алерт | — |

Пороги выбраны прогоном семи суток истории, а не на глаз; обоснование каждого
числа — в [спеке](../../docs/superpowers/specs/2026-08-07-uplink-email-alerting-design.md).

`DeadMansSwitch` уходит не в почту, а webhook'ами на `cloud1` и `cloud2` —
см. [`ops/heartbeat/README.md`](../heartbeat/README.md).

## SMTP

Почта настраивается переменными окружения в `grafana.sh`:

```
-e GF_SMTP_ENABLED=true
-e GF_SMTP_HOST=smtp.gmail.com:587
-e GF_SMTP_USER=<gmail-адрес>
-e GF_SMTP_PASSWORD__FILE=/etc/grafana/secrets/smtp
-e GF_SMTP_FROM_ADDRESS=<gmail-адрес>
-v /opt/grafana/secrets:/etc/grafana/secrets:ro
```

Пароль — **app-password Google** (16 символов, требует включённой двухэтапной
аутентификации), лежит файлом, а не значением переменной: значение видно в
`docker inspect` и в `ps`, файл — нет. Суффикс `__FILE` Grafana понимает для
любой настройки.

Записывать строго без перевода строки:

```bash
printf '%s' '<app-password>' | sudo tee /opt/grafana/secrets/smtp >/dev/null
sudo chmod 0600 /opt/grafana/secrets/smtp
sudo chown 1000:1000 /opt/grafana/secrets/smtp
```

Владелец `1000:1000` — под этим uid работает контейнер. Проверка:
`stat -c '%a %s' /opt/grafana/secrets/smtp` должен дать `600 16`. **17 байт
означают, что затесался `\n`** — SMTP-аутентификация упадёт с невнятным
«username and password not accepted», и искать причину будешь долго.

Применение требует пересоздания контейнера (`sudo sh /opt/grafana/grafana.sh`),
потому что переменные окружения задаются при запуске. Скрипт делает
`docker pull`, так что заодно может приехать новая версия Grafana — проверяй
`grafana server -v` после.

## Грабли

- **Бэкап дашборда в каталоге провижининга блокирует Grafana целиком.**
  Держи копии в `/opt/grafana/dashboard-backups/`, а не рядом с провижинингом.
- **Пароль admin в этом файле не хранится** — если он утерян, сбрасывается
  через `grafana cli admin reset-admin-password` внутри контейнера.
