# Grafana

Как устроена и раскатывается Grafana парка: дашборды из этого каталога и из
`bins/*/grafana/`, бэкап, SMTP. Алертинг в Grafana выключен: правила и рассылка
живут в [`ops/alerting/`](../alerting/README.md) (vmalert и Alertmanager).

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
Алерты по этому источнику считает vmalert, не Grafana. UID менять нельзя: дашборды ссылаются
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
kubectl -n monitoring rollout restart deploy/grafana
```

Без рестарта изменения не применяются. Провижининг дашбордов выполняется
только при старте: `updateIntervalSeconds` ничего не перечитывает
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
(`198.51.100.105:/volume1/k8s/backup/grafana`), хранит семь последних. Снимок
делается модулем `sqlite3` из образа `python:3.12-alpine` (backup API захватывает
и WAL), а не утилитой `sqlite3`: под работает под uid 472, а `apk add` требует
root.

## Legacy: docker на .102

Прежний путь раскатки (те же скрипты без `--k3s`) остался рабочим на случай
отката:

```bash
./ops/grafana/dashboards/deploy.sh
ssh mmv@198.51.100.102 'sudo docker update --restart=unless-stopped grafana && sudo docker start grafana'
```

Без `--k3s` скрипт копирует дашборды на `mmv@198.51.100.102` (переопределяется
переменной `GRAFANA_HOST`) в `/opt/grafana/data/dashboards`. Применяются они
`docker restart grafana`. Алертинг в legacy-контейнер не возвращается: с
2026-11-09 он выключен и в k3s, откат описан в
[`ops/alerting/README.md`](../alerting/README.md#откат).

## Дашборды

Дашборды, не привязанные к бинарю, лежат в [`dashboards/`](dashboards/);
дашборды бинарей — в `bins/outline-ws-rust/grafana/` и
`bins/outline-ss-rust/grafana/`. Раскатывайте их все разом
(`./dashboards/deploy.sh --k3s` собирает все три каталога) — см. «Раскатка».

### Дашборд `outline alerting`

[`dashboards/outline-alerting.json`](dashboards/outline-alerting.json) (uid
`outline-alerting`) — здоровье алертинга (vmalert и Alertmanager) и по одной
панели на правило: метрика с пороговой линией, по которой видно, когда условие
было истинным. При 90-дневном хранении VictoriaMetrics
(`-retentionPeriod=90d`) по этим панелям видно и то, как правило вело бы себя в
прошлом, до того как его завели.

Верхний ряд «Здоровье алертинга» (до 2026-11-09 он строился на метриках
`grafana_alerting_*`, теперь на метриках vmalert, Alertmanager и серии `ALERTS`):

| Панель | Запрос (сокращённо) | Что показывает |
|--------|---------------------|----------------|
| Активных алертов | `count(ALERTS{alertstate="firing",alertname!="DeadMansSwitch"})` | сколько алертов горит сейчас; `DeadMansSwitch` исключён, он firing всегда; ноль — норма |
| Правил в работе | `count(vmalert_alerts_firing)` | сколько правил загрузил vmalert; меньше восьми — не тот `rules.yaml` в ConfigMap `vmalert-rules` или он не перечитался (`vmalert_config_last_reload_successful`, лог пода) |
| Ошибок вычисления за 24ч | `sum(increase(vmalert_alerting_rules_errors_total[24h]))` | правило, которое не вычисляется, не сработает никогда; ноль обязателен. При недоступной VictoriaMetrics панель пуста: метрики vmalert лежат в ней же, этот случай ловит пульс `DeadMansSwitch` |
| Пропущенных тактов за час | `sum(increase(vmalert_iteration_missed_total[1h]))` | такты, которые vmalert пропустил, потому что предыдущий не закончился; ненулевое значение — алерт придёт с задержкой |
| Уведомления по каналам (за час) | `alertmanager_notifications_total` и `alertmanager_notifications_failed_total` по `integration` | отправки по `email`, `telegram`, `webhook`; `webhook` — пульс, около 20 в час (по одной отправке на наблюдателя раз в ~6 минут), `email` и `telegram` растут только на настоящих срабатываниях; линии `failed` должны быть нулевыми |
| Горящие алерты по правилам | `count by (alertname) (ALERTS{alertstate="firing",...})` | сколько экземпляров каждого правила горело в каждый момент; частая гребёнка вместо сплошных блоков — флапающее правило |
| Горящие сейчас | `ALERTS{alertstate="firing",...}` (таблица) | алерты, горящие прямо сейчас, с метками |

Серия `ALERTS` пишется vmalert в VictoriaMetrics через `-remoteWrite.url`.
Заглушки и группировка — в Alertmanager (датасорс `alertmanager-k3s`, см.
[`grafana-provisioning.yaml`](../nanopi-r5c-k3s/apps/monitoring/grafana-provisioning.yaml)).
Ниже ряд «По правилам»: метрика каждого правила с его порогом.

Метрики vmalert и Alertmanager берутся jobs `vmalert`
(`vmalert.monitoring:8880`) и `alertmanager` (`alertmanager.monitoring:9093`) в
scrape-конфиге VictoriaMetrics. Адреса — ClusterIP, а не ingress: обращение из
пода на MetalLB-VIP своего же кластера уходит наружу и возвращается (hairpin), и
Traefik отвечает 5xx.

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

С 2026-11-09 алертинг Grafana выключен (`GF_UNIFIED_ALERTING_ENABLED=false` в
[`apps/monitoring/grafana.yaml`](../nanopi-r5c-k3s/apps/monitoring/grafana.yaml),
том провижининга алертинга и Secret `grafana-alerting` убраны). Выключен, а не
только расконфигурирован: провижиненные правила остаются в `grafana.db` и
продолжали бы вычисляться и слать почту.

Правила, маршруты, получатели, раскатка и откат — в
[`ops/alerting/README.md`](../alerting/README.md):

| Что | Где |
|-----|-----|
| правила (8 штук), пороги, `for`, `keep_firing_for` | [`ops/alerting/vmalert/rules.yaml`](../alerting/vmalert/rules.yaml); обоснование чисел — комментарии над правилами и [спека](../../docs/superpowers/specs/2026-08-07-uplink-email-alerting-design.md) |
| маршруты и получатели (`owner`, `owner-events`, `heartbeat-observers`) | [`ops/alerting/alertmanager/alertmanager.yml`](../alerting/alertmanager/alertmanager.yml) |
| раскатка и офлайн-проверки | `./ops/alerting/deploy.sh`, `./ops/alerting/test.sh` |
| пульс `DeadMansSwitch` | [`ops/heartbeat/README.md`](../heartbeat/README.md) |

Каталог [`alerting/`](alerting/) в этом каталоге (`rules.yaml`,
`contact-points.yaml`, `policies.yaml`, `deploy.sh`) оставлен только для отката
и не раскатывается. Его удаляют не раньше 2026-11-22; перед удалением
проверьте, что отката не было и пульс идёт только от Alertmanager.

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
аутентификации). Тот же пароль использует Alertmanager: `ops/alerting/deploy.sh`
копирует его из Secret `grafana-smtp` (ключ `smtp`) в Secret `alertmanager-smtp`,
поэтому при ротации пароля обновите Secret `grafana-smtp` и затем выполните
`./ops/alerting/deploy.sh`. Пароль подключён файлом, а не значением переменной: значение видно в
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
