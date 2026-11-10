# Grafana

Как устроена и раскатывается Grafana парка: дашборды из этого каталога и из
`bins/*/grafana/`, бэкап, SMTP. Алертинг в Grafana выключен: правила и рассылка
живут в [`ops/alerting/`](../alerting/README.md) (vmalert и Alertmanager).

Реальные имена узлов, домены и адреса парка в этом документе заменены условными: `fleet.example` — домен парка; `relay-a`…`relay-d` — промежуточные cloud-узлы; `exit-a`…`exit-e` — выходные узлы; `198.51.100.0/24` — домашняя сеть (`.102`, `.104` и т. д. — последний октет). Соответствие — в локальном некоммитируемом `FLEET.local.md`.

Grafana OSS работает в docker на NAS `198.51.100.105` (compose-проект
[`ops/nas-monitoring/`](../nas-monitoring/README.md), образ `grafana/grafana`
v13.3.0), снаружи — `https://grafana.k3s.fleet.example` через Service и
EndpointSlice в k3s ([`grafana-nas.yaml`](../nanopi-r5c-k3s/apps/monitoring/grafana-nas.yaml)).
С 2026-08-09 до 2026-11-09 она работала в k3s (Deployment `monitoring/grafana`,
удалён 2026-11-10), до этого — в docker на `198.51.100.102`: там `/opt/grafana`
нетронут, контейнер остановлен и снят с автозапуска (`docker update --restart=no`).

Датасорс `prometheus` (uid `adnsc1wi03doga`) указывает на VictoriaMetrics в той же
compose-сети — `http://victoria-metrics:8428`
([`datasources.yaml`](../nas-monitoring/grafana/datasources/datasources.yaml)).
Алерты по этому источнику считает vmalert, не Grafana. UID менять нельзя: дашборды ссылаются
на датасорс именно по нему, и с другим UID все панели окажутся пустыми.

Состояние — SQLite `/volume2/grafana/grafana.db` на NAS. Кроме провижиненных, в базе
живут семь дашбордов, заведённых руками и отсутствующих в git (`Power`,
`Temperature`, `Node Exporter Full`, `Tunnels`, `Outline`, `VictoriaMetrics`,
`Xray Dashboard`); их копия есть только в ночном бэкапе.

## Раскатка

```bash
./ops/grafana/dashboards/deploy.sh --nas
ssh sysadm@198.51.100.105 'docker restart grafana'
```

Без рестарта изменения не применяются. Провижининг дашбордов выполняется
только при старте: `updateIntervalSeconds` ничего не перечитывает
(проверено 2026-08-09 на 13.0.2 — три дашборда, обновлённых в 08:51, продолжали
отдавать старые версии, потому что контейнер стартовал накануне). Рестарт
контейнера — действие на проде, согласуйте его с владельцем. Что провижининг
прошёл, видно в логе:

```bash
ssh sysadm@198.51.100.105 'docker logs --since 2m grafana 2>&1 | grep "provision"'
```

Особенности режима `--nas`:

- Дашборды собираются из трёх мест. Кроме этого каталога, скрипт забирает
  `bins/outline-ss-rust/grafana/` и `bins/outline-ws-rust/grafana/` (если файлы
  не переданы аргументами). Провайдер стоит с `disableDeletion: false`, и
  дашборд, не попавший в каталог `/volume2/grafana/dashboards`, будет удалён из БД при
  следующем старте.
- Скрипт только копирует файлы (`scp -O`) и на NAS ничего не удаляет. Убранный из
  репозитория дашборд остаётся в `/volume2/grafana/dashboards/` и после рестарта
  Grafana остаётся на экране. Чтобы удалить его, на NAS выполните
  `rm /volume2/grafana/dashboards/<файл>.json` и перезапустите Grafana
  (`docker restart grafana`, с согласия владельца): при старте провайдер не
  находит файл и удаляет дашборд из БД (`disableDeletion: false`).
- Переименование файла без смены `uid` оставляет на NAS два файла с одним `uid`.
  Провайдер обработает их в произвольном порядке, и на экране может оказаться
  любая из двух версий; в логе должна быть ошибка про повторяющийся `uid`
  [проверить: точный текст сообщения Grafana 13.3.0]. Удалите старый файл на NAS
  до рестарта.
- Невалидный JSON скрипт не раскатывает (проверка `python3 -c json.load`):
  провижинер пропустил бы такой файл молча, оставив на экране старую версию.
- `scp` идёт с флагом `-O`: UGOS отклоняет scp в режиме SFTP.

Устройство NAS-проекта, права UGOS, секрет SMTP и восстановление — в
[`ops/nas-monitoring/README.md`](../nas-monitoring/README.md).

## Бэкап

Контейнер `grafana-backup` в compose-проекте на NAS ежедневно в `00:30` UTC
(03:30 MSK) снимает консистентный снимок БД и кладёт
`grafana-YYYYmmdd-HHMM.db.gz` в `/volume1/k8s/backup/grafana` на HDD NAS, хранит
семь последних. Снимок делается модулем `sqlite3` из образа
`python:3.12-alpine` (backup API захватывает и WAL). Восстановление — в
[`ops/nas-monitoring/README.md`](../nas-monitoring/README.md#восстановление).

## Legacy: docker на .102

Прежний путь раскатки (скрипт без флага) остался рабочим на случай отката
на `.102`:

```bash
./ops/grafana/dashboards/deploy.sh
ssh mmv@198.51.100.102 'sudo docker update --restart=unless-stopped grafana && sudo docker start grafana'
```

Без флага скрипт копирует дашборды на `mmv@198.51.100.102` (переопределяется
переменной `GRAFANA_HOST`) в `/opt/grafana/data/dashboards`. Применяются они
`docker restart grafana`. Алертинг в legacy-контейнер не возвращается: с
2026-11-09 он выключен и в Grafana на NAS, откат описан в
[`ops/alerting/README.md`](../alerting/README.md#откат).

## Дашборды

Дашборды, не привязанные к бинарю, лежат в [`dashboards/`](dashboards/);
дашборды бинарей — в `bins/outline-ws-rust/grafana/` и
`bins/outline-ss-rust/grafana/`. Раскатывайте их все разом
(`./dashboards/deploy.sh --nas` собирает все три каталога) — см. «Раскатка».

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
[`datasources.yaml`](../nas-monitoring/grafana/datasources/datasources.yaml)).
Ниже ряд «По правилам»: метрика каждого правила с его порогом.

Метрики vmalert и Alertmanager берутся jobs `vmalert` и `alertmanager` в
scrape-конфиге VictoriaMetrics. VictoriaMetrics стоит на NAS, вне кластера,
поэтому ClusterIP ей недоступен: она ходит на ingress vmalert и трёх реплик
Alertmanager и подставляет прежние значения `instance`
(`vmalert.monitoring:8880`, `alertmanager.monitoring:9093`), чтобы дашборд не
менялся.

Scrape-конфиг: источник —
[`ops/nas-monitoring/victoria-metrics/scrape.yaml`](../nas-monitoring/victoria-metrics/scrape.yaml).
`deploy.sh` из `ops/nas-monitoring/` копирует его на NAS в каталог, смонтированный
в контейнер целиком; VictoriaMetrics перечитывает файл раз в минуту
(`-promscrape.configCheckInterval=1m` в
[`docker-compose.yaml`](../nas-monitoring/docker-compose.yaml)), рестарт не нужен.

### Как забрать дашборд, заведённый руками в UI

Начиная с Grafana 12 дашборды хранятся в unified storage — таблица `resource` в
`grafana.db` (на NAS — `/volume2/grafana/grafana.db`, в
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
[`scrape.yaml`](../nas-monitoring/victoria-metrics/scrape.yaml) и выкладывают
через `ops/nas-monitoring/deploy.sh`.

## Алертинг

С 2026-11-09 алертинг Grafana выключен (`GF_UNIFIED_ALERTING_ENABLED=false` в
[`docker-compose.yaml`](../nas-monitoring/docker-compose.yaml), том провижининга
алертинга и Secret `grafana-alerting` убраны). Выключен, а не
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

Почта настраивается переменными окружения сервиса `grafana` в
[`docker-compose.yaml`](../nas-monitoring/docker-compose.yaml):

| Переменная | Значение |
|---|---|
| `GF_SMTP_ENABLED` | `true` |
| `GF_SMTP_HOST` | `smtp.gmail.com:587` |
| `GF_SMTP_USER` | Gmail-адрес |
| `GF_SMTP_PASSWORD__FILE` | `/run/secrets/smtp/smtp` (файл `/volume1/docker/monitoring/secrets/smtp` на NAS) |
| `GF_SMTP_FROM_ADDRESS` | тот же Gmail-адрес: `smtp.gmail.com` отправляет только от имени аутентифицированного пользователя |
| `GF_SMTP_FROM_NAME` | `Grafana - fleet.example` |

Пароль — app-password Google (16 символов, требует включённой двухэтапной
аутентификации). Файл на NAS копируется из Secret `grafana-smtp` (ключ `smtp`) в
k3s, как это сделать и как проверить длину — в
[`ops/nas-monitoring/README.md`](../nas-monitoring/README.md#секрет-smtp). Тот же
Secret использует Alertmanager: `ops/alerting/deploy.sh` копирует пароль из
`grafana-smtp` в Secret `alertmanager-smtp`, поэтому при ротации пароля
обновите Secret `grafana-smtp`, выполните `./ops/alerting/deploy.sh` и
обновите файл на NAS. Пароль подключён файлом, а не значением переменной:
значение видно в `docker inspect` и в `ps`, файл — нет. Суффикс `__FILE`
Grafana понимает для любой настройки.

Записывайте пароль строго без перевода строки. 17 байт вместо 16 означают, что
затесался `\n`: SMTP-аутентификация упадёт с «username and password not
accepted».

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
  `ssh sysadm@198.51.100.105 "docker exec grafana grafana cli admin reset-admin-password '<пароль>'"`.
