# VictoriaMetrics и Grafana на NAS

Compose-проект с VictoriaMetrics, Grafana и двумя контейнерами бэкапа. Работает на UGREEN NAS `198.51.100.105` (UGOS, docker) с 2026-11-09; до этого VictoriaMetrics и Grafana жили в k3s (namespace `monitoring`, данные на `local-path` узла `k3s-1`). Документ нужен владельцу парка, который выкатывает конфигурацию на NAS, обновляет дашборды или восстанавливает данные.

Реальные имена узлов, домены и адреса парка в этом документе заменены условными: `fleet.example` — домен парка; `198.51.100.0/24` — домашняя сеть (`.105` — NAS). Соответствие — в локальном некоммитируемом `FLEET.local.md`.

Требования:

- доступ по ssh на NAS как `sysadm` (uid 1000) с ключом; docker вызывается без `sudo`;
- `docker` с плагином compose на машине разработчика (`deploy.sh` проверяет файл через `docker compose config -q`);
- для секрета SMTP: `kubectl` и `KUBECONFIG=~/.kube/k3s-home.yaml` — Secret `grafana-smtp` в k3s остался.

## Состав

Проект `monitoring`, файлы на NAS лежат в `/volume1/docker/monitoring`.

| Контейнер | Порт | Данные | Бэкап |
|-----------|------|--------|-------|
| `victoria-metrics` | `8428` | `/volume2/victoria-metrics` (NVMe, shared folder с флагом `C`, без снапшотов) | `vmbackup` |
| `grafana` | `3000` | `/volume2/grafana` (NVMe, SQLite `grafana.db`, каталог дашбордов `dashboards/`) | `grafana-backup` |
| `vmbackup` | нет | читает `/volume2/victoria-metrics` через API снапшота VictoriaMetrics | `/volume1/k8s/backup/victoria-metrics` (HDD), ежедневно в `01:15` UTC, инкрементально; в `-dst` хранится одна копия, ротации нет |
| `grafana-backup` | нет | читает `/volume2/grafana/grafana.db` | `/volume1/k8s/backup/grafana/grafana-YYYYmmdd-HHMM.db.gz` (HDD), ежедневно в `00:30` UTC, хранит 7 последних (`KEEP = 7` в `backup/grafana-backup.py`) |

`vmbackup` держит в `-dst` одну инкрементальную копию: части, которых нет в новом снапшоте, он удаляет. Повреждённые или ошибочно удалённые данные попадают в бэкап в течение суток, и предыдущего состояния уже нет. Семь суточных файлов хранит только `grafana-backup`.

Время запуска бэкапов задано в UTC (`RUN_AT_UTC`): в busybox этих образов нет tzdata, имя пояса в `TZ` игнорировалось бы молча. `00:30` UTC — это 03:30 MSK, `01:15` UTC — 04:15 MSK. Значение проверяется при старте: всё, кроме `HH:MM` (00–23, 00–59), останавливает контейнер с сообщением `RUN_AT_UTC must be HH:MM in UTC, got '...'` в `docker logs`, и docker перезапускает его с нарастающей задержкой.

### Сигнал об успехе бэкапа

После успешного прогона оба контейнера пишут в VictoriaMetrics ряд `nas_backup_last_success_timestamp_seconds{backup="vmbackup"}` и `{backup="grafana"}` со временем успеха (Unix-секунды). Адрес задаёт переменная `PUSH_URL`, по умолчанию `http://victoria-metrics:8428/api/v1/import/prometheus`. Если записать не удалось, в лог идёт `could not report success to ...`, а сам бэкап считается успешным.

По этому ряду vmalert в k3s поднимает `BackupStale` (больше 26 часов без успеха) и `BackupMissing` (ни одной записи за 8 дней), см. [`ops/alerting/README.md`](../alerting/README.md#правила). Последний успех каждого бэкапа:

```bash
curl -s http://198.51.100.105:8428/api/v1/query \
  --data-urlencode 'query=time() - last_over_time(nas_backup_last_success_timestamp_seconds[8d])'
```

Значение — секунды с последнего успеха; в норме не больше 86400 плюс длительность прогона.

Образы закреплены по digest в `docker-compose.yaml` (VictoriaMetrics и vmbackup v1.155.0, Grafana v13.3.0, бэкап Grafana — `python:3.12-alpine`).

Связь с k3s:

- В k3s остались Service `victoria-metrics` и `grafana` в namespace `monitoring` без selector'а и вручную написанные EndpointSlice `victoria-metrics-nas` и `grafana-nas` с адресом NAS. Адреса `victoria-metrics.monitoring:8428` (vmalert, `smarthome/power`, `smarthome/humidity`) и ingress `vm.k3s.fleet.example`, `grafana.k3s.fleet.example` остались прежними. Манифесты: [`victoria-metrics-nas.yaml`](../nanopi-r5c-k3s/apps/monitoring/victoria-metrics-nas.yaml) и [`grafana-nas.yaml`](../nanopi-r5c-k3s/apps/monitoring/grafana-nas.yaml). Адрес NAS меняется правкой EndpointSlice.
- vmalert и Alertmanager остаются в k3s. VictoriaMetrics на NAS скрейпит их через Traefik (job `vmalert`, три реплики Alertmanager), а датасорс `alertmanager-k3s` в Grafana ходит на ingress Alertmanager; см. `victoria-metrics/scrape.yaml` и `grafana/datasources/datasources.yaml`.
- Датасорс `prometheus` (uid `adnsc1wi03doga`) указывает на `http://victoria-metrics:8428` внутри compose-сети. UID менять нельзя: дашборды ссылаются на него, и при другом UID все панели окажутся пустыми.

## Права на shared folders UGOS

Права на shared folders UGOS задаёт собственный ACL (xattr `system.ugacl_self`), а не биты режима. Проверено 2026-11-09 и 2026-11-10:

| uid | Кто | Запись в `/volume2/...` |
|-----|-----|-------------------------|
| 1000 | `sysadm` | разрешена |
| 472 | пользователь по умолчанию в образе Grafana | `Permission denied` |

Поэтому `victoria-metrics` и `vmbackup` запускаются как `1000:1000`, а `grafana` и `grafana-backup` как `1000:0` (`user:` в `docker-compose.yaml`). `chown`, `chmod` и `setfacl` права не меняют. Если контейнер падает с `Permission denied` на каталоге данных, правьте права в интерфейсе UGOS (параметры общей папки), а не командами [проверить: точное название раздела в UGOS].

## Выкладка конфигурации

`deploy.sh` копирует compose-файл и конфигурацию на NAS; `scp` работает с флагом `-O`, потому что UGOS отклоняет scp в режиме SFTP (`dest open: No such file`).

```bash
./ops/nas-monitoring/deploy.sh          # только копирование файлов
./ops/nas-monitoring/deploy.sh --up     # копирование, затем docker compose up -d
```

`--up` пересоздаёт контейнеры, у которых изменилась конфигурация, а это перезапуск VictoriaMetrics (около 1,5 минуты без приёма метрик по замеру переезда 2026-11-09) и Grafana (около 1 минуты). Запускайте с согласия владельца.

Если изменились только файлы в `backup/*` или `grafana/datasources/*`, `--up` ничего не пересоздаёт: compose не видит изменения в конфигурации контейнера (файлы приходят bind-mount'ом), а процессы читают их только при старте. Перезапустите нужный контейнер: `ssh sysadm@198.51.100.105 'cd /volume1/docker/monitoring && docker compose restart <service>'`, где `<service>` — `grafana-backup` или `vmbackup` для `backup/*`, `grafana` для `grafana/datasources/*` (`restart` контейнера `grafana` — тот же простой около 1 минуты). Правка `victoria-metrics/scrape.yaml` рестарта не требует, см. ниже.

Адрес NAS переопределяется переменной `NAS_HOST` (по умолчанию `sysadm@198.51.100.105`).

Каталоги конфигурации монтируются в контейнеры целиком, не отдельными файлами: bind-mount одиночного файла держит inode, и после замены файла через `scp` контейнер видит старую версию.

Проверка:

```bash
ssh sysadm@198.51.100.105 'cd /volume1/docker/monitoring && docker compose ps'
```

Все четыре контейнера в состоянии `Up`, у `victoria-metrics` статус `healthy`.

`scrape.yaml` перечитывается без рестарта: в compose задан `-promscrape.configCheckInterval=1m`, так что после `deploy.sh` изменения подхватываются в течение минуты. Состояние целей: `http://198.51.100.105:8428/targets`.

## Секрет SMTP

Пароль SMTP (app-password Google, 16 символов) в git не хранится. Grafana читает его из `/volume1/docker/monitoring/secrets/smtp` на NAS (в контейнере `/run/secrets/smtp/smtp`, переменная `GF_SMTP_PASSWORD__FILE`). `deploy.sh` завершается с ошибкой, если файла нет или он пуст.

Источник — Secret `grafana-smtp` (ключ `smtp`) в k3s. Тот же Secret использует `ops/alerting/deploy.sh` для `alertmanager-smtp`, поэтому из кластера его удалять нельзя.

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring get secret grafana-smtp -o jsonpath='{.data.smtp}' | base64 -d |
  ssh sysadm@198.51.100.105 'umask 077; mkdir -p /volume1/docker/monitoring/secrets && cat > /volume1/docker/monitoring/secrets/smtp'
ssh sysadm@198.51.100.105 'wc -c < /volume1/docker/monitoring/secrets/smtp'
```

Проверка: `wc -c` печатает `16`. Значение 17 означает, что в файл попал перевод строки, и SMTP-аутентификация падает с `username and password not accepted`. Новый пароль читается только при старте Grafana: `docker restart grafana`.

Пароль admin Grafana в compose не задан намеренно: он живёт в `grafana.db`, а `GF_SECURITY_ADMIN_PASSWORD` сбрасывал бы его при каждом старте. Сброс: `ssh sysadm@198.51.100.105 "docker exec grafana grafana cli admin reset-admin-password '<пароль>'"`.

## Обновление дашбордов

```bash
./ops/grafana/dashboards/deploy.sh --nas
ssh sysadm@198.51.100.105 'docker restart grafana'
ssh sysadm@198.51.100.105 'docker logs --since 2m grafana 2>&1 | grep "provision dashboards"'
```

Скрипт копирует JSON в `/volume2/grafana/dashboards` (в контейнере `/var/lib/grafana/dashboards`). Без аргументов он берёт дашборды из трёх мест: `ops/grafana/dashboards/`, `bins/outline-ss-rust/grafana/` и `bins/outline-ws-rust/grafana/`. Провайдер стоит с `disableDeletion: false`, поэтому дашборд, которого нет в каталоге, удаляется из базы при следующем старте Grafana. Выкладывайте все три источника разом; при передаче отдельных файлов остальные остаются в каталоге нетронутыми.

Без рестарта изменения не видны: провижининг выполняется только при старте. Рестарт Grafana — действие на проде, согласуйте с владельцем.

## Восстановление

Данные после восстановления откатываются к моменту последнего бэкапа: до 24 часов потерь для VictoriaMetrics (бэкап в `01:15` UTC) и для Grafana (в `00:30` UTC). Все команды выполняются на NAS под `sysadm`.

### VictoriaMetrics

1. Остановите контейнеры, которые работают с каталогом данных:

   ```bash
   cd /volume1/docker/monitoring && docker compose stop vmbackup victoria-metrics
   ```

2. Запустите `vmrestore` (по тегу, он нужен только для разовых запусков). Каталог данных должен быть пуст или `vmrestore` откажется перезаписывать его [проверить: поведение v1.155.0 на непустом `-storageDataPath`; при необходимости переименуйте старый каталог].

   ```bash
   docker run --rm --user 1000:1000 \
     -v /volume2/victoria-metrics:/victoria-metrics-data \
     -v /volume1/k8s/backup:/backup \
     victoriametrics/vmrestore:v1.155.0 \
     -src=fs:///backup/victoria-metrics -storageDataPath=/victoria-metrics-data
   ```

   `vmrestore` на NAS ещё не запускался [проверить: прогон на копии каталога].

3. Запустите контейнеры: `docker compose start victoria-metrics vmbackup`.

Проверка: `curl -s http://198.51.100.105:8428/health` отвечает `OK`; в `http://198.51.100.105:8428/targets` цели в состоянии `up`; графики за прошлые недели не пусты.

### Grafana

1. Остановите контейнеры: `docker compose stop grafana grafana-backup`.
2. Выберите копию и распакуйте её вместо базы. Файлы `-wal` и `-shm` остаются от старой базы и испортят новую, их удаляют.

   ```bash
   ls -lh /volume1/k8s/backup/grafana/
   cd /volume2/grafana
   rm -f grafana.db-wal grafana.db-shm
   gunzip -c /volume1/k8s/backup/grafana/grafana-<YYYYmmdd-HHMM>.db.gz > grafana.db
   ```

   `<YYYYmmdd-HHMM>` — метка выбранной копии, например `20261110-0030`.

3. Запустите: `docker compose start grafana grafana-backup`.

Проверка: `docker logs --since 1m grafana` без `level=error`; вход под прежним паролем admin; ручные дашборды (`Power`, `Temperature`, `Node Exporter Full`, `Tunnels`, `Outline`, `VictoriaMetrics`, `Xray Dashboard`) на месте. Они живут только в базе и отсутствуют в git, их копия есть лишь в бэкапе.

Целостность последней копии: `gunzip -c <файл>.db.gz > /tmp/g.db && sqlite3 /tmp/g.db 'PRAGMA integrity_check'` [проверить: на NAS может не быть утилиты `sqlite3`; тогда `python3 -c`]. Копия `grafana-20261110-0030.db.gz` проверена 2026-11-10: `integrity_check` вернул `ok`.

## Откат в k3s

Условие: NAS недоступен или данные на нём потеряны. Старые объекты в k3s удалены 2026-11-10 вместе с PVC `victoria-metrics-data` и `grafana-data`, данные на `local-path` не сохранились. Откат пересоздаёт их из git и наполняет из бэкапов на NAS. Каждый шаг — действие на проде, только с согласия владельца. Если NAS не загружается, бэкапы на его HDD недоступны, и восстановить данные нечем.

Манифесты до переезда лежат в коммите `a6aa553f~1` (проверено: в нём все пять файлов `victoria-metrics.yaml`, `grafana.yaml`, `grafana-provisioning.yaml`, `grafana-backup.yaml`, `victoria-metrics-backup.yaml`, а также `scrape.yaml`, который затем переехал в `ops/nas-monitoring/victoria-metrics/`).

1. Остановите запись в общие бэкапы с NAS, чтобы два `vmbackup` не писали в один каталог: `docker compose stop` в `/volume1/docker/monitoring` (если NAS жив).

2. Уберите из репозитория манифесты NAS и верните Service. Удалите (или переименуйте во вне-`*.yaml`, например `.disabled`) `ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics-nas.yaml` и `ops/nanopi-r5c-k3s/apps/monitoring/grafana-nas.yaml`, а изменения Service из серии переезда откатите через `git revert`. `apps/deploy.sh apps` применяет весь каталог `monitoring/` (`apply_dir` берёт каждый `*.yaml`), и при следующей раскатке `kubectl apply` для `victoria-metrics-nas.yaml` и `grafana-nas.yaml` выполнит трёхсторонний merge: в манифесте нет `selector`, а в last-applied он был, поэтому `selector` исчезнет из Service, и тот снова будет указывать на NAS через EndpointSlice. Тот же `apply_dir` заново создаст и удалённые срезы.

3. Достаньте манифесты из истории:

   ```bash
   export KUBECONFIG=~/.kube/k3s-home.yaml
   mkdir -p /tmp/rollback
   for f in victoria-metrics grafana grafana-provisioning grafana-backup victoria-metrics-backup scrape; do
     git show a6aa553f~1:ops/nanopi-r5c-k3s/apps/monitoring/$f.yaml > /tmp/rollback/$f.yaml
   done
   ```

4. Удалите EndpointSlice, указывающие на NAS: у Service с selector'ом их ведёт контроллер, а ручные срезы добавили бы NAS в бэкенды.

   ```bash
   kubectl -n monitoring delete endpointslice victoria-metrics-nas grafana-nas
   ```

5. Примените манифесты с `replicas: 0`. В `victoria-metrics.yaml` и `grafana.yaml` из `a6aa553f~1` стоит `replicas: 1` (строки 17 и 21), и после `kubectl apply` поды стартовали бы на пустых PVC: VictoriaMetrics создала бы пустую TSDB, Grafana — новую `grafana.db`, и `vmrestore` с `gunzip` потом писали бы в каталоги данных работающих процессов. Поэтому правьте число реплик до `apply` (Service заменит selector-less на обычный; одноимённые Ingress перезапишутся):

   ```bash
   cd /tmp/rollback
   for f in victoria-metrics grafana; do
     sed 's/^  replicas: 1$/  replicas: 0/' $f.yaml | kubectl apply -f -
   done
   kubectl apply -f grafana-provisioning.yaml -f grafana-backup.yaml -f victoria-metrics-backup.yaml
   kubectl -n monitoring get deploy victoria-metrics grafana
   ```

   В выводе `READY 0/0` у обоих Deployment'ов. Если не `0/0`, остановите их сразу: `kubectl -n monitoring scale deploy/victoria-metrics deploy/grafana --replicas=0`. Команда не прогонялась [проверить: `sed` меняет ровно одну строку в каждом файле — `diff <(cat f.yaml) <(sed ... f.yaml)` до `apply`]. CronJob'ы `vmbackup` и `grafana-backup` из `grafana-backup.yaml` и `victoria-metrics-backup.yaml` начнут работать по расписанию, пока тома пусты; если до восстановления наступит их время (расписание `vmbackup` в старом манифесте — `15 4 * * *`), поставьте `for c in vmbackup grafana-backup; do kubectl -n monitoring patch cronjob $c -p '{"spec":{"suspend":true}}'; done` [проверить: на живом кластере] и снимите `suspend` после шага 7: `vmbackup` на пустой TSDB удалил бы из `-dst` всё, чего нет в снапшоте.

   Дашборды Grafana в k3s были ConfigMap'ами `grafana-dashboard-<имя>`, а режим `--k3s` удалён из `deploy.sh`. Верните его временно из истории: `git show a6aa553f:ops/grafana/dashboards/deploy.sh > ops/grafana/dashboards/deploy-k3s.sh`, запустите `bash ops/grafana/dashboards/deploy-k3s.sh --k3s` (скрипт делает `cd` в свой каталог и ищет `bins/*/grafana` относительно него) и затем удалите временный файл. Список ConfigMap'ов в `grafana.yaml` из `a6aa553f~1` должен совпасть с набором дашбордов [проверить: дашборды, добавленные после 2026-11-09, надо дописать в projected volume `dashboards` — скрипт печатает нужные строки].


6. Наполните тома. PVC на `local-path` привязывается к узлу при первом использовании, поэтому разовые Job'ы прибивайте к `k3s-1`, как и Deployment'ы. Бэкапы подключайте тем же NFS-томом, что и старые CronJob'ы (`198.51.100.105:/volume1/k8s/backup`).

   VictoriaMetrics (`vmrestore` + возврат `scrape.yaml` в корень тома, потому что в бэкап он не входит):

   ```yaml
   apiVersion: batch/v1
   kind: Job
   metadata: { name: vmrestore, namespace: monitoring }
   spec:
     backoffLimit: 0
     template:
       spec:
         restartPolicy: Never
         nodeSelector: { kubernetes.io/hostname: k3s-1 }
         securityContext: { runAsUser: 1000, fsGroup: 1000 }
         containers:
           - name: vmrestore
             image: victoriametrics/vmrestore:v1.155.0
             args: ["-src=fs:///backup/victoria-metrics", "-storageDataPath=/victoria-metrics-data"]
             volumeMounts:
               - { name: data, mountPath: /victoria-metrics-data }
               - { name: backup, mountPath: /backup }
         volumes:
           - { name: data, persistentVolumeClaim: { claimName: victoria-metrics-data } }
           - { name: backup, nfs: { server: 198.51.100.105, path: /volume1/k8s/backup } }
   ```

   Grafana (распаковка копии в том; владелец `472`, под которым запускался Deployment в k3s; `-wal` и `-shm` удаляются до копирования, иначе остатки старой базы испортят новую):

   ```yaml
   apiVersion: batch/v1
   kind: Job
   metadata: { name: grafana-restore, namespace: monitoring }
   spec:
     backoffLimit: 0
     template:
       spec:
         restartPolicy: Never
         nodeSelector: { kubernetes.io/hostname: k3s-1 }
         containers:
           - name: restore
             image: python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df
             command: ["sh", "-c", "cd /data && rm -f grafana.db-wal grafana.db-shm && gunzip -c /backup/grafana/grafana-<YYYYmmdd-HHMM>.db.gz > grafana.db && chown 472:472 grafana.db"]
             volumeMounts:
               - { name: data, mountPath: /data }
               - { name: backup, mountPath: /backup }
         volumes:
           - { name: data, persistentVolumeClaim: { claimName: grafana-data } }
           - { name: backup, nfs: { server: 198.51.100.105, path: /volume1/k8s/backup } }
   ```

   Оба Job'а в этом виде не прогонялись [проверить: на пустом PVC, до боевого отката]. `scrape.yaml` положите в корень тома VictoriaMetrics тем же способом (второй Job с `cp` из ConfigMap или `kubectl cp` в Job-под) [проверить: как scrape.yaml доставлялся в PVC до переезда; в репозитории способ не описан]. Версию `scrape.yaml` из `a6aa553f~1` перед этим сверьте с `ops/nas-monitoring/victoria-metrics/scrape.yaml`: в переезд правились цели `grafana`, `vmalert`, `alertmanager`, а job `alertmanager` с тех пор переведён на три реплики.

7. Верните реплики: `kubectl -n monitoring scale deploy/victoria-metrics deploy/grafana --replicas=1`.

Проверка:

```bash
kubectl -n monitoring get pods,pvc
kubectl -n monitoring exec deploy/victoria-metrics -- wget -qO- http://127.0.0.1:8428/health
kubectl -n monitoring logs deploy/grafana --since=2m | grep "provision"
```

`victoria-metrics` и `grafana` в `Running`, PVC в `Bound`, health отвечает `OK`, в логе vmalert нет ошибок обращения к `victoria-metrics.monitoring:8428`.

Пока поднято только одно из двух мест (NAS или k3s), второе должно быть остановлено: два `vmbackup` пишут в один каталог `/volume1/k8s/backup/victoria-metrics`, и бэкап одного из них не соответствует данным другого.

## Известные проблемы

- Автозапуск после перезагрузки NAS не проверялся. Контейнеры идут с `restart: unless-stopped`, но порядок старта docker и монтирования `/volume2` и `/volume1` в UGOS после ребута не проверен. После первой перезагрузки NAS проверьте `docker compose ps` и права на `/volume2/grafana`.
- Grafana 13 пишет в лог `status=501` на запросы `/apis/quotas.grafana.app/...` из браузерного интерфейса. На работу дашбордов это не влияет.
- Доступ к shared folders определяет UGOS ACL, а не режим файла: контейнер с uid 472 получает `Permission denied`, см. раздел «Права на shared folders UGOS».
- `scp` без `-O` падает с `dest open: No such file`: UGOS отклоняет SFTP-режим. Все скрипты в проекте используют `scp -O`.
- Бэкапы лежат на HDD того же NAS. Потеря NAS уносит данные и бэкапы вместе; копии вне NAS нет.
