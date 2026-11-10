# Бэкап Jellyfin с NVMe на HDD

Контейнер `jellyfin-backup` раз в сутки копирует данные приложения UGOS
`com.ugreen.docker.jellyfin` с NVMe (`/volume2`) на HDD (`/volume1`). Узел:
UGREEN DXP4800 Plus `198.51.100.105`, Jellyfin 12.2.0 (образ `ugreen/jellyfin:12.2`).

Реальные адреса парка в этом документе заменены условными: `198.51.100.0/24` — домашняя сеть (`.105` — последний октет). Соответствие — в локальном некоммитируемом `FLEET.local.md`. В `docker-compose.yaml` и `deploy.sh` адреса настоящие.

Исходники — в этом каталоге репозитория; на NAS их копирует `deploy.sh` в `/volume1/docker/jellyfin-backup`. Файлы на NAS руками не правьте: следующая выкладка их перезапишет.

## Что копируется

| Источник на NAS | Куда | Хранение |
|---|---|---|
| `/volume2/@appstore/com.ugreen.docker.jellyfin/config/data/jellyfin.db` | `data/jellyfin.db` в архиве | снимок через sqlite3 backup API, Jellyfin не останавливается |
| `.../config/config` (`system.xml`, `encoding.xml`, `network.xml`) | `config/` в архиве | |
| `.../config/root` (библиотеки, `options.xml`) | `root/` в архиве | |
| остальное из `.../config/data`, кроме `jellyfin.db*` и `library.db*` | `data/` в архиве | |
| `/volume2/jellyfin/plugins` (Plugin path) | `plugins/` в архиве | |
| `.../config/metadata` (постеры, NFO) | `/volume1/k8s/backup/jellyfin/metadata` | инкрементальное зеркало, одна копия |

Архивы: `/volume1/k8s/backup/jellyfin/jellyfin-YYYYMMDD-HHMM.tar.gz`, время в
имени в UTC. Хранятся последние 14 (`KEEP`). Архив около 20 МБ, зеркало
метаданных около 590 МБ (2026-11-09).

Не копируются `config/log` и `/volume2/@appstore/com.ugreen.docker.jellyfin/cache`:
Jellyfin создаёт их заново.

Запуск в 01:45 UTC (04:45 МСК), после `grafana-backup` (03:30 МСК) и
`vmbackup` (04:15 МСК) из `/volume1/docker/monitoring`.

## Управление

Выкладка с рабочей машины, из корня репозитория:

```bash
ops/nas-jellyfin-backup/deploy.sh          # только скопировать файлы
ops/nas-jellyfin-backup/deploy.sh --up     # скопировать и перезапустить контейнер
```

`--up` выполняет `docker compose up -d` и затем `docker compose restart jellyfin-backup`: скрипт приходит bind-mount'ом каталога, compose не видит в нём изменения конфигурации, а запущенный цикл держит старый код до рестарта. Рестарт не трогает Jellyfin, только контейнер бэкапа. Адрес NAS переопределяется переменной `NAS_HOST` (по умолчанию `sysadm@198.51.100.105`).

Остальные команды — на NAS от `sysadm` в каталоге `/volume1/docker/jellyfin-backup`.

Снимок прямо сейчас, вне расписания:

```bash
docker compose run --rm -e ONCE=1 jellyfin-backup
```

Последний прогон по расписанию:

```bash
docker logs --tail 20 jellyfin-backup
```

В логе успешного прогона есть строки `written ...tar.gz`, `kept: N` и
`metadata mirror: X copied, Y removed`. При ошибке: `jellyfin backup failed: ...`,
цикл при этом продолжает работать и повторит попытку на следующие сутки.

После успешного прогона скрипт пишет в VictoriaMetrics ряд `nas_backup_last_success_timestamp_seconds{backup="jellyfin"}` со временем успеха. Адрес — переменная `PUSH_URL` в `docker-compose.yaml`: `http://198.51.100.105:8428/api/v1/import/prometheus`, по IP хоста, потому что имя `victoria-metrics` есть только в docker-сети проекта `monitoring`. Без `PUSH_URL` скрипт не стартует (`KeyError: 'PUSH_URL'`). Если записать не удалось, в логе `could not report success to ...`, бэкап при этом считается успешным. Алерты по этому ряду (`BackupStale` через 26 часов без успеха, `BackupMissing` через 8 дней без записей) описаны в [`ops/alerting/README.md`](../alerting/README.md#правила).

`RUN_AT_UTC` проверяется при старте: значение не в формате `HH:MM` останавливает контейнер с сообщением `RUN_AT_UTC must be HH:MM in UTC, got '...'`.

## Восстановление

1. Остановите Jellyfin:
   ```bash
   docker stop jellyfin-app-1
   ```
2. Распакуйте нужный архив поверх `config` и верните метаданные и плагины.
   Файлы `config` принадлежат root, поэтому через одноразовый контейнер:
   ```bash
   docker run --rm -v /volume1:/v1 -v /volume2:/v2 alpine sh -c '
   set -e
   A=/v2/@appstore/com.ugreen.docker.jellyfin/config
   B=/v1/k8s/backup/jellyfin
   ARCH=$B/jellyfin-<YYYYMMDD-HHMM>.tar.gz
   rm -f $A/data/jellyfin.db $A/data/jellyfin.db-wal $A/data/jellyfin.db-shm
   mkdir -p /tmp/r && tar -xzf $ARCH -C /tmp/r
   cp -a /tmp/r/config /tmp/r/root /tmp/r/data $A/
   cp -a /tmp/r/plugins/. /v2/jellyfin/plugins/
   mkdir -p $A/metadata && cp -a $B/metadata/. $A/metadata/
   '
   ```
   `<YYYYMMDD-HHMM>` — метка архива из `ls /volume1/k8s/backup/jellyfin`.
   Старые `-wal` и `-shm` удаляются до копирования: иначе SQLite применит к
   восстановленной базе журнал от другой.
3. Запустите Jellyfin и проверьте, что мастер первого запуска не открылся:
   ```bash
   docker start jellyfin-app-1
   curl -s http://127.0.0.1:8899/System/Info/Public
   ```
   В ответе должно быть `"StartupWizardCompleted":true`.

Если приложение переустанавливалось из Центра приложений, сначала проверьте,
что пути в `docker-compose.yaml` выше совпадают с новыми: `docker inspect
jellyfin-app-1` → `Mounts`. Порядок папок в Resource access path: первой
должна быть `jellyfin/data`, затем `Movies` и `Movies_TV`, иначе шаблон UGOS
смонтирует `Movies` в `/data` и библиотека «Фильмы» потеряет путь.

## Известные особенности

- Контейнер работает от root: файлы Jellyfin принадлежат root, а SQLite при
  чтении пишет `jellyfin.db-shm`. По той же причине `config` смонтирован на
  запись. Результаты передаются `OWNER_UID:OWNER_GID` (1000:0, `sysadm`).
- Внутри контейнера режимы каталогов на `/volume1` выглядят как `drwx------`:
  доступ определяет ACL UGOS (`system.ugacl_self`), с хоста каталоги доступны.
