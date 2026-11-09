# Перенос Grafana и VictoriaMetrics из k3s в docker на NAS: план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Цель:** VictoriaMetrics и Grafana переезжают из namespace `monitoring` кластера k3s (под на `k3s-1`, `local-path`) в docker compose на NAS `198.18.1.105` с данными на NVMe `/volume2`. Имена `vm.k3s.beerloga.su`, `grafana.k3s.beerloga.su` и внутрикластерные `victoria-metrics.monitoring:8428`, `grafana.monitoring:3000` продолжают работать.

**Архитектура:** на NAS один compose-проект `monitoring`: `victoria-metrics`, `grafana` и два контейнера ночных бэкапов. В k3s Service'ы `victoria-metrics` и `grafana` теряют селектор и смотрят на NAS через EndpointSlice, заданный вручную. Ingress'ы остаются как есть, а vmalert, power и humidity продолжают ходить на прежнее ClusterIP-имя. vmalert и Alertmanager остаются в k3s и получают Ingress'ы, чтобы VictoriaMetrics на NAS могла их скрейпить, а Grafana — открыть Alertmanager как источник данных.

**Стек:** Docker 29.6.2 + Compose v5.1.3 на UGOS (DXP4800 Plus, 6 CPU, 7,7 ГБ RAM), VictoriaMetrics/vmbackup/vmrestore v1.155.0, Grafana 13.3.0, k3s v1.36.2, Traefik v3.7.10 (чарт 41.2.0).

## Глобальные ограничения

- Образы те же, что сейчас в k3s, и закреплены по digest:
  - `victoriametrics/victoria-metrics@sha256:f60dc268b54ecf87f6e09d740c2b732838aa9193090cc741417c9f6386a130df` (v1.155.0)
  - `victoriametrics/vmbackup@sha256:26af85b273442e15e5172769979998ad98486706051acbe7826cd3a8c5d83bca` (v1.155.0)
  - `grafana/grafana@sha256:488984b716c0862639f91a698adbe2862677a5a07bad42da5f03f3030883b205` (v13.3.0)
  - `python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df` (3.12-alpine)
  - `victoriametrics/vmrestore:v1.155.0` — по тегу, только для разовых запусков руками.
- UID контейнеров на NAS: VictoriaMetrics и vmbackup `1000:1000`, Grafana и её бэкап `1000:0`. Права в shared folders UGOS задаёт собственный ACL (`system.ugacl_self`), а не биты режима: uid 472 (по умолчанию в образе Grafana) получает `Permission denied`, uid 1000 (`sysadm`) пишет. Проверено 2026-11-09. `chown`/`chmod`/`setfacl` эти права не меняют.
- Каталоги данных — shared folders на NVMe, созданные в интерфейсе UGOS: `/volume2/victoria-metrics` (флаг `C`, без снапшотов) и `/volume2/grafana`. Бэкапы — на HDD, в `/volume1/k8s/backup/{victoria-metrics,grafana}`, в те же каталоги, куда их пишут CronJob'ы k3s. Поэтому `vmbackup` остаётся инкрементальным.
- Compose-проект на NAS лежит в `/volume1/docker/monitoring`. Файлы конфигурации монтировать каталогами, а не отдельными файлами: bind-mount одиночного файла держит inode, и после замены файла контейнер продолжает видеть старую версию.
- Любой `kubectl apply/scale/patch`, `docker compose up` на NAS или остановка сервиса — действие на проде. Выполнять только после явного «да» владельца на конкретную задачу (AGENTS.md, «Выкатка на хосты»; память: `no-prod-restarts-without-approval`).
- Коммиты только по команде владельца, только своими путями: `git commit -- <paths>`. Перед push — `git log origin/main..main`. Без трейлера Co-Authored-By.
- Секреты в git не попадают: пароль SMTP копируется из Secret `grafana-smtp` (ключ `smtp`) в `/volume1/docker/monitoring/secrets/smtp` на NAS.
- Время в контейнерах бэкапов — UTC (в busybox нет tzdata). 03:30 MSK = `00:30` UTC, 04:15 MSK = `01:15` UTC.
- Документация в `ops/**` ведётся только на русском, пар `*.ru.md` там нет. Если правка заденет файл, у которого есть пара, обновлять обе стороны.

## Что проверено до написания плана (2026-11-09)

| Вопрос | Результат |
|---|---|
| Порты 3000 и 8428 на NAS | свободны (`ss -ltn`) |
| Скрейп-цели доступны с NAS | все 14 проверенных отвечают 200: node-exporter `.102/.104/.51`, `:9486`, `:9090`, `:9091` на `.102/.104`, `https://{cloud1,cloud2,nuxt,nuxt2}.beerloga.su/.../metrics` |
| DNS на NAS | `*.k3s.beerloga.su` → `198.18.1.200` (резолвер `127.0.0.1`, затем `198.18.1.1`) |
| Запись uid 1000 в `/volume1/k8s/backup` из контейнера | работает, там уже лежат бэкапы `victoria-metrics` (формат vmbackup) и `grafana` |
| Запись в `/volume1/docker` под `sysadm` | работает |
| `/bin/sh` в образе vmbackup | есть (busybox) |
| Объём данных | VM 2,0 ГБ, Grafana 16,7 МБ (`grafana.db` 12,9 МБ + WAL) |
| Кто ходит на `victoria-metrics.monitoring` | vmalert (`-datasource.url`, `-remoteRead.url`, `-remoteWrite.url`), `smarthome/power`, `smarthome/humidity`, источник данных Grafana |
| Чего стоит простой VM | правило `DeadMansSwitch` гаснет примерно через 4 мин после недоступности VM, наблюдатели на cloud1/2 шлют письмо после 15 мин тишины (`heartbeat-watch --threshold 900`). Окно переключения VM должно быть меньше ~10 мин |

## Файлы

| Путь | Что |
|---|---|
| `ops/nas-monitoring/docker-compose.yaml` | создать: compose-проект на NAS |
| `ops/nas-monitoring/victoria-metrics/scrape.yaml` | перенести `git mv` из `ops/nanopi-r5c-k3s/apps/monitoring/scrape.yaml` и поправить цели `grafana`, `vmalert`, `alertmanager` |
| `ops/nas-monitoring/grafana/datasources/datasources.yaml` | создать: источники данных (UID `adnsc1wi03doga` не менять) |
| `ops/nas-monitoring/grafana/dashboards-provider/outline.yaml` | создать: провайдер дашбордов из `/var/lib/grafana/dashboards` |
| `ops/nas-monitoring/backup/vmbackup-loop.sh` | создать: ежедневный запуск `vmbackup` |
| `ops/nas-monitoring/backup/grafana-backup.py` | создать: ежедневный бэкап `grafana.db` (логика из CronJob `grafana-backup`) |
| `ops/nas-monitoring/deploy.sh` | создать: копирование проекта на NAS и `docker compose up -d` |
| `ops/nas-monitoring/README.md` | создать: схема, запуск, восстановление, откат |
| `ops/grafana/dashboards/deploy.sh` | изменить: режим `--nas` |
| `ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml` | изменить: Ingress `vmalert`, `alertmanager` |
| `ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics-nas.yaml` | создать: Service без селектора + EndpointSlice + Ingress `vm` |
| `ops/nanopi-r5c-k3s/apps/monitoring/grafana-nas.yaml` | создать: Service без селектора + EndpointSlice + Ingress `grafana` |
| `ops/nanopi-r5c-k3s/apps/monitoring/{victoria-metrics,grafana,grafana-provisioning,grafana-backup,victoria-metrics-backup}.yaml` | на время проверки `replicas: 0`, `suspend: true`, Service/Ingress убрать; после проверки удалить |
| `ops/nanopi-r5c-k3s/apps/README.md`, `ops/nanopi-r5c-k3s/apps/ingress/README.md`, `ops/grafana/README.md` | изменить: где теперь живут VM и Grafana |

---

### Задача 1: предполётная проверка (прод не трогаем)

**Files:** нет.

- [ ] **Шаг 1: сверить живой scrape-конфиг с репозиторием.** В k3s VM читает `scrape.yaml` из своего PVC, а не из git.

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring exec deploy/victoria-metrics -- cat /victoria-metrics-data/scrape.yaml \
  | diff - ops/nanopi-r5c-k3s/apps/monitoring/scrape.yaml && echo SAME
```

Ожидается: `SAME`. Если есть разница, сначала перенести её в репозиторий (живой файл — правда) и только потом продолжать.

- [ ] **Шаг 2: скачать образы на NAS и проверить архитектуру.** NAS — x86_64, digest'ы выше — image index.

```bash
ssh sysadm@198.18.1.105 'for i in \
  victoriametrics/victoria-metrics@sha256:f60dc268b54ecf87f6e09d740c2b732838aa9193090cc741417c9f6386a130df \
  victoriametrics/vmbackup@sha256:26af85b273442e15e5172769979998ad98486706051acbe7826cd3a8c5d83bca \
  victoriametrics/vmrestore:v1.155.0 \
  grafana/grafana@sha256:488984b716c0862639f91a698adbe2862677a5a07bad42da5f03f3030883b205 \
  python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df; do
  docker pull -q "$i" && docker image inspect -f "{{.Architecture}} $i" "$i"; done'
```

Ожидается: пять строк `amd64 …`.

- [ ] **Шаг 3: проверить, что в образе VictoriaMetrics есть `wget`** (на нём держится healthcheck в compose).

```bash
ssh sysadm@198.18.1.105 'docker run --rm --entrypoint /bin/sh victoriametrics/victoria-metrics@sha256:f60dc268b54ecf87f6e09d740c2b732838aa9193090cc741417c9f6386a130df -c "command -v wget"'
```

Ожидается: `/usr/bin/wget` или `/bin/wget`. Если пусто, убрать `healthcheck` у `victoria-metrics` в задаче 2 и заменить `depends_on.condition: service_healthy` на `service_started`.

- [ ] **Шаг 4: положить пароль SMTP на NAS.**

```bash
ssh sysadm@198.18.1.105 'mkdir -p /volume1/docker/monitoring/secrets && chmod 700 /volume1/docker/monitoring/secrets'
kubectl -n monitoring get secret grafana-smtp -o jsonpath='{.data.smtp}' | base64 -d \
  | ssh sysadm@198.18.1.105 'umask 077; cat > /volume1/docker/monitoring/secrets/smtp'
ssh sysadm@198.18.1.105 'wc -c /volume1/docker/monitoring/secrets/smtp'
```

Ожидается: ненулевой размер (пароль приложения Gmail — 16 символов, без перевода строки).

---

### Задача 2: compose-проект для NAS

**Files:**
- Create: `ops/nas-monitoring/docker-compose.yaml`
- Move + modify: `ops/nanopi-r5c-k3s/apps/monitoring/scrape.yaml` → `ops/nas-monitoring/victoria-metrics/scrape.yaml`
- Create: `ops/nas-monitoring/grafana/datasources/datasources.yaml`
- Create: `ops/nas-monitoring/grafana/dashboards-provider/outline.yaml`
- Create: `ops/nas-monitoring/deploy.sh`

**Interfaces:**
- Produces: имена контейнеров/сервисов `victoria-metrics` (порт 8428) и `grafana` (порт 3000) в сети compose-проекта `monitoring`; каталог проекта на NAS `/volume1/docker/monitoring`; `deploy.sh [--up]`.

- [ ] **Шаг 1: перенести scrape-конфиг.**

```bash
mkdir -p ops/nas-monitoring/victoria-metrics
git mv ops/nanopi-r5c-k3s/apps/monitoring/scrape.yaml ops/nas-monitoring/victoria-metrics/scrape.yaml
```

- [ ] **Шаг 2: поправить три цели в `ops/nas-monitoring/victoria-metrics/scrape.yaml`.** Остальные задания не трогать.

Задание `grafana` — ClusterIP больше не резолвится, Grafana теперь в той же сети compose:

```yaml
- job_name: grafana
  static_configs:
  - targets:
    # Same compose project on the NAS: plain service name, no ingress.
    - grafana:3000
    labels:
      hostname: 'ubuntu'
  relabel_configs:
    - source_labels: [hostname]
      target_label: instance
```

Задания `vmalert` и `alertmanager` (в конце файла) заменить на:

```yaml
- job_name: vmalert
  static_configs:
  - targets:
    # vmalert stays in k3s; the NAS reaches it through Traefik. No hairpin
    # here: the NAS is outside the cluster.
    - https://vmalert.k3s.beerloga.su/metrics
  relabel_configs:
    # Keep the instance value the series had while scraped by ClusterIP, so
    # history does not split into two series at the move.
    - target_label: instance
      replacement: vmalert.monitoring:8880
- job_name: alertmanager
  static_configs:
  - targets:
    - https://alertmanager.k3s.beerloga.su/metrics
  relabel_configs:
    - target_label: instance
      replacement: alertmanager.monitoring:9093
```

- [ ] **Шаг 3: проверить конфиг самой VictoriaMetrics.**

```bash
docker run --rm -v "$PWD/ops/nas-monitoring/victoria-metrics:/cfg:ro" \
  victoriametrics/victoria-metrics@sha256:f60dc268b54ecf87f6e09d740c2b732838aa9193090cc741417c9f6386a130df \
  -promscrape.config=/cfg/scrape.yaml -promscrape.config.dryRun
echo rc=$?
```

Ожидается: `rc=0`, в выводе нет `cannot parse`.

- [ ] **Шаг 4: источники данных Grafana** — `ops/nas-monitoring/grafana/datasources/datasources.yaml`:

```yaml
# Datasources for the NAS Grafana.
#
# The datasource UID is not cosmetic: dashboards reference datasources by UID,
# and the migrated ones all point at adnsc1wi03doga. Change it and every panel
# comes up empty.
apiVersion: 1
datasources:
  - name: prometheus
    uid: adnsc1wi03doga
    type: prometheus
    access: proxy
    # Same compose project: service name, no ingress.
    url: http://victoria-metrics:8428
    isDefault: true
    jsonData:
      timeInterval: 15s
  - name: alertmanager
    uid: alertmanager-k3s
    type: alertmanager
    access: proxy
    # Alertmanager stays in k3s and is reached through Traefik.
    url: https://alertmanager.k3s.beerloga.su
    jsonData:
      implementation: prometheus
      handleGrafanaManagedAlerts: false
```

- [ ] **Шаг 5: провайдер дашбордов** — `ops/nas-monitoring/grafana/dashboards-provider/outline.yaml`:

```yaml
# Dashboards come from /var/lib/grafana/dashboards, i.e. the dashboards/
# subdirectory of the /volume2/grafana shared folder. ops/grafana/dashboards/
# deploy.sh --nas copies them there. Provisioning runs only at startup, so the
# container has to be restarted after a copy.
apiVersion: 1
providers:
  - name: outline
    orgId: 1
    type: file
    # A deleted file removes the dashboard: the directory is the single source
    # of truth. Hand-made dashboards live in the database and are untouched.
    disableDeletion: false
    allowUiUpdates: false
    options:
      path: /var/lib/grafana/dashboards
      foldersFromFilesStructure: false
```

- [ ] **Шаг 6: `ops/nas-monitoring/docker-compose.yaml`.** Сервисы бэкапов добавляются в задаче 3.

```yaml
# VictoriaMetrics + Grafana on the UGREEN NAS 198.18.1.105, moved out of k3s
# (see README.md). k3s keeps the names: the Services victoria-metrics and
# grafana in namespace monitoring point here through hand-written
# EndpointSlices.
#
# UIDs: the shared folders are governed by the UGOS ACL (system.ugacl_self),
# not by mode bits. uid 1000 (sysadm) may write, the Grafana image's own uid
# 472 may not, hence user: "1000:0" for Grafana.
name: monitoring

services:
  victoria-metrics:
    image: victoriametrics/victoria-metrics@sha256:f60dc268b54ecf87f6e09d740c2b732838aa9193090cc741417c9f6386a130df # v1.155.0
    container_name: victoria-metrics
    user: "1000:1000"
    command:
      - -storageDataPath=/victoria-metrics-data
      - -retentionPeriod=90d
      - -inmemoryDataFlushInterval=60s
      # Measured 2026-08-11: all caches hold 182Mi at 28k active series, so
      # 320MB is about double the working set. See the k3s manifest history.
      - -memory.allowedBytes=320MB
      # Directory mount, not a file mount: a replaced file would stay invisible
      # behind the old inode.
      - -promscrape.config=/etc/victoria-metrics/scrape.yaml
      - -promscrape.configCheckInterval=1m
    ports:
      - "8428:8428"
    volumes:
      - /volume2/victoria-metrics:/victoria-metrics-data
      - ./victoria-metrics:/etc/victoria-metrics:ro
    mem_limit: 1g
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8428/health"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 20s

  grafana:
    image: grafana/grafana@sha256:488984b716c0862639f91a698adbe2862677a5a07bad42da5f03f3030883b205 # v13.3.0
    container_name: grafana
    user: "1000:0"
    environment:
      TZ: Europe/Moscow
      # Soft heap ceiling: without it the idle RSS sat at ~600Mi (measured
      # 2026-08-11, live heap 341Mi, next_gc 595Mi).
      GOMEMLIMIT: 512MiB
      GF_DATABASE_WAL: "true"
      GF_PLUGINS_PREINSTALL_DISABLED: "true"
      # Alerting lives in vmalert + Alertmanager in k3s since 2026-11-09.
      GF_UNIFIED_ALERTING_ENABLED: "false"
      GF_SMTP_ENABLED: "true"
      GF_SMTP_HOST: smtp.gmail.com:587
      GF_SMTP_USER: balookrd@gmail.com
      GF_SMTP_PASSWORD__FILE: /run/secrets/smtp/smtp
      GF_SMTP_FROM_ADDRESS: balookrd@gmail.com
      GF_SMTP_FROM_NAME: "Grafana - beerloga.su"
      # The admin password is NOT set here on purpose: it lives in the migrated
      # grafana.db, and GF_SECURITY_ADMIN_PASSWORD would reset it on every start.
    ports:
      - "3000:3000"
    volumes:
      - /volume2/grafana:/var/lib/grafana
      - ./grafana/datasources:/etc/grafana/provisioning/datasources:ro
      - ./grafana/dashboards-provider:/etc/grafana/provisioning/dashboards:ro
      - ./secrets:/run/secrets/smtp:ro
    mem_limit: 768m
    restart: unless-stopped
    depends_on:
      victoria-metrics:
        condition: service_healthy
```

- [ ] **Шаг 7: `ops/nas-monitoring/deploy.sh`.**

```bash
#!/usr/bin/env bash
#
# deploy.sh — copy the compose project to the NAS.
#   ./deploy.sh          # copy files only
#   ./deploy.sh --up     # copy, then `docker compose up -d` (production action:
#                        # ask the owner first)
#
# The SMTP password is not in git: put it into
# /volume1/docker/monitoring/secrets/smtp once (README.md, "Секрет SMTP").

set -euo pipefail
cd "$(dirname "$0")"

host=${NAS_HOST:-sysadm@198.18.1.105}
dest=/volume1/docker/monitoring

docker compose -f docker-compose.yaml config -q

ssh "$host" "mkdir -p $dest/victoria-metrics $dest/grafana/datasources $dest/grafana/dashboards-provider $dest/backup"
scp -O -q docker-compose.yaml "$host:$dest/"
scp -O -q victoria-metrics/scrape.yaml "$host:$dest/victoria-metrics/"
scp -O -q grafana/datasources/*.yaml "$host:$dest/grafana/datasources/"
scp -O -q grafana/dashboards-provider/*.yaml "$host:$dest/grafana/dashboards-provider/"
scp -O -q backup/* "$host:$dest/backup/"
ssh "$host" "test -s $dest/secrets/smtp" ||
	{ echo "missing $dest/secrets/smtp on the NAS (README.md)" >&2; exit 1; }
echo "==> copied to $host:$dest"

if [ "${1:-}" = "--up" ]; then
	ssh "$host" "cd $dest && docker compose up -d && docker compose ps"
fi
```

```bash
chmod +x ops/nas-monitoring/deploy.sh
```

- [ ] **Шаг 8: проверить синтаксис compose локально.**

```bash
(cd ops/nas-monitoring && docker compose -f docker-compose.yaml config -q && echo COMPOSE_OK)
```

Ожидается: `COMPOSE_OK`. `deploy.sh` целиком здесь не запускать: каталога `backup/` ещё нет.

- [ ] **Шаг 9: коммит — по команде владельца.**

```bash
git commit -- ops/nas-monitoring ops/nanopi-r5c-k3s/apps/monitoring/scrape.yaml \
  -m "ops(nas): compose project for VictoriaMetrics and Grafana on the NAS"
```

---

### Задача 3: ночные бэкапы на NAS

**Files:**
- Create: `ops/nas-monitoring/backup/vmbackup-loop.sh`
- Create: `ops/nas-monitoring/backup/grafana-backup.py`
- Modify: `ops/nas-monitoring/docker-compose.yaml` (сервисы `vmbackup`, `grafana-backup`)

**Interfaces:**
- Consumes: сервис `victoria-metrics` (`http://victoria-metrics:8428/snapshot/create`) из задачи 2.
- Produces: `ONCE=1` у обоих скриптов — один прогон сразу и выход. Нужен для проверки здесь и в задаче 9.

- [ ] **Шаг 1: `ops/nas-monitoring/backup/vmbackup-loop.sh`.**

```sh
#!/bin/sh
# Daily vmbackup of the NAS VictoriaMetrics into /backup/victoria-metrics.
#
# vmbackup asks VictoriaMetrics for a snapshot through the API and copies
# incrementally against what is already in the destination, so the result is
# consistent while the database keeps writing.
#
# RUN_AT_UTC is HH:MM in UTC: busybox in this image has no tzdata, so TZ names
# would be ignored silently. 01:15 UTC = 04:15 MSK, after grafana-backup.
# ONCE=1 runs one backup immediately and exits (manual check).
set -u
RUN_AT_UTC=${RUN_AT_UTC:-01:15}

run() {
	/vmbackup-prod \
		-storageDataPath=/victoria-metrics-data \
		-snapshot.createURL=http://victoria-metrics:8428/snapshot/create \
		-dst=fs:///backup/victoria-metrics
}

if [ "${ONCE:-0}" = 1 ]; then
	run
	exit $?
fi

while :; do
	now=$(date -u +%s)
	next=$(date -u -d "$(date -u +%Y-%m-%d) ${RUN_AT_UTC}:00" +%s)
	[ "$next" -le "$now" ] && next=$((next + 86400))
	echo "next vmbackup at $(date -u -d "@$next") (in $((next - now)) s)"
	sleep $((next - now))
	run || echo "vmbackup failed with exit code $?" >&2
done
```

- [ ] **Шаг 2: `ops/nas-monitoring/backup/grafana-backup.py`.** Логика та же, что в CronJob `grafana-backup`, плюс расписание.

```python
"""Daily backup of grafana.db into /backup/grafana, keeping the last KEEP.

sqlite3's backup API takes a consistent snapshot of a live database, WAL
included. /data must be mounted read-write: SQLite touches the -shm file even
when it only reads.

RUN_AT_UTC is HH:MM in UTC (00:30 UTC = 03:30 MSK). ONCE=1 runs one backup
immediately and exits.
"""
import datetime as dt
import gzip
import os
import shutil
import sqlite3
import time

DST = "/backup/grafana"
KEEP = 7
RUN_AT_UTC = os.environ.get("RUN_AT_UTC", "00:30")


def backup() -> None:
    os.makedirs(DST, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M")
    tmp = "/tmp/grafana.db"
    # mode=rw: a plain connect() would create an empty grafana.db when the
    # file is missing and then back up that empty database.
    src = sqlite3.connect("file:/data/grafana.db?mode=rw", uri=True)
    dst = sqlite3.connect(tmp)
    src.backup(dst)
    dst.close()
    src.close()

    out = f"{DST}/grafana-{stamp}.db.gz"
    # Write to .part and rename, so a failure midway never leaves a truncated
    # grafana-*.db.gz that counts toward KEEP.
    part = out + ".part"
    with open(tmp, "rb") as f, gzip.open(part, "wb") as g:
        shutil.copyfileobj(f, g)
    os.replace(part, out)
    os.unlink(tmp)
    print(f"written {out} ({os.path.getsize(out)} bytes)", flush=True)

    # The timestamp format sorts lexically in chronological order.
    snaps = sorted(f for f in os.listdir(DST) if f.startswith("grafana-") and f.endswith(".db.gz"))
    for old in snaps[:-KEEP]:
        os.unlink(f"{DST}/{old}")
        print("pruned", old, flush=True)
    print("kept:", len(snaps[-KEEP:]), flush=True)


def seconds_until(hhmm: str) -> float:
    now = dt.datetime.now(dt.timezone.utc)
    h, m = map(int, hhmm.split(":"))
    nxt = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if nxt <= now:
        nxt += dt.timedelta(days=1)
    return (nxt - now).total_seconds()


if os.environ.get("ONCE") == "1":
    backup()
else:
    while True:
        wait = seconds_until(RUN_AT_UTC)
        print(f"next grafana backup in {int(wait)} s", flush=True)
        time.sleep(wait)
        try:
            backup()
        except Exception as e:  # keep the loop alive; the log shows the failure
            print(f"grafana backup failed: {e!r}", flush=True)
```

- [ ] **Шаг 3: проверить `grafana-backup.py` на маке на тестовой базе.**

```bash
t=$(mktemp -d); mkdir "$t/data" "$t/backup"
python3 -c "import sqlite3; c=sqlite3.connect('$t/data/grafana.db'); c.execute('create table t(x)'); c.execute('insert into t values (42)'); c.commit()"
docker run --rm -e ONCE=1 -v "$t/data:/data" -v "$t/backup:/backup" \
  -v "$PWD/ops/nas-monitoring/backup:/opt/backup:ro" \
  python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df \
  python3 /opt/backup/grafana-backup.py
gzip -dc "$t"/backup/grafana/grafana-*.db.gz > "$t/restored.db"
python3 -c "import sqlite3; print(sqlite3.connect('$t/restored.db').execute('select x from t').fetchone())"
```

Ожидается: `written /backup/grafana/grafana-…db.gz`, `kept: 1`, затем `(42,)`.

- [ ] **Шаг 4: проверить арифметику расписания в `vmbackup-loop.sh`** — запустить и прочитать первую строку лога, бэкап не выполняется.

```bash
docker run --rm -e RUN_AT_UTC=23:59 --entrypoint /bin/sh \
  -v "$PWD/ops/nas-monitoring/backup:/opt/backup:ro" \
  victoriametrics/vmbackup@sha256:26af85b273442e15e5172769979998ad98486706051acbe7826cd3a8c5d83bca \
  -c 'timeout 3 /bin/sh /opt/backup/vmbackup-loop.sh; true'
```

Ожидается: `next vmbackup at … 23:59:00 UTC … (in N s)`, где N ≤ 86400.

- [ ] **Шаг 5: добавить сервисы бэкапов в `ops/nas-monitoring/docker-compose.yaml`** (в конец `services:`):

```yaml
  vmbackup:
    image: victoriametrics/vmbackup@sha256:26af85b273442e15e5172769979998ad98486706051acbe7826cd3a8c5d83bca # v1.155.0
    container_name: vmbackup
    init: true
    user: "1000:1000"
    entrypoint: ["/bin/sh", "/opt/backup/vmbackup-loop.sh"]
    environment:
      RUN_AT_UTC: "01:15"     # 04:15 MSK
    volumes:
      - /volume2/victoria-metrics:/victoria-metrics-data
      # HDD, not the NVMe the data lives on: a dead SSD must not take the
      # backup with it. Same directory the k3s CronJob wrote, so vmbackup stays
      # incremental across the move.
      - /volume1/k8s/backup:/backup
      - ./backup:/opt/backup:ro
    restart: unless-stopped
    depends_on:
      victoria-metrics:
        condition: service_healthy

  grafana-backup:
    image: python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df # 3.12-alpine
    container_name: grafana-backup
    init: true
    user: "1000:0"
    command: ["python3", "/opt/backup/grafana-backup.py"]
    environment:
      RUN_AT_UTC: "00:30"     # 03:30 MSK
    volumes:
      - /volume2/grafana:/data
      - /volume1/k8s/backup:/backup
      - ./backup:/opt/backup:ro
    restart: unless-stopped
```

- [ ] **Шаг 6: проверить compose и скопировать проект на NAS** (только файлы, без запуска).

```bash
(cd ops/nas-monitoring && docker compose -f docker-compose.yaml config -q && echo COMPOSE_OK)
chmod +x ops/nas-monitoring/backup/vmbackup-loop.sh
ops/nas-monitoring/deploy.sh
```

Ожидается: `COMPOSE_OK`, `==> copied to sysadm@198.18.1.105:/volume1/docker/monitoring`.

- [ ] **Шаг 7: коммит — по команде владельца.**

```bash
git commit -- ops/nas-monitoring -m "ops(nas): nightly vmbackup and Grafana backups on the NAS"
```

---

### Задача 4: режим `--nas` в выкладке дашбордов

**Files:**
- Modify: `ops/grafana/dashboards/deploy.sh`

**Interfaces:**
- Produces: `ops/grafana/dashboards/deploy.sh --nas [file.json ...]` кладёт файлы в `/volume2/grafana/dashboards` на NAS. Без аргументов выкладывает все дашборды, включая `bins/*/grafana/*.json`.

- [ ] **Шаг 1: разбор флага.** Заменить блок

```bash
k3s=0
if [ "${1:-}" = "--k3s" ]; then
	k3s=1
	shift
fi
```

на

```bash
k3s=0
nas=0
case "${1:-}" in
--k3s) k3s=1; shift ;;
--nas) nas=1; shift ;;
esac
```

- [ ] **Шаг 2: полный набор файлов и для `--nas`.** Заменить условие `if [ "$k3s" = 1 ]; then` внутри блока `if [ ${#files[@]} -eq 0 ]` на

```bash
	if [ "$k3s" = 1 ] || [ "$nas" = 1 ]; then
```

Комментарий над ним (про `disableDeletion=false`) справедлив и для NAS: провайдер там тоже удаляет дашборды, которых нет в каталоге.

- [ ] **Шаг 3: ветка `--nas`.** Вставить перед строкой `scp -q "${files[@]}" "$host:/tmp/"`:

```bash
if [ "$nas" = 1 ]; then
	# NAS Grafana (ops/nas-monitoring): dashboards live in the dashboards/
	# subdirectory of the /volume2/grafana shared folder, which the container
	# sees as /var/lib/grafana/dashboards. sysadm (uid 1000) may write there
	# under the UGOS ACL, so no sudo and no chown.
	nas_host=${NAS_HOST:-sysadm@198.18.1.105}
	nas_dest=/volume2/grafana/dashboards
	ssh "$nas_host" "mkdir -p $nas_dest"
	# -O: the NAS sftp-server rejects scp's default SFTP mode ("dest open: No
	# such file"); the legacy protocol works.
	scp -O -q "${files[@]}" "$nas_host:$nas_dest/"
	cat <<EOF

==> copied to $nas_host:$nas_dest. Grafana provisions dashboards at startup,
    so restart it (a production action — ask the owner first):

    ssh $nas_host 'docker restart grafana'
    ssh $nas_host 'docker logs --since 2m grafana 2>&1 | grep "provision dashboards"'
EOF
	exit 0
fi
```

- [ ] **Шаг 4: обновить шапку скрипта.** Под строкой `#   ./deploy.sh --k3s [file.json ...]   # cluster: one ConfigMap per dashboard` добавить:

```bash
#   ./deploy.sh --nas [file.json ...]   # NAS: copy into /volume2/grafana/dashboards
```

- [ ] **Шаг 5: проверить на NAS.** Grafana на NAS ещё не запущена, копирование ничего не ломает.

```bash
bash -n ops/grafana/dashboards/deploy.sh && ops/grafana/dashboards/deploy.sh --nas
ssh sysadm@198.18.1.105 'ls /volume2/grafana/dashboards'
```

Ожидается: `json ok: …`, и в каталоге пять файлов: `outline-alerting.json`, `unbound-dashboard.json`, `outline-ss-rust-dashboard.json`, `outline-ws-rust-dashboard.json`, `outline-ws-rust-hang-diagnostics.json`.

- [ ] **Шаг 6: коммит — по команде владельца.**

```bash
git commit -- ops/grafana/dashboards/deploy.sh -m "ops(grafana): deploy dashboards to the NAS Grafana"
```

---

### Задача 5: Ingress для vmalert и Alertmanager (прод, нужно «да» владельца)

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml`

**Interfaces:**
- Produces: `https://vmalert.k3s.beerloga.su/metrics` и `https://alertmanager.k3s.beerloga.su` — их используют `scrape.yaml` (задача 2) и источник данных Grafana.

- [ ] **Шаг 1: дописать в конец `ingress-routes.yaml`.**

```yaml
---
# vmalert and Alertmanager stay in k3s after VictoriaMetrics and Grafana moved
# to the NAS (ops/nas-monitoring). The NAS scrapes their /metrics and Grafana
# reads Alertmanager through these names. LAN-only, like every *.k3s name;
# Alertmanager has no auth, so anyone on the LAN can create a silence.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vmalert
  namespace: monitoring
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: "true"
spec:
  ingressClassName: traefik
  rules:
    - host: vmalert.k3s.beerloga.su
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: vmalert
                port:
                  number: 8880
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: alertmanager
  namespace: monitoring
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: "true"
spec:
  ingressClassName: traefik
  rules:
    - host: alertmanager.k3s.beerloga.su
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: alertmanager
                port:
                  number: 9093
```

- [ ] **Шаг 2: применить и проверить с NAS.**

```bash
KUBECONFIG=~/.kube/k3s-home.yaml kubectl apply -f ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml
ssh sysadm@198.18.1.105 'for u in https://vmalert.k3s.beerloga.su/metrics https://alertmanager.k3s.beerloga.su/metrics https://alertmanager.k3s.beerloga.su/-/ready; do echo "$(curl -s -m8 -o /dev/null -w %{http_code} $u) $u"; done'
```

Ожидается: три строки `200`.

- [ ] **Шаг 3: строки в таблицу `ops/nanopi-r5c-k3s/apps/ingress/README.md`** (раздел «HTTP-имена за Traefik»), с обезличенными именами, как в остальной таблице:

```markdown
| `vmalert.k3s.fleet.example` | `monitoring/vmalert` | `ingress-routes.yaml` |
| `alertmanager.k3s.fleet.example` | `monitoring/alertmanager` (без авторизации) | `ingress-routes.yaml` |
```

- [ ] **Шаг 4: коммит — по команде владельца.**

```bash
git commit -- ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml ops/nanopi-r5c-k3s/apps/ingress/README.md \
  -m "ops(k3s): expose vmalert and Alertmanager through Traefik"
```

---

### Задача 6: первичное восстановление VM на NAS (прод не трогаем)

**Files:** нет.

Большую часть данных (2,0 ГБ) переносим заранее, из последнего ночного бэкапа. В задаче 7 останется докачать только изменения за несколько часов.

- [ ] **Шаг 1: убедиться, что последний ночной бэкап свежий.**

```bash
ssh sysadm@198.18.1.105 'ls -la --time-style=+%F_%T /volume1/k8s/backup/victoria-metrics/'
```

Ожидается: `backup_complete.ignore` с датой сегодня около 04:15 MSK.

- [ ] **Шаг 2: восстановить в пустой `/volume2/victoria-metrics`.** Контейнер `victoria-metrics` на NAS не должен быть запущен: vmrestore пишет в каталог неработающей базы.

```bash
ssh sysadm@198.18.1.105 'docker ps --format "{{.Names}}" | grep -x victoria-metrics && echo "STOP: VM is running" || \
  docker run --rm --user 1000:1000 \
    -v /volume1/k8s/backup:/backup:ro -v /volume2/victoria-metrics:/victoria-metrics-data \
    victoriametrics/vmrestore:v1.155.0 \
    -src=fs:///backup/victoria-metrics -storageDataPath=/victoria-metrics-data'
ssh sysadm@198.18.1.105 'du -sh /volume2/victoria-metrics; lsattr -d /volume2/victoria-metrics/data'
```

Ожидается: vmrestore завершается без `error`, объём около 2 ГБ, у `data` флаг `C`.

---

### Задача 7: переключение VictoriaMetrics (прод, нужно «да» владельца)

**Files:**
- Create: `ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics-nas.yaml`
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics.yaml` (`replicas: 0`, убрать Service и Ingress)
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics-backup.yaml` (`suspend: true`)

**Interfaces:**
- Consumes: каталог `/volume2/victoria-metrics` из задачи 6, проект на NAS из задач 2–3, Ingress'ы из задачи 5.
- Produces: `victoria-metrics.monitoring:8428` и `vm.k3s.beerloga.su` ведут на `198.18.1.105:8428`.

Окно простоя — от шага 3 до шага 6, ожидается 2–4 минуты. Пульс dead-man гаснет примерно через 4 минуты недоступности VM, письмо с cloud1/2 приходит после 15 минут тишины: если окно растянулось дольше 10 минут, предупредите владельца, что письмо придёт. Метрики между финальным снапшотом (шаг 2) и стартом VM на NAS (шаг 5) теряются, это 1–3 минуты.

- [ ] **Шаг 1: подготовить манифест `victoria-metrics-nas.yaml`.**

```yaml
# VictoriaMetrics runs in docker on the NAS 198.18.1.105 (ops/nas-monitoring)
# since 2026-11-xx. The Service keeps its name, so vmalert, smarthome/power,
# smarthome/humidity and vm.k3s.beerloga.su keep working unchanged.
#
# Service without a selector + a hand-written EndpointSlice: Kubernetes does not
# manage the slice. If the NAS address or port changes, edit it here. The label
# kubernetes.io/service-name ties the slice to the Service; the port carries no
# name because the Service port has none.
apiVersion: v1
kind: Service
metadata:
  name: victoria-metrics
  namespace: monitoring
spec:
  ports:
    - { port: 8428, targetPort: 8428, protocol: TCP }
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: victoria-metrics-nas
  namespace: monitoring
  labels:
    kubernetes.io/service-name: victoria-metrics
    endpointslice.kubernetes.io/managed-by: manual
addressType: IPv4
ports:
  - { port: 8428, protocol: TCP }
endpoints:
  - addresses: [198.18.1.105]
    conditions: { ready: true }
---
# Browser and debugging access. In-cluster clients use the ClusterIP name.
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: victoria-metrics
  namespace: monitoring
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: "true"
spec:
  ingressClassName: traefik
  rules:
    - host: vm.k3s.beerloga.su
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: victoria-metrics
                port:
                  number: 8428
```

В `victoria-metrics.yaml` поставить `replicas: 0` и удалить документы `Service` и `Ingress` (они теперь в `victoria-metrics-nas.yaml`; два файла с одним Service перетирали бы друг друга при `deploy.sh apps`). Deployment и PVC остаются до задачи 10 как точка отката. В `victoria-metrics-backup.yaml` добавить `suspend: true` в `spec`.

- [ ] **Шаг 2: финальный инкрементальный бэкап из k3s.**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring create job vmbackup-final --from=cronjob/vmbackup
kubectl -n monitoring wait --for=condition=complete job/vmbackup-final --timeout=10m
kubectl -n monitoring logs job/vmbackup-final | tail -3
```

Ожидается: `job.batch/vmbackup-final condition met`, в логе `backup successfully finished`.

- [ ] **Шаг 3: остановить VM в k3s и ночной бэкап.**

```bash
kubectl -n monitoring scale deploy/victoria-metrics --replicas=0
kubectl -n monitoring patch cronjob vmbackup -p '{"spec":{"suspend":true}}'
kubectl -n monitoring wait --for=delete pod -l app=victoria-metrics --timeout=2m
```

- [ ] **Шаг 4: докачать изменения на NAS.**

```bash
ssh sysadm@198.18.1.105 'docker run --rm --user 1000:1000 \
  -v /volume1/k8s/backup:/backup:ro -v /volume2/victoria-metrics:/victoria-metrics-data \
  victoriametrics/vmrestore:v1.155.0 \
  -src=fs:///backup/victoria-metrics -storageDataPath=/victoria-metrics-data'
```

Ожидается: завершение без `error`, докачано немного (части за последние часы).

- [ ] **Шаг 5: запустить VM на NAS.**

```bash
ssh sysadm@198.18.1.105 'cd /volume1/docker/monitoring && docker compose up -d victoria-metrics vmbackup && docker compose ps'
sleep 30
curl -s http://198.18.1.105:8428/health; echo
curl -s 'http://198.18.1.105:8428/api/v1/targets?state=active' | python3 -c 'import json,sys; t=json.load(sys.stdin)["data"]["activeTargets"]; bad=[x["scrapeUrl"] for x in t if x["health"]!="up"]; print(len(t),"targets, down:",bad)'
```

Ожидается: `OK`; список down содержит только `grafana:3000` (Grafana на NAS ещё не запущена).

- [ ] **Шаг 6: переключить Service в k3s на NAS.**

```bash
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics-nas.yaml
kubectl -n monitoring get svc victoria-metrics -o jsonpath='selector={.spec.selector}{"\n"}'
kubectl -n monitoring get endpointslice -l kubernetes.io/service-name=victoria-metrics
```

Ожидается: `selector=` (пусто) и единственный slice `victoria-metrics-nas` с адресом `198.18.1.105`. Если остался старый автоматический slice (`victoria-metrics-xxxxx`), удалить его: `kubectl -n monitoring delete endpointslice <имя>`.

- [ ] **Шаг 7: проверить потребителей.**

```bash
curl -s https://vm.k3s.beerloga.su/health; echo
kubectl -n monitoring logs deploy/vmalert --since=3m | grep -ciE 'error|failed'
curl -s 'http://198.18.1.105:8428/api/v1/query' --data-urlencode 'query=count(ALERTS{alertname="DeadMansSwitch"})' ; echo
kubectl -n smarthome logs deploy/power --since=3m | tail -3
kubectl -n smarthome logs deploy/humidity --since=3m | tail -3
```

Ожидается: `OK`; ошибок vmalert за последние 3 минуты 0 (или только из окна шагов 3–6); `DeadMansSwitch` есть в `ALERTS`; в логах power/humidity нет ошибок записи.

- [ ] **Шаг 8: сверить пульс на наблюдателях.** Через 5 минут после шага 6 `heartbeat-watch` на cloud1 и cloud2 должен видеть свежий пульс: ничего в почте и Telegram, `systemctl status heartbeat-watch.timer` без ошибок (подробности в `ops/heartbeat/README.md`).

- [ ] **Шаг 9: коммит — по команде владельца.**

```bash
git commit -- ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics-nas.yaml \
  ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics.yaml \
  ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics-backup.yaml \
  -m "ops(k3s): point victoria-metrics at the NAS"
```

---

### Задача 8: переключение Grafana (прод, нужно «да» владельца)

**Files:**
- Create: `ops/nanopi-r5c-k3s/apps/monitoring/grafana-nas.yaml`
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml` (`replicas: 0`, убрать Service)
- Modify: `ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml` (Ingress `grafana` переезжает в `grafana-nas.yaml`)
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/grafana-backup.yaml` (`suspend: true`)

**Interfaces:**
- Consumes: VM на NAS (задача 7), дашборды в `/volume2/grafana/dashboards` (задача 4).
- Produces: `grafana.k3s.beerloga.su` и `grafana.monitoring:3000` ведут на `198.18.1.105:3000`.

Простой интерфейса Grafana — от шага 2 до шага 6, ожидается 3–5 минут. На алертинг не влияет. В `grafana.db` семь дашбордов, которых нет ни в одном репозитории, поэтому PVC в k3s не трогаем до задачи 10.

- [ ] **Шаг 1: подготовить `grafana-nas.yaml`.**

```yaml
# Grafana runs in docker on the NAS 198.18.1.105 (ops/nas-monitoring) since
# 2026-11-xx. Same pattern as victoria-metrics-nas.yaml: the Service keeps its
# name and points at the NAS through a hand-written EndpointSlice.
apiVersion: v1
kind: Service
metadata:
  name: grafana
  namespace: monitoring
spec:
  ports:
    - { port: 3000, targetPort: 3000, protocol: TCP }
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: grafana-nas
  namespace: monitoring
  labels:
    kubernetes.io/service-name: grafana
    endpointslice.kubernetes.io/managed-by: manual
addressType: IPv4
ports:
  - { port: 3000, protocol: TCP }
endpoints:
  - addresses: [198.18.1.105]
    conditions: { ready: true }
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grafana
  namespace: monitoring
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: "true"
spec:
  ingressClassName: traefik
  rules:
    - host: grafana.k3s.beerloga.su
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: grafana
                port:
                  number: 3000
```

Из `ingress-routes.yaml` удалить документ `Ingress grafana` (он теперь в `grafana-nas.yaml`). В `grafana.yaml` поставить `replicas: 0` и удалить документ `Service`. В `grafana-backup.yaml` добавить `suspend: true` в `spec`.

- [ ] **Шаг 2: остановить Grafana в k3s и её бэкап.**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring scale deploy/grafana --replicas=0
kubectl -n monitoring patch cronjob grafana-backup -p '{"spec":{"suspend":true}}'
kubectl -n monitoring wait --for=delete pod -l app=grafana --timeout=2m
```

- [ ] **Шаг 3: скопировать данные Grafana с k3s-1 на NAS.** Grafana остановлена штатно, так что `grafana.db` и WAL согласованы между собой. Файлы на NAS станут принадлежать `sysadm` (uid 1000) — так и нужно.

```bash
pv=$(kubectl -n monitoring get pvc grafana-data -o jsonpath='{.spec.volumeName}')
path=$(kubectl get pv "$pv" -o jsonpath='{.spec.local.path}{.spec.hostPath.path}')
echo "$path"
ssh mmv@k3s-1 "sudo tar -C '$path' --exclude=./dashboards -cf - ." \
  | ssh sysadm@198.18.1.105 'tar -C /volume2/grafana --no-same-owner -xf -'
ssh sysadm@198.18.1.105 'ls -la /volume2/grafana; ls /volume2/grafana/dashboards'
```

`tar` на NAS завершается с кодом 2 из-за `Cannot change mode` на корне `/volume2/grafana`: права корня shared folder задаёт ACL UGOS. Других ошибок быть не должно.

Ожидается: путь вида `/var/lib/rancher/k3s/storage/pvc-…_monitoring_grafana-data`; на NAS — `grafana.db` около 13 МБ, каталоги `csv`, `pdf`, `plugins`, `png`, `unified-search`, владелец `sysadm`; `dashboards/` — пять файлов из задачи 4.

- [ ] **Шаг 4: запустить Grafana и бэкап на NAS.**

```bash
ssh sysadm@198.18.1.105 'cd /volume1/docker/monitoring && docker compose up -d grafana grafana-backup && sleep 20 && docker compose ps'
curl -s http://198.18.1.105:3000/api/health; echo
ssh sysadm@198.18.1.105 'docker logs grafana 2>&1 | grep -E "provision dashboards|level=error" | tail -10'
```

Ожидается: `"database": "ok"`; в логе есть `finished to provision dashboards`; строк `level=error` нет (или только известные, например про отключённый алертинг; каждую разобрать).

- [ ] **Шаг 5: переключить Service и Ingress в k3s.**

```bash
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/grafana-nas.yaml
kubectl -n monitoring get svc grafana -o jsonpath='selector={.spec.selector}{"\n"}'
kubectl -n monitoring get endpointslice -l kubernetes.io/service-name=grafana
curl -s -o /dev/null -w '%{http_code}\n' https://grafana.k3s.beerloga.su/api/health
```

Ожидается: `selector=` (пусто), один slice `grafana-nas`, `200`. Если остался старый автоматический slice, удалить его.

- [ ] **Шаг 6: проверка владельцем в браузере.** Владелец открывает `https://grafana.k3s.beerloga.su`, входит под своим паролем (он в перенесённой базе) и проверяет: пять дашбордов из репозитория и семь своих на месте, панели `outline-ws-rust` показывают свежие данные, источник данных `alertmanager` в Connections → Data sources проходит «Save & test».

- [ ] **Шаг 7: проверить, что VM на NAS скрейпит Grafana.**

```bash
curl -s 'http://198.18.1.105:8428/api/v1/query' --data-urlencode 'query=up{job="grafana"}' ; echo
```

Ожидается: значение `"1"`.

- [ ] **Шаг 8: коммит — по команде владельца.**

```bash
git commit -- ops/nanopi-r5c-k3s/apps/monitoring/grafana-nas.yaml \
  ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml \
  ops/nanopi-r5c-k3s/apps/monitoring/grafana-backup.yaml \
  ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml \
  -m "ops(k3s): point grafana at the NAS"
```

---

### Задача 9: наблюдение 48 часов

**Files:** нет.

- [ ] **Шаг 1: на следующее утро — бэкапы на NAS.**

```bash
ssh sysadm@198.18.1.105 'docker logs --since 26h grafana-backup; docker logs --since 26h vmbackup 2>&1 | tail -5; ls -la /volume1/k8s/backup/grafana | tail -3; ls -la /volume1/k8s/backup/victoria-metrics'
```

Ожидается: `written /backup/grafana/grafana-YYYYMMDD-0030.db.gz` (имя по UTC), у vmbackup — `backup successfully finished`, `backup_complete.ignore` с сегодняшней датой около 04:15 MSK.

- [ ] **Шаг 2: бэкап Grafana читается как база.** Число дашбордов здесь не сравниваем: в Grafana 13 они лежат в unified storage, и таблица `dashboard` может быть пустой.

```bash
ssh sysadm@198.18.1.105 'f=$(ls /volume1/k8s/backup/grafana/*.db.gz | tail -1); echo "$f"; gzip -dc "$f" > /tmp/g.db && docker run --rm -v /tmp/g.db:/g.db python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df python3 -c "import sqlite3; print(sqlite3.connect(\"/g.db\").execute(\"pragma integrity_check\").fetchone())"; rm -f /tmp/g.db'
```

Ожидается: имя файла со вчерашней или сегодняшней датой и `('ok',)`.

- [ ] **Шаг 3: перезагрузка NAS не теряет сервисы** — только если владелец сам перезагружает NAS в эти 48 часов: после загрузки `docker compose ps` в `/volume1/docker/monitoring` показывает четыре контейнера `running`.

- [ ] **Шаг 4: память k3s-1 освободилась.**

```bash
KUBECONFIG=~/.kube/k3s-home.yaml kubectl top node 2>/dev/null || ssh mmv@k3s-1 free -m
```

Ожидается: на k3s-1 примерно на 1–1,3 ГБ больше свободной памяти, чем до переноса (VM ~590 МиБ RSS + Grafana ~600 МиБ).

---

### Задача 10: уборка в k3s и документация (прод, нужно «да» владельца)

**Files:**
- Delete: `ops/nanopi-r5c-k3s/apps/monitoring/{victoria-metrics,grafana,grafana-provisioning,grafana-backup,victoria-metrics-backup}.yaml`
- Create: `ops/nas-monitoring/README.md`
- Modify: `ops/nanopi-r5c-k3s/apps/README.md`, `ops/nanopi-r5c-k3s/apps/ingress/README.md`, `ops/grafana/README.md`

- [ ] **Шаг 1: удалить объекты в k3s.** Удаление PVC стирает старые данные на k3s-1 без возможности вернуть: делать только после задачи 9 и отдельного «да».

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring delete deploy victoria-metrics grafana
kubectl -n monitoring delete cronjob vmbackup grafana-backup
kubectl -n monitoring delete job vmbackup-final --ignore-not-found
kubectl -n monitoring delete configmap grafana-datasources grafana-dashboard-provider \
  grafana-dashboard-outline-alerting grafana-dashboard-outline-ss-rust-dashboard \
  grafana-dashboard-outline-ws-rust-dashboard grafana-dashboard-outline-ws-rust-hang-diagnostics \
  grafana-dashboard-unbound-dashboard
kubectl -n monitoring delete pvc victoria-metrics-data grafana-data
```

Secret `grafana-smtp` НЕ удалять: `ops/alerting/deploy.sh` (строка 52) берёт из него пароль SMTP для Secret `alertmanager-smtp`, и без него повторная выкладка алертинга падает с `Secret grafana-smtp has no key smtp`.

- [ ] **Шаг 2: удалить файлы из репозитория.**

```bash
git rm ops/nanopi-r5c-k3s/apps/monitoring/{victoria-metrics,grafana,grafana-provisioning,grafana-backup,victoria-metrics-backup}.yaml
```

- [ ] **Шаг 3: режим `--k3s` в `ops/grafana/dashboards/deploy.sh`.** Он создаёт ConfigMap'ы, которые больше никто не монтирует. Удалить ветку `if [ "$k3s" = 1 ]; then … fi` с генерацией ConfigMap'ов, разбор `--k3s` и строку о нём в шапке. Проверить: `bash -n ops/grafana/dashboards/deploy.sh`.

- [ ] **Шаг 4: `ops/nas-monitoring/README.md`** по `~/.claude/tech-docs-style.md`: что где работает (таблица контейнер | порт | данные | бэкап), как выкатить (`deploy.sh`, `deploy.sh --up`), секрет SMTP, права UGOS ACL (uid 1000, почему не 472), как обновить дашборды (`deploy.sh --nas` + `docker restart grafana`), как восстановить VM (`vmrestore` при остановленном контейнере) и Grafana (распаковать `grafana-*.db.gz` в `/volume2/grafana/grafana.db` при остановленном контейнере), откат на k3s (раздел «Откат» ниже), известные проблемы.

- [ ] **Шаг 5: ссылки в остальной документации.**
  - `ops/nanopi-r5c-k3s/apps/README.md`: разделы про VictoriaMetrics (около строки 124) и Grafana (около строки 136) — данные на NAS, в кластере остаются Service + EndpointSlice; ссылка на `ops/nas-monitoring/README.md`.
  - `ops/nanopi-r5c-k3s/apps/ingress/README.md`: строки `grafana` и `vm` в таблице — колонка «Где объявлен Ingress» → `../monitoring/grafana-nas.yaml` / `../monitoring/victoria-metrics-nas.yaml`, бэкенд — NAS.
  - `ops/grafana/README.md`: выкладка дашбордов — `deploy.sh --nas`; строки 136–138 и 184 про `scrape.yaml` в PVC.
  - Старый путь `scrape.yaml` (живая копия теперь `/volume1/docker/monitoring/victoria-metrics/scrape.yaml`, выкладка `ops/nas-monitoring/deploy.sh`): `ops/provision-node/install.sh:1755`, `ops/provision-node/README.md:387-393` и `README.ru.md:388-395` (пара EN/RU), `ops/provision-node/assets/victoria-metrics/scrape-unbound-exporter.yaml:2-3`.

- [ ] **Шаг 6: обновить память** (`jellyfin-on-105-ugreen-nas`, `vm-move-to-105-planned`, `victoriametrics-in-k3s`, `grafana-provisioning-102`, `k3s-1-memory-imbalance`) и `FLEET.local.md`: где теперь VM и Grafana.

- [ ] **Шаг 7: коммит — по команде владельца.**

```bash
git commit -- ops/nanopi-r5c-k3s/apps/monitoring ops/nas-monitoring/README.md \
  ops/nanopi-r5c-k3s/apps/README.md ops/nanopi-r5c-k3s/apps/ingress/README.md \
  ops/grafana/README.md ops/grafana/dashboards/deploy.sh \
  -m "ops: drop the k3s VictoriaMetrics and Grafana, document the NAS setup"
```

---

## Откат

Пока не выполнена задача 10, откат каждого компонента занимает пару минут.

**VictoriaMetrics:**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring delete endpointslice victoria-metrics-nas
git show HEAD~1:ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics.yaml | kubectl apply -f -   # commit before task 7
kubectl -n monitoring scale deploy/victoria-metrics --replicas=1
kubectl -n monitoring patch cronjob vmbackup -p '{"spec":{"suspend":false}}'
ssh sysadm@198.18.1.105 'cd /volume1/docker/monitoring && docker compose stop victoria-metrics vmbackup'
```

`HEAD~1` заменить на коммит, предшествующий задаче 7 (`git log --oneline -- ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics.yaml`). Метрики, записанные на NAS после переключения, в VM k3s не попадут: в истории будет дыра.

**Grafana:** то же с `grafana-nas` / `grafana.yaml` / `grafana-backup`, плюс вернуть Ingress `grafana` в `ingress-routes.yaml`. Изменения, сделанные в Grafana на NAS (новые дашборды, пользователи), в k3s не попадут. Если они нужны, остановить обе Grafana и скопировать `/volume2/grafana/grafana.db` обратно в PV на k3s-1.

## Известные проблемы

- Бэкапы лежат на HDD того же NAS. Они защищают от отказа NVMe и от ошибок в данных, но не от потери NAS целиком. Копия вне `.105` в этот план не входит.
- Alertmanager становится доступен из LAN без авторизации (`alertmanager.k3s.beerloga.su`): любой в домашней сети может создать silence.
- Если UGOS после обновления прошивки поменяет ACL shared folders, контейнеры с uid 1000 могут потерять запись. Симптом — `permission denied` в `docker logs victoria-metrics` или `grafana`. Права чинятся в интерфейсе UGOS.
- Работает ли автозапуск compose-проекта, созданного из CLI, после перезагрузки NAS, проверяется только в задаче 9, шаг 3 [проверить: UGOS поднимает docker до монтирования `/volume2`].
