# Миграция VictoriaMetrics в k3s: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Перенести VictoriaMetrics с docker на `198.18.1.102` в k3s вместе с
1,4 ГБ истории, завести ей ночной бэкап и привести раскладку бэкапов на NAS к
единому виду.

**Architecture:** Под селится на `k3s-1`, данные — `local-path` на NVMe (у TSDB
поток мелких записей с fsync, сетевая ФС противопоказана). Внутри кластера
доступ по ClusterIP `victoria-metrics.monitoring:8428`, снаружи — Ingress
`vm.k3s.beerloga.su`. Клиенты (`power`, `humidity`, Grafana) переключаются на
внутреннее имя, код при этом не меняется.

**Tech Stack:** k3s v1.36.2, VictoriaMetrics v1.149.0, vmbackup, local-path
storage, Traefik ingress с готовым wildcard-TLS, NFS на NAS для бэкапов.

Спека: [`docs/superpowers/specs/2026-08-09-victoriametrics-to-k3s-design.md`](../specs/2026-08-09-victoriametrics-to-k3s-design.md).

## Global Constraints

- Образ строго `victoriametrics/victoria-metrics:v1.149.0` — ровно тот, что
  работает; `latest` запрещён. Для бэкапа — `victoriametrics/vmbackup:v1.149.0`.
- Namespace `monitoring`. Имена: Deployment/Service/PVC — `victoria-metrics`,
  `victoria-metrics`, `victoria-metrics-data`; CronJob — `vmbackup`.
- **`nodeSelector: kubernetes.io/hostname: k3s-1`** и у пода, и у CronJob
  бэкапа: оба монтируют один PVC `ReadWriteOnce`.
- Хранилище — `local-path`, 20 Gi. NFS для TSDB **не использовать**.
- Флаги запуска ровно как в docker: `-retentionPeriod=90d`,
  `-inmemoryDataFlushInterval=60s`,
  `-promscrape.config=/victoria-metrics-data/scrape.yaml`.
- `securityContext`: `runAsUser: 1000`, `fsGroup: 1000` — как в docker
  (`--user 1000:1000`).
- **Раскладка NAS:** данные в корне экспорта, бэкапы в `backup/`. Бэкап
  Grafana переезжает `k8s/grafana/` → `k8s/backup/grafana/`, бэкап VM пишется в
  `k8s/backup/victoria-metrics/`.
- Клиенты в кластере ходят на `http://victoria-metrics.monitoring:8428`.
  **UID датасорса Grafana `adnsc1wi03doga` менять нельзя.**
- Цели скрейпа: четыре `127.0.0.1` (`:9100`, `:9486`, `:9090`, `:9091`) →
  `198.18.1.102`; пятая (`127.0.0.1:8428`, сама VM) **остаётся как есть**.
- Управление кластером с мака: `export KUBECONFIG=~/.kube/k3s-home.yaml`.
- `/opt/victoria-metrics` на `.102` **не удалять** — путь отката.
- Git: коммиты на английском, без Co-Authored-By и Claude-атрибуции.
  `git commit` — только по явной команде владельца.

---

### Task 1: Манифест VictoriaMetrics

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics.yaml` (переписать
  целиком — сейчас там незаполненная заготовка с TODO)

**Interfaces:**
- Produces: Deployment `victoria-metrics`, PVC `victoria-metrics-data`,
  Service `victoria-metrics:8428`, Ingress `vm.k3s.beerloga.su`. PVC наполняет
  Задача 3; на Service ссылаются Задачи 4 и 5.

- [ ] **Step 1: Переписать victoria-metrics.yaml**

Полное содержимое `ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics.yaml`:

```yaml
# VictoriaMetrics, migrated off the docker container on 198.18.1.102.
#
# Storage is local-path, NOT NFS — the opposite of what z2m and the smarthome
# services use. A TSDB writes small blocks continuously and fsyncs them, which
# is exactly the workload a network filesystem handles worst; upstream advises
# against it. Durability comes from the nightly vmbackup, not from the volume.
#
# Pinned to k3s-1 explicitly. local-path would pin it anyway through the PV's
# node affinity, but writing it down makes the placement predictable: it is
# clear up front which disk holds the data and where a restore has to go.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: victoria-metrics
  namespace: monitoring
spec:
  replicas: 1
  strategy:
    type: Recreate            # singleton over a RWO volume
  selector:
    matchLabels: { app: victoria-metrics }
  template:
    metadata:
      labels: { app: victoria-metrics }
    spec:
      nodeSelector:
        kubernetes.io/hostname: k3s-1
      securityContext:
        runAsUser: 1000       # same as --user 1000:1000 in docker
        fsGroup: 1000
      containers:
        - name: victoria-metrics
          image: victoriametrics/victoria-metrics:v1.149.0
          args:
            - -retentionPeriod=90d
            - -inmemoryDataFlushInterval=60s
            # The scrape config lives inside the data directory, exactly as on
            # the gateway node: it migrates together with the data.
            - -promscrape.config=/victoria-metrics-data/scrape.yaml
          ports:
            - { containerPort: 8428, name: http }
          volumeMounts:
            - { name: data, mountPath: /victoria-metrics-data }
          readinessProbe:
            httpGet: { path: /health, port: 8428 }
            initialDelaySeconds: 10
            periodSeconds: 10
          resources:
            requests: { cpu: 100m, memory: 256Mi }
            limits:   { memory: 1Gi }
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: victoria-metrics-data
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: victoria-metrics-data
  namespace: monitoring
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: local-path
  resources:
    requests:
      storage: 20Gi           # 1.4 GB in use at 90 days retention
---
apiVersion: v1
kind: Service
metadata:
  name: victoria-metrics
  namespace: monitoring
spec:
  selector: { app: victoria-metrics }
  ports:
    - { port: 8428, targetPort: 8428 }
---
# External access for a browser and for debugging. In-cluster clients (power,
# humidity, Grafana) use the ClusterIP name instead — there is no reason to
# leave the cluster and come back through the ingress.
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

- [ ] **Step 2: Проверить синтаксис и схему**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/monitoring
ruby -ryaml -e 'YAML.load_stream(File.read("victoria-metrics.yaml")); puts "yaml ok"'
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl apply --dry-run=server -f victoria-metrics.yaml
```

Ожидаемо: `yaml ok`, затем четыре строки `created (server dry run)` —
deployment, pvc, service, ingress.

- [ ] **Step 3: Убедиться, что заготовочные TODO ушли**

```bash
grep -n "TODO\|<PLACEHOLDER>\|nfs-client" victoria-metrics.yaml || echo "заготовка вычищена"
```

Ожидаемо: `заготовка вычищена`.

- [ ] **Step 4: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics.yaml
git commit -m "ops(k3s): manifest for VictoriaMetrics migrated off the gateway"
```

---

### Task 2: Бэкапы — vmbackup и переезд Grafana в `backup/`

**Files:**
- Create: `ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics-backup.yaml`
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/grafana-backup.yaml` (том `backup`)

**Interfaces:**
- Consumes: PVC `victoria-metrics-data` и Service `victoria-metrics` (Задача 1).
- Produces: CronJob `vmbackup`; `grafana-backup` пишет в новый путь.

- [ ] **Step 1: Создать манифест vmbackup**

Полное содержимое `ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics-backup.yaml`:

```yaml
# Nightly VictoriaMetrics backup to the NAS.
#
# vmbackup rather than tar: it asks VictoriaMetrics for a snapshot through the
# API and copies incrementally, so the result is consistent even though the
# database keeps writing. Copying the directory of a live TSDB is not.
#
# Same nodeSelector as the database: both mount the same ReadWriteOnce volume,
# so they have to sit on the same node.
apiVersion: batch/v1
kind: CronJob
metadata:
  name: vmbackup
  namespace: monitoring
spec:
  schedule: "15 4 * * *"      # after grafana-backup at 03:30
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 2
      template:
        spec:
          restartPolicy: Never
          nodeSelector:
            kubernetes.io/hostname: k3s-1
          securityContext:
            runAsUser: 1000
            fsGroup: 1000
          containers:
            - name: vmbackup
              image: victoriametrics/vmbackup:v1.149.0
              args:
                - -storageDataPath=/victoria-metrics-data
                - -snapshot.createURL=http://victoria-metrics.monitoring:8428/snapshot/create
                - -dst=fs:///backup/victoria-metrics
              volumeMounts:
                - { name: data, mountPath: /victoria-metrics-data }
                - { name: backup, mountPath: /backup }
          volumes:
            - name: data
              persistentVolumeClaim:
                claimName: victoria-metrics-data
            - name: backup
              nfs:
                server: 198.18.1.125
                path: /mnt/HD/HD_a2/k8s/backup
```

- [ ] **Step 2: Перенастроить бэкап Grafana на `backup/`**

В `ops/nanopi-r5c-k3s/apps/monitoring/grafana-backup.yaml` заменить том
`backup` — меняется только путь NFS, скрипт внутри не трогаем (он пишет в
`/backup/grafana`, и теперь это будет `k8s/backup/grafana`):

```yaml
            - name: backup
              nfs:
                server: 198.18.1.125
                path: /mnt/HD/HD_a2/k8s/backup
```

И поправить комментарий в шапке файла, добавив после строки про NFS-том:

```yaml
# Backups live under backup/ on the export, data lives in the root — otherwise
# the two are indistinguishable a month later.
```

- [ ] **Step 3: Проверить синтаксис**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/monitoring
ruby -ryaml -e 'ARGV.each { |f| YAML.load_stream(File.read(f)) }; puts "yaml ok"' victoria-metrics-backup.yaml grafana-backup.yaml
grep -n "path: /mnt" victoria-metrics-backup.yaml grafana-backup.yaml
```

Ожидаемо: `yaml ok` и в обоих файлах путь `/mnt/HD/HD_a2/k8s/backup`.

- [ ] **Step 4: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/monitoring/victoria-metrics-backup.yaml ops/nanopi-r5c-k3s/apps/monitoring/grafana-backup.yaml
git commit -m "ops(k3s): nightly VictoriaMetrics backup, tidy the NAS layout"
```

---

### Task 3: Переезд данных

Здесь открывается окно: пока VictoriaMetrics не поднимется в кластере, скрейпы
не выполняются, и в графиках будет пропуск.

**Files:** изменений в git нет.

**Interfaces:**
- Consumes: манифест из Задачи 1.
- Produces: PVC с данными и поправленным `scrape.yaml`.

- [ ] **Step 1: Зафиксировать эталон**

```bash
ssh mmv@198.18.1.102 'sudo -n du -sb /opt/victoria-metrics/data | cut -f1; echo "целей: $(sudo -n grep -c "targets:" /opt/victoria-metrics/data/scrape.yaml)"; sudo -n md5sum /opt/victoria-metrics/data/scrape.yaml'
```

Запомнить размер в байтах, число целей (ожидается 26) и md5 конфига — по ним
Шаг 6 проверит перенос.

- [ ] **Step 2: Остановить контейнер**

```bash
ssh mmv@198.18.1.102 'sudo -n docker update --restart=no victoria-metrics >/dev/null && sudo -n docker stop victoria-metrics >/dev/null && sudo -n docker inspect -f "{{.State.Status}} restart={{.HostConfig.RestartPolicy.Name}}" victoria-metrics'
```

Ожидаемо: `exited restart=no`. Снятие автозапуска обязательно: иначе после
перезагрузки узла поднимется второй экземпляр и начнёт писать в те же цели.

- [ ] **Step 3: Упаковать данные**

```bash
ssh mmv@198.18.1.102 'cd /opt/victoria-metrics && sudo -n tar czf /tmp/vm-data.tar.gz -C data . && sudo -n chown mmv:mmv /tmp/vm-data.tar.gz && ls -lh /tmp/vm-data.tar.gz'
```

Ожидаемо: архив порядка 0,5–1,4 ГБ (сжатие TSDB даёт немного).

- [ ] **Step 4: Создать PVC и залить данные**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/monitoring
kubectl apply -f victoria-metrics.yaml
kubectl -n monitoring scale deploy/victoria-metrics --replicas=0
kubectl -n monitoring run vm-loader --image=busybox:1.36 --restart=Never \
  --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"k3s-1"},"containers":[{"name":"vm-loader","image":"busybox:1.36","command":["sleep","3600"],"volumeMounts":[{"name":"data","mountPath":"/data"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"victoria-metrics-data"}}]}}'
kubectl -n monitoring wait --for=condition=Ready pod/vm-loader --timeout=300s
scp mmv@198.18.1.102:/tmp/vm-data.tar.gz /tmp/vm-data.tar.gz
kubectl -n monitoring cp /tmp/vm-data.tar.gz vm-loader:/data/vm-data.tar.gz
kubectl -n monitoring exec vm-loader -- sh -c 'cd /data && tar xzf vm-data.tar.gz && rm -f vm-data.tar.gz && ls -l /data | head'
```

Ожидаемо: в `/data` появились каталоги VictoriaMetrics (`data/`, `indexdb/`,
`metadata/`, `snapshots/`) и файл `scrape.yaml`.

- [ ] **Step 5: Переписать четыре цели в scrape.yaml**

Пятую (саму VictoriaMetrics на `127.0.0.1:8428`) не трогаем — в поде это она
сама:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring exec vm-loader -- sh -c "sed -i 's|127.0.0.1:9100|198.18.1.102:9100|; s|127.0.0.1:9486|198.18.1.102:9486|; s|127.0.0.1:9090|198.18.1.102:9090|; s|127.0.0.1:9091|198.18.1.102:9091|' /data/scrape.yaml && grep -n '127.0.0.1\|198.18.1.102' /data/scrape.yaml"
```

Ожидаемо: четыре строки с `198.18.1.102:<порт>` и **одна** оставшаяся
`127.0.0.1:8428`. Если `127.0.0.1` осталось больше одной — правка не полная.

- [ ] **Step 6: Сверить перенос и убрать helper**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring exec vm-loader -- sh -c 'du -sb /data | cut -f1; grep -c "targets:" /data/scrape.yaml'
kubectl -n monitoring delete pod vm-loader
rm -f /tmp/vm-data.tar.gz
ssh mmv@198.18.1.102 'rm -f /tmp/vm-data.tar.gz'
```

Ожидаемо: размер того же порядка, что эталон из Шага 1 (точного совпадения не
будет — архив распакован без `snapshots`-мусора), целей по-прежнему 26.

- [ ] **Step 7: Поднять VictoriaMetrics**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring scale deploy/victoria-metrics --replicas=1
kubectl -n monitoring rollout status deploy/victoria-metrics --timeout=300s
kubectl -n monitoring logs deploy/victoria-metrics --tail=20 | grep -iE "started|error|panic" | head -5
```

Ожидаемо: `successfully rolled out`, в логе `started VictoriaMetrics`, без
`panic`. Ошибки чтения индекса означают повреждение при переносе — тогда откат
(Шаг 8) и повтор.

- [ ] **Step 8: Знать, как откатиться**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring scale deploy/victoria-metrics --replicas=0
ssh mmv@198.18.1.102 'sudo -n docker update --restart=unless-stopped victoria-metrics && sudo -n docker start victoria-metrics'
```

Данные на `.102` нетронуты. Порядок важен: сначала погасить под, потом поднять
контейнер, иначе оба будут скрейпить одни цели.

Коммита нет.

---

### Task 4: Переключить клиентов

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/smarthome/humidity.yaml` (аргумент `--victoria`)
- Modify: `ops/nanopi-r5c-k3s/apps/smarthome/power.yaml` (аргумент `--victoria`)
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/grafana-provisioning.yaml` (url датасорса)

**Interfaces:**
- Consumes: Service `victoria-metrics` из Задачи 1.

- [ ] **Step 1: Переключить humidity и power**

В обоих манифестах заменить строку аргумента:

```yaml
            - vm.beerloga.su
```

на:

```yaml
            - victoria-metrics.monitoring
```

Код сервисов не меняется: он собирает `http://{host}:8428/api/v1/import`, и
внутреннее имя подставляется туда же.

- [ ] **Step 2: Применить и проверить**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/smarthome
kubectl apply -f humidity.yaml -f power.yaml
kubectl -n smarthome rollout status deploy/humidity --timeout=180s
kubectl -n smarthome rollout status deploy/power --timeout=180s
kubectl -n smarthome logs deploy/power --tail=5 | grep -iE "error|victoria" | head -3
```

Ожидаемо: оба пода перезапустились, в логах нет ошибок отправки.

- [ ] **Step 3: Переключить датасорс Grafana**

В `ops/nanopi-r5c-k3s/apps/monitoring/grafana-provisioning.yaml` заменить:

```yaml
        url: http://198.18.1.102:8428
```

на:

```yaml
        url: http://victoria-metrics.monitoring:8428
```

**UID `adnsc1wi03doga` не трогать** — дашборды ссылаются на датасорс по нему.

- [ ] **Step 4: Применить и перезапустить Grafana**

Провижининг применяется только при старте, поэтому нужен рестарт пода:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/monitoring
kubectl apply -f grafana-provisioning.yaml
kubectl -n monitoring rollout restart deploy/grafana
kubectl -n monitoring rollout status deploy/grafana --timeout=300s
```

Ожидаемо: `successfully rolled out`.

- [ ] **Step 5: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/smarthome/humidity.yaml ops/nanopi-r5c-k3s/apps/smarthome/power.yaml ops/nanopi-r5c-k3s/apps/monitoring/grafana-provisioning.yaml
git commit -m "ops(k3s): point metric writers and Grafana at the in-cluster VictoriaMetrics"
```

---

### Task 5: Проверки

**Files:** изменений в git нет.

- [ ] **Step 1: Сервис отвечает снаружи и внутри**

```bash
curl -s -o /dev/null -w 'ingress: %{http_code} verify=%{ssl_verify_result}\n' https://vm.k3s.beerloga.su/health
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring exec deploy/grafana -- wget -qO- http://victoria-metrics.monitoring:8428/health && echo " <- ClusterIP"
```

Ожидаемо: `200 0` через ingress и `OK` изнутри кластера.

- [ ] **Step 2: Все цели скрейпа живы**

```bash
curl -s https://vm.k3s.beerloga.su/api/v1/targets | python3 -c "
import json,sys
t=json.load(sys.stdin)['data']['activeTargets']
up=[x for x in t if x['health']=='up']
print(f'целей: {len(t)}, up: {len(up)}')
for x in t:
    if x['health']!='up': print('  DOWN:', x['scrapeUrl'], x.get('lastError','')[:80])
"
```

Ожидаемо: 26 целей, все `up`. Любая `DOWN` с адресом `198.18.1.102` означает
ошибку в правке Шага 5 Задачи 3.

- [ ] **Step 3: История переехала**

```bash
curl -sG https://vm.k3s.beerloga.su/api/v1/query --data-urlencode 'query=count(count_over_time(power_watt[60d]))' | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']['result']
print('серий power_watt за 60 дней:', d[0]['value'][1] if d else 'НЕТ ДАННЫХ')
"
```

Ожидаемо: непустое число — значит 90-дневная история на месте, а не начата с
нуля.

- [ ] **Step 4: Новые точки идут**

```bash
sleep 60
curl -sG https://vm.k3s.beerloga.su/api/v1/query --data-urlencode 'query=power_watt' | python3 -c "
import json,sys,time
d=json.load(sys.stdin)['data']['result']; now=time.time()
print('серий сейчас:', len(d))
for r in d[:3]: print(f\"  {r['metric'].get('unit','?')}: свежесть {now-float(r['value'][0]):.0f}с\")
"
```

Ожидаемо: свежесть в пределах минуты — `power` пишет в новый адрес.

- [ ] **Step 5: Дашборды**

Открыть `https://grafana.k3s.beerloga.su`, посмотреть любой дашборд за
последние сутки. Ожидаемо: график непрерывен, кроме короткого пропуска на
момент переезда. Пустые панели означают, что датасорс не переключился —
проверить `kubectl -n monitoring get cm grafana-datasources -o yaml`.

---

### Task 6: Бэкапы — перенос архивов и прогон

**Files:** изменений в git нет.

**Interfaces:**
- Consumes: CronJob'ы из Задачи 2.

- [ ] **Step 1: Перенести архивы Grafana в `backup/`**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n default run nas-move --rm -i --restart=Never --image=busybox:1.36 \
  --overrides='{"spec":{"containers":[{"name":"nas-move","image":"busybox:1.36","command":["sh","-c","mkdir -p /nas/backup/grafana /nas/backup/victoria-metrics && if [ -d /nas/grafana ]; then mv /nas/grafana/* /nas/backup/grafana/ 2>/dev/null; rmdir /nas/grafana; fi; chmod -R 777 /nas/backup; echo \"--- корень ---\"; ls -l /nas; echo \"--- backup ---\"; ls -l /nas/backup/grafana"],"volumeMounts":[{"name":"nas","mountPath":"/nas"}]}],"volumes":[{"name":"nas","nfs":{"server":"198.18.1.125","path":"/mnt/HD/HD_a2/k8s"}}]}}'
```

Ожидаемо: в корне остались только данные (`registry`, `smarthome`,
`zigbee2mqtt-data`, `backup`), архивы Grafana лежат в `backup/grafana/`.

- [ ] **Step 2: Применить CronJob'ы**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/monitoring
kubectl apply -f victoria-metrics-backup.yaml -f grafana-backup.yaml
```

Ожидаемо: `cronjob.batch/vmbackup created`, `cronjob.batch/grafana-backup configured`.

- [ ] **Step 3: Прогнать бэкап VictoriaMetrics вручную**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring create job vmbackup-manual --from=cronjob/vmbackup
kubectl -n monitoring wait --for=condition=complete job/vmbackup-manual --timeout=600s
kubectl -n monitoring logs job/vmbackup-manual | tail -5
kubectl -n monitoring delete job vmbackup-manual
```

Ожидаемо: в логе строки о создании снапшота и завершении копирования, без
ошибок. Если job висит в `Pending` — проверить, что он попал на `k3s-1`
(PVC `ReadWriteOnce` держит под VictoriaMetrics именно там).

- [ ] **Step 4: Прогнать бэкап Grafana и проверить путь**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring create job grafana-backup-manual --from=cronjob/grafana-backup
kubectl -n monitoring wait --for=condition=complete job/grafana-backup-manual --timeout=300s
kubectl -n monitoring logs job/grafana-backup-manual | tail -3
kubectl -n monitoring delete job grafana-backup-manual
```

Ожидаемо: листинг с архивами Grafana — теперь по пути `k8s/backup/grafana/`.

- [ ] **Step 5: Проверить итог на NAS**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n default run nas-check --rm -i --restart=Never --image=busybox:1.36 \
  --overrides='{"spec":{"containers":[{"name":"nas-check","image":"busybox:1.36","command":["sh","-c","echo Данные:; ls /nas; echo; echo Бэкапы:; ls -l /nas/backup/grafana /nas/backup/victoria-metrics | head -20"],"volumeMounts":[{"name":"nas","mountPath":"/nas"}]}],"volumes":[{"name":"nas","nfs":{"server":"198.18.1.125","path":"/mnt/HD/HD_a2/k8s"}}]}}'
```

Ожидаемо: в корне — данные и `backup`, внутри `backup/` — оба комплекта.

---

### Task 7: Перенести Grafana на k3s-1

Сейчас её PVC привязан к `k3s-2` — том создался там при первом запуске. После
переезда VictoriaMetrics все stateful-сервисы кластера окажутся на `k3s-1`,
кроме Grafana, и это стоит выровнять: одна нода — одно место, где лежат данные
и куда восстанавливать из бэкапа.

Перенос local-path тома между нодами делается только через копирование:
привязка PV к ноде неизменна, поэтому старый PVC удаляется, а новый создаётся
на нужной ноде. Промежуточная площадка — NFS.

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml` (добавить `nodeSelector`)

**Interfaces:**
- Consumes: работающий бэкап Grafana (Задача 6) — страховка на случай сбоя.

- [ ] **Step 1: Убедиться, что свежий бэкап есть**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n default run nas-check --rm -i --restart=Never --image=busybox:1.36 \
  --overrides='{"spec":{"containers":[{"name":"nas-check","image":"busybox:1.36","command":["sh","-c","ls -l /nas/backup/grafana | tail -3"],"volumeMounts":[{"name":"nas","mountPath":"/nas"}]}],"volumes":[{"name":"nas","nfs":{"server":"198.18.1.125","path":"/mnt/HD/HD_a2/k8s"}}]}}'
```

Ожидаемо: хотя бы один архив со свежей датой. Без него дальше не идти —
копирование между нодами единственная страховка потеряет.

- [ ] **Step 2: Зафиксировать эталон и погасить Grafana**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring exec deploy/grafana -- sh -c 'md5sum /var/lib/grafana/grafana.db; du -sb /var/lib/grafana | cut -f1'
kubectl -n monitoring scale deploy/grafana --replicas=0
kubectl -n monitoring wait --for=delete pod -l app=grafana --timeout=180s
```

Запомнить md5 и размер — по ним Шаг 6 проверит перенос.

- [ ] **Step 3: Скопировать данные на NFS (под на k3s-2, где лежит том)**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring run grafana-export --image=busybox:1.36 --restart=Never \
  --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"k3s-2"},"containers":[{"name":"grafana-export","image":"busybox:1.36","command":["sh","-c","mkdir -p /nas/tmp-grafana-migrate && cp -a /data/. /nas/tmp-grafana-migrate/ 2>/dev/null; chmod -R 777 /nas/tmp-grafana-migrate; ls -l /nas/tmp-grafana-migrate"],"volumeMounts":[{"name":"data","mountPath":"/data"},{"name":"nas","mountPath":"/nas"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"grafana-data"}},{"name":"nas","nfs":{"server":"198.18.1.125","path":"/mnt/HD/HD_a2/k8s"}}]}}'
kubectl -n monitoring wait --for=jsonpath='{.status.phase}'=Succeeded pod/grafana-export --timeout=300s
kubectl -n monitoring logs grafana-export | tail -8
kubectl -n monitoring delete pod grafana-export
```

Ожидаемо: в листинге `grafana.db` и остальные файлы. Ошибки
`can't preserve ownership` безвредны — NAS сквошит владельца.

- [ ] **Step 4: Пересоздать PVC на k3s-1**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring delete pvc grafana-data
```

В `ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml` добавить в `spec.template.spec`
(рядом с `securityContext`):

```yaml
      nodeSelector:
        kubernetes.io/hostname: k3s-1
```

и заменить комментарий про node affinity в шапке файла на:

```yaml
# Pinned to k3s-1: local-path ties the volume to a node anyway, and keeping all
# stateful services on one node means one place to look for data and one place
# to restore into.
```

Затем применить (Deployment пока в 0 репликах, том создастся при старте):

```bash
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml
```

- [ ] **Step 5: Залить данные на новом томе**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring run grafana-import --image=busybox:1.36 --restart=Never \
  --overrides='{"spec":{"nodeSelector":{"kubernetes.io/hostname":"k3s-1"},"containers":[{"name":"grafana-import","image":"busybox:1.36","command":["sh","-c","cp -a /nas/tmp-grafana-migrate/. /data/ 2>/dev/null; chown -R 472:472 /data; ls -l /data"],"volumeMounts":[{"name":"data","mountPath":"/data"},{"name":"nas","mountPath":"/nas"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"grafana-data"}},{"name":"nas","nfs":{"server":"198.18.1.125","path":"/mnt/HD/HD_a2/k8s"}}]}}'
kubectl -n monitoring wait --for=jsonpath='{.status.phase}'=Succeeded pod/grafana-import --timeout=300s
kubectl -n monitoring logs grafana-import | tail -8
kubectl -n monitoring delete pod grafana-import
```

Ожидаемо: файлы на месте, владелец `472:472` — это uid образа Grafana.

- [ ] **Step 6: Поднять и сверить**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring scale deploy/grafana --replicas=1
kubectl -n monitoring rollout status deploy/grafana --timeout=300s
kubectl -n monitoring get pod -l app=grafana -o jsonpath='нода={.items[0].spec.nodeName}{"\n"}'
kubectl -n monitoring exec deploy/grafana -- md5sum /var/lib/grafana/grafana.db
curl -s https://grafana.k3s.beerloga.su/api/health
```

Ожидаемо: нода `k3s-1`, md5 совпадает с эталоном из Шага 2, health отдаёт
`"database": "ok"`. Расхождение md5 означает потерю данных при копировании —
восстанавливать из бэкапа.

- [ ] **Step 7: Убрать временный каталог с NAS**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n default run nas-clean --rm -i --restart=Never --image=busybox:1.36 \
  --overrides='{"spec":{"containers":[{"name":"nas-clean","image":"busybox:1.36","command":["sh","-c","rm -rf /nas/tmp-grafana-migrate && ls /nas"],"volumeMounts":[{"name":"nas","mountPath":"/nas"}]}],"volumes":[{"name":"nas","nfs":{"server":"198.18.1.125","path":"/mnt/HD/HD_a2/k8s"}}]}}'
```

Ожидаемо: в корне экспорта временного каталога больше нет.

- [ ] **Step 8: Проверить дашборды глазами**

Открыть `https://grafana.k3s.beerloga.su` — дашборды на месте, включая ручные
(`Power`, `Tunnels`, `Xray Dashboard`), данные рисуются.

- [ ] **Step 9: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml
git commit -m "ops(k3s): move Grafana onto k3s-1 alongside the other stateful pods"
```

---

### Task 8: Документация

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/README.md`
- Modify: `ops/grafana/README.md` (адрес VictoriaMetrics)

- [ ] **Step 1: Дополнить apps/README.md**

После абзаца про сервисы умного дома добавить:

```markdown
VictoriaMetrics мигрирована с `198.18.1.102` 2026-08-09 — namespace
`monitoring`, под прибит к `k3s-1`, данные на `local-path` (NVMe). Здесь
сознательно НЕ NFS: у TSDB поток мелких записей с fsync, сетевая ФС для этого
не годится — в отличие от z2m и smarthome, где она уместна.

В кластере обращаться по `http://victoria-metrics.monitoring:8428`, снаружи —
`https://vm.k3s.beerloga.su`. Ночной бэкап — CronJob `vmbackup` (снапшот через
API, инкрементально).

**Раскладка на NAS:** данные лежат в корне экспорта (`registry/`, `smarthome/`,
`zigbee2mqtt-data/`), бэкапы — в `backup/` (`backup/grafana/`,
`backup/victoria-metrics/`).
```

- [ ] **Step 2: Поправить адрес VictoriaMetrics в ops/grafana/README.md**

Заменить упоминание датасорса:

```markdown
VictoriaMetrics с 2026-08-09 живёт в кластере (`monitoring/victoria-metrics`).
Датасорс `prometheus` (uid `adnsc1wi03doga`) смотрит на
`http://victoria-metrics.monitoring:8428`. Менять uid нельзя: дашборды
ссылаются на датасорс именно по нему.
```

- [ ] **Step 3: Проверить, что старый адрес не остался**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
grep -rn "198.18.1.102:8428\|vm.beerloga.su" ops/nanopi-r5c-k3s/ ops/grafana/README.md | grep -v "^Binary"
```

Ожидаемо: пусто либо только упоминания в историческом контексте (описание
того, как было до переезда).

- [ ] **Step 4: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/README.md ops/grafana/README.md
git commit -m "docs(k3s): record the VictoriaMetrics migration and the NAS layout rule"
```

---

## Известные ограничения

- **Под привязан к `k3s-1`.** Потеря ноды = восстановление из бэкапа; до
  первого успешного прогона `vmbackup` окно уязвимости шире обычного, поэтому
  Задача 6 идёт сразу за переездом.
- **Пропуск метрик** на время переезда виден в графиках как разрыв.
- **`.102` остаётся зависимостью**: там mosquitto и четыре экспортёра, которые
  VictoriaMetrics продолжает опрашивать по сети.
- **Имя `vm.beerloga.su`** остаётся указывать на `.102` и никем не
  используется; удалять запись не требуется.
- **Retention не меняется** — 90 дней, как было.
- **Все stateful-поды на `k3s-1`** (VictoriaMetrics, Grafana, samsung-tv).
  Потеря этой ноды означает восстановление всех троих; взамен понятно, где
  лежат данные.
