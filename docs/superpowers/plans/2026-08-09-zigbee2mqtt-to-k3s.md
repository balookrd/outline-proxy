# Миграция zigbee2mqtt в k3s: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Перенести zigbee2mqtt с docker на `198.18.1.102` в k3s, сохранив
зигби-сеть из 22 устройств и не трогая mosquitto.

**Architecture:** Координатор сетевой (`tcp://198.18.1.106:8888`), поэтому под не
привязан к железу. Каталог данных переезжает целиком на `local-path`;
`configuration.yaml` остаётся единственным источником настроек, переменных
окружения в манифесте нет. Брокер остаётся на `.102`, и z2m продолжает ходить на
него по тому же адресу, что записан в конфиге.

**Tech Stack:** k3s v1.36.2, zigbee2mqtt 2.12.0, local-path storage, Traefik
ingress с готовым wildcard-TLS, mosquitto на `.102`.

Спека: [`docs/superpowers/specs/2026-08-09-zigbee2mqtt-to-k3s-design.md`](../specs/2026-08-09-zigbee2mqtt-to-k3s-design.md).

## Global Constraints

- Образ строго `koenkk/zigbee2mqtt:2.12.0` — ровно та версия, что работает на
  `.102`. Заготовочная 2.1.1 запрещена: формат `database.db` она не примет.
- Namespace `home`. Имена: Deployment/Service/PVC — `zigbee2mqtt`,
  `zigbee2mqtt`, `zigbee2mqtt-data`.
- **Ни одной переменной окружения в манифесте.** Настройки живут в
  `configuration.yaml` внутри PVC; в нём уже прописаны координатор
  `tcp://198.18.1.106:8888` (`adapter: ember`) и брокер `mqtt://198.18.1.102:1883`.
- `securityContext`: `runAsUser: 1000`, `fsGroup: 1000` — совпадает и с uid
  внутри образа, и с владельцем файлов на `.102`, поэтому `chown` не нужен.
- StorageClass `local-path`, 1 Gi. `nodeSelector` не задавать: PV несёт
  node-affinity.
- `strategy: Recreate`, `replicas: 1`. Координатор пускает ровно одного клиента.
- Каталог `log/` не переносится и не бэкапится.
- Управление кластером с мака: `export KUBECONFIG=~/.kube/k3s-home.yaml`.
- Узел-источник: `ssh mmv@198.18.1.102`, `sudo -n` доступен, docker через sudo.
- `/opt/zigbee2mqtt` на `.102` **не удалять** — путь отката.
- Git: коммиты на английском, без Co-Authored-By и Claude-атрибуции, работаем в
  `main`. `git commit` — только по явной команде владельца.
- `ops/nanopi-r5c-k3s/` ведётся по-русски, EN-пары нет.

---

### Task 1: Манифест zigbee2mqtt

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/home/zigbee2mqtt.yaml` (переписать целиком)

**Interfaces:**
- Produces: Deployment `zigbee2mqtt` (ns `home`), PVC `zigbee2mqtt-data`,
  Service `zigbee2mqtt:8080`. PVC наполняет Задача 3; на Service уже смотрит
  готовый Ingress `z2m.k3s.beerloga.su`.

- [ ] **Step 1: Переписать zigbee2mqtt.yaml**

Полное содержимое `ops/nanopi-r5c-k3s/apps/home/zigbee2mqtt.yaml`:

```yaml
# zigbee2mqtt, migrated off the docker container on 198.18.1.102.
#
# The coordinator is a network adapter (tcp://198.18.1.106:8888), not a USB
# stick, so the pod is free to run on any node — no device passthrough, no
# nodeSelector. Data lives on local-path and the PV's node affinity keeps the
# pod with it.
#
# Singleton, and not merely by convention: the coordinator accepts exactly one
# client. Two replicas would fight over the session, so replicas: 1 + Recreate.
#
# There are deliberately NO environment variables here. configuration.yaml
# inside the PVC is the single source of truth — it already carries the
# coordinator address, the MQTT broker (mqtt://198.18.1.102:1883, still on the
# gateway node) and, critically, network_key / pan_id / ext_pan_id. Duplicating
# half of it into env is how the two drift apart.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zigbee2mqtt
  namespace: home
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels: { app: zigbee2mqtt }
  template:
    metadata:
      labels: { app: zigbee2mqtt }
    spec:
      securityContext:
        runAsUser: 1000       # matches the image and the migrated files
        fsGroup: 1000
      containers:
        - name: zigbee2mqtt
          image: koenkk/zigbee2mqtt:2.12.0
          ports:
            - { containerPort: 8080, name: frontend }
          volumeMounts:
            - { name: data, mountPath: /app/data }
          readinessProbe:
            # tcpSocket, not httpGet: the frontend answers / with a redirect.
            tcpSocket: { port: 8080 }
            initialDelaySeconds: 15
            periodSeconds: 10
          resources:
            requests: { cpu: 50m, memory: 128Mi }
            limits:   { memory: 384Mi }   # measured 102 MB in steady state
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: zigbee2mqtt-data
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: zigbee2mqtt-data
  namespace: home
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: local-path
  resources:
    requests:
      storage: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: zigbee2mqtt
  namespace: home
spec:
  selector: { app: zigbee2mqtt }
  ports:
    - { port: 8080, targetPort: 8080 }
```

- [ ] **Step 2: Проверить синтаксис**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/home
ruby -ryaml -e 'YAML.load_stream(File.read("zigbee2mqtt.yaml")); puts "yaml ok"'
```

Ожидаемо: `yaml ok`.

- [ ] **Step 3: Проверить против кластера, не применяя**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/home
kubectl apply --dry-run=server -f zigbee2mqtt.yaml
```

Ожидаемо: `deployment.apps/zigbee2mqtt created (server dry run)`,
`persistentvolumeclaim/zigbee2mqtt-data created (server dry run)`,
`service/zigbee2mqtt created (server dry run)`.

- [ ] **Step 4: Убедиться, что env не осталось**

```bash
grep -c "ZIGBEE2MQTT_CONFIG" zigbee2mqtt.yaml || echo "env нет — как и задумано"
```

Ожидаемо: `env нет — как и задумано`.

- [ ] **Step 5: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/home/zigbee2mqtt.yaml
git commit -m "ops(k3s): run zigbee2mqtt in the cluster"
```

---

### Task 2: CronJob бэкапа зигби-данных

**Files:**
- Create: `ops/nanopi-r5c-k3s/apps/home/zigbee2mqtt-backup.yaml`

**Interfaces:**
- Consumes: PVC `zigbee2mqtt-data` (Задача 1), NFS-экспорт
  `198.18.1.125:/mnt/HD/HD_a2/k8s`.
- Produces: CronJob `zigbee2mqtt-backup`, кладущий
  `z2m-YYYYmmdd-HHMM.tar.gz` в `/mnt/HD/HD_a2/k8s/backup/zigbee2mqtt`.

- [ ] **Step 1: Создать манифест**

Полное содержимое `ops/nanopi-r5c-k3s/apps/home/zigbee2mqtt-backup.yaml`:

```yaml
# Nightly zigbee2mqtt backup to the NAS.
#
# database.db together with coordinator_backup.json IS the Zigbee network map:
# lose it and all 22 devices have to be re-paired by hand. configuration.yaml
# carries network_key / pan_id, which are equally unrecoverable.
#
# Plain tar — no package installation, so no root needed (the pod runs as 1000).
# The log directory is excluded: it is churn, not state.
#
# The NFS volume is inline rather than via a StorageClass: nfs-provisioner is
# not deployed, and one CronJob does not justify it.
apiVersion: batch/v1
kind: CronJob
metadata:
  name: zigbee2mqtt-backup
  namespace: home
spec:
  schedule: "45 3 * * *"      # after grafana-backup at 03:30
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 2
      template:
        spec:
          restartPolicy: Never
          securityContext:
            runAsUser: 1000
            fsGroup: 1000
          containers:
            - name: backup
              image: alpine:3.20
              command:
                - /bin/sh
                - -c
                - |
                  set -eu
                  stamp=$(date +%Y%m%d-%H%M)
                  dest=/backup/zigbee2mqtt
                  mkdir -p "$dest"
                  tar czf "$dest/z2m-$stamp.tar.gz" -C /data --exclude=./log .
                  # Keep the last seven; the timestamp format sorts
                  # chronologically under a plain lexical sort.
                  ls -1 "$dest"/z2m-*.tar.gz | head -n -7 | xargs -r rm -f
                  ls -l "$dest"
              volumeMounts:
                - { name: data, mountPath: /data, readOnly: true }
                - { name: backup, mountPath: /backup }
          volumes:
            - name: data
              persistentVolumeClaim:
                claimName: zigbee2mqtt-data
                readOnly: true
            - name: backup
              nfs:
                server: 198.18.1.125
                path: /mnt/HD/HD_a2/k8s
```

- [ ] **Step 2: Проверить синтаксис**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/home
ruby -ryaml -e 'YAML.load_stream(File.read("zigbee2mqtt-backup.yaml")); puts "yaml ok"'
```

Ожидаемо: `yaml ok`.

- [ ] **Step 3: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/home/zigbee2mqtt-backup.yaml
git commit -m "ops(k3s): nightly zigbee2mqtt backup to the NAS"
```

---

### Task 3: Переезд

Здесь открывается окно: зигби-команды из MQTT не обрабатываются, пока не
поднимется под. Сеть при этом жива — координатор автономен, привязки
кнопка→лампа продолжают работать.

**Files:** изменений в git нет.

**Interfaces:**
- Consumes: манифест из Задачи 1.
- Produces: работающий под z2m с перенесёнными данными.

- [ ] **Step 1: Зафиксировать эталон для сверки**

```bash
ssh mmv@198.18.1.102 'sudo -n md5sum /opt/zigbee2mqtt/data/configuration.yaml /opt/zigbee2mqtt/data/database.db; sudo -n grep -c . /opt/zigbee2mqtt/data/database.db'
```

Запомнить обе контрольные суммы и число строк (сейчас 22) — по ним Шаг 7
проверит, что данные доехали без потерь.

- [ ] **Step 2: Создать PVC, не поднимая под**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/home
kubectl apply -f zigbee2mqtt.yaml
kubectl -n home scale deploy/zigbee2mqtt --replicas=0
```

Ожидаемо: три объекта созданы, реплики сведены к нулю. PVC остаётся `Pending` —
`local-path` использует `WaitForFirstConsumer`, том появится с первым подом.

- [ ] **Step 3: Остановить контейнер на .102**

```bash
ssh mmv@198.18.1.102 'sudo -n docker update --restart=no z2m >/dev/null && sudo -n docker stop z2m >/dev/null && sudo -n docker inspect -f "{{.State.Status}} restart={{.HostConfig.RestartPolicy.Name}}" z2m'
```

Ожидаемо: `exited restart=no`. `--restart=no` обязателен: иначе после
перезагрузки узла контейнер вернётся и начнёт драться с подом за координатор.

- [ ] **Step 4: Упаковать данные**

```bash
ssh mmv@198.18.1.102 'cd /opt/zigbee2mqtt/data && sudo -n tar czf /tmp/z2m-data.tar.gz --exclude=./log . && sudo -n chown mmv:mmv /tmp/z2m-data.tar.gz && ls -l /tmp/z2m-data.tar.gz'
```

Ожидаемо: архив в пределах сотни килобайт.

- [ ] **Step 5: Поднять helper-под и залить данные**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n home run z2m-loader --image=busybox:1.36 --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"z2m-loader","image":"busybox:1.36","command":["sleep","3600"],"volumeMounts":[{"name":"data","mountPath":"/data"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"zigbee2mqtt-data"}}]}}'
kubectl -n home wait --for=condition=Ready pod/z2m-loader --timeout=240s
scp mmv@198.18.1.102:/tmp/z2m-data.tar.gz /tmp/z2m-data.tar.gz
kubectl -n home cp /tmp/z2m-data.tar.gz z2m-loader:/data/z2m-data.tar.gz
kubectl -n home exec z2m-loader -- sh -c 'cd /data && tar xzf z2m-data.tar.gz && rm -f z2m-data.tar.gz && ls -l /data'
```

Ожидаемо: в `/data` — `configuration.yaml`, `database.db`,
`coordinator_backup.json`, `state.json`, `device_icons/`, все с владельцем
`1000:1000`. Отдельный `chown` не нужен, в отличие от переезда Grafana: helper
распаковывает архив от root, а `tar` восстанавливает исходных владельцев — на
`.102` файлы уже принадлежат uid 1000, и ровно под этим uid работает контейнер
z2m. Если в листинге владелец другой — выполнить
`kubectl -n home exec z2m-loader -- chown -R 1000:1000 /data`.

- [ ] **Step 6: Убрать helper и поднять z2m**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n home delete pod z2m-loader
rm -f /tmp/z2m-data.tar.gz
ssh mmv@198.18.1.102 'rm -f /tmp/z2m-data.tar.gz'
kubectl -n home scale deploy/zigbee2mqtt --replicas=1
kubectl -n home rollout status deploy/zigbee2mqtt --timeout=300s
```

Ожидаемо: `deployment "zigbee2mqtt" successfully rolled out`.

- [ ] **Step 7: Сверить данные с эталоном**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n home exec deploy/zigbee2mqtt -- sh -c 'md5sum /app/data/configuration.yaml; grep -c . /app/data/database.db'
```

`configuration.yaml` обязан совпасть с суммой из Шага 1. У `database.db`
сравнивается только число строк: z2m его переписывает при старте, поэтому md5
разойдётся законно, а вот число устройств уменьшиться не должно.

Расхождение в `configuration.yaml` означает, что уехал не тот файл, — сеть с
чужим `network_key` не соберётся. Тогда откатиться (Шаг 9) и разбираться.

Коммита нет.

- [ ] **Step 8: Проверить, что z2m ожил**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n home logs deploy/zigbee2mqtt | grep -iE "connected to mqtt|coordinator|started|error" | head -10
```

Ожидаемо: подключение к MQTT и к координатору, без `error`.

- [ ] **Step 9: Знать, как откатиться**

Если что-то пошло не так:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n home scale deploy/zigbee2mqtt --replicas=0
ssh mmv@198.18.1.102 'sudo -n docker update --restart=unless-stopped z2m && sudo -n docker start z2m'
```

Данные на `.102` нетронуты. Порядок важен: сначала погасить под, потом поднять
контейнер — иначе оба будут ломиться к координатору.

---

### Task 4: Проверка сквозного пути

**Files:** изменений в git нет.

- [ ] **Step 1: Фронтенд по HTTPS**

```bash
curl -s -o /dev/null -w 'z2m: %{http_code} verify=%{ssl_verify_result}\n' https://z2m.k3s.beerloga.su
```

Ожидаемо: `200 0` (или `302 0` с редиректом фронтенда) и `verify=0` —
сертификат от общего wildcard уже валиден.

- [ ] **Step 2: z2m публикует в MQTT**

Проверяем не retained-состояние (оно могло остаться от старого контейнера), а
живой поток: подписываемся и ждём сообщение от любого устройства.

```bash
ssh mmv@198.18.1.102 'timeout 90 sudo -n docker exec mosquitto mosquitto_sub -h localhost -t "zigbee2mqtt/+" -C 3 -v 2>&1 | head -5'
```

Ожидаемо: три сообщения с состояниями устройств. Пусто за 90 секунд — z2m к
брокеру не подключился либо не видит координатор; смотреть логи пода.

- [ ] **Step 3: Список устройств на месте**

```bash
ssh mmv@198.18.1.102 'timeout 30 sudo -n docker exec mosquitto mosquitto_sub -h localhost -t "zigbee2mqtt/bridge/devices" -C 1 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(\"устройств:\", len(d))
print(\"онлайн:\", sum(1 for x in d if x.get(\"supported\") is not False))
"'
```

Ожидаемо: число устройств того же порядка, что и до переезда (22 записи в
`database.db`, часть из них — координатор и группы).

- [ ] **Step 4: Проверить в UI**

Открыть `https://z2m.k3s.beerloga.su` — список устройств, у большинства свежий
`last seen`. Это то, что не проверить командой.

---

### Task 5: Бэкап — применение и прогон

**Files:** изменений в git нет.

**Interfaces:**
- Consumes: манифест из Задачи 2, наполненный PVC из Задачи 3.

- [ ] **Step 1: Применить CronJob и прогнать вручную**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/home
kubectl apply -f zigbee2mqtt-backup.yaml
kubectl -n home create job z2m-backup-manual --from=cronjob/zigbee2mqtt-backup
kubectl -n home wait --for=condition=complete job/z2m-backup-manual --timeout=300s
kubectl -n home logs job/z2m-backup-manual | tail -5
```

Ожидаемо: job завершается, в логе — листинг с одним `z2m-<дата>.tar.gz`.

Если под висит в `ContainerCreating` с ошибкой монтирования NFS — проверить, что
экспорт `198.18.1.125:/mnt/HD/HD_a2/k8s` доступен с ноды (NFS-клиент на нодах
есть: `nfs-utils 2.8.3`, проверять через `ls /usr/sbin/mount.nfs`, а не
`command -v` — `/usr/sbin` вне PATH неинтерактивного ssh).

- [ ] **Step 2: Проверить содержимое архива**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n home run z2m-check --rm -i --restart=Never --image=alpine:3.20 \
  --overrides='{"spec":{"containers":[{"name":"z2m-check","image":"alpine:3.20","command":["sh","-c","ls -l /backup/zigbee2mqtt && tar tzf /backup/zigbee2mqtt/$(ls -1 /backup/zigbee2mqtt | tail -1)"],"volumeMounts":[{"name":"backup","mountPath":"/backup"}]}],"volumes":[{"name":"backup","nfs":{"server":"198.18.1.125","path":"/mnt/HD/HD_a2/k8s"}}]}}'
```

Ожидаемо: в архиве `./configuration.yaml`, `./database.db`,
`./coordinator_backup.json`, `./state.json` и **нет** `./log`.

- [ ] **Step 3: Убрать тестовый job**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n home delete job z2m-backup-manual
```

---

### Task 6: Документация

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/README.md`

- [ ] **Step 1: Обновить раздел о пропускаемых манифестах**

В `apps/README.md` в абзаце **Guard** сейчас сказано, что пропускается
`zigbee2mqtt` из-за `<COORDINATOR_IP>`. Это больше не так — заменить упоминание:

```markdown
**Guard.** Скрипт не применяет `*.example.yaml` (шаблоны секретов) и любой манифест с
незаполненными `<PLACEHOLDER>` — вместо битого объекта печатает `[skip]`. Сейчас
пропускаются `outline/*` и `ocserv` (`<REGISTRY>/<TAG>`) — заполнишь значения,
повторный прогон их подхватит.
```

- [ ] **Step 2: Добавить абзац про zigbee2mqtt**

После абзаца про Grafana добавить:

```markdown
zigbee2mqtt мигрирован с `198.18.1.102` 2026-08-09. Координатор сетевой
(`tcp://198.18.1.106:8888`), поэтому под не привязан к железу. Настройки —
в `configuration.yaml` внутри PVC, а не в переменных окружения: там же лежат
`network_key` и `pan_id`, без которых сеть из 22 устройств не соберётся.
Брокер mosquitto **остался на `.102`** вместе с шестью контейнерами умного дома
и четырьмя внешними клиентами; z2m ходит на него по прежнему адресу.
Ночной бэкап — CronJob `zigbee2mqtt-backup` на NAS, семь копий.
```

- [ ] **Step 3: Проверить, что упоминание COORDINATOR_IP исчезло**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
grep -rn "COORDINATOR_IP" ops/ || echo "плейсхолдера больше нет"
```

Ожидаемо: `плейсхолдера больше нет`.

- [ ] **Step 4: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/README.md
git commit -m "docs(k3s): record the zigbee2mqtt migration"
```

---

## Известные ограничения

- Под привязан к ноде через local-path. Потеря ноды = восстановление PVC из
  бэкапа на NAS.
- `.102` остаётся зависимостью: там mosquitto, а координатор — отдельная железка
  в LAN. Переезд снимает с узла один сервис, но не развязывает умный дом.
- Старый адрес фронтенда `http://198.18.1.102:8080` перестаёт отвечать; новый —
  `https://z2m.k3s.beerloga.su`.
- Mosquitto и остальные контейнеры умного дома на `.102` не тронуты и в этот
  план не входят.
