# Миграция mosquitto с `.102` в k3s — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** перенести MQTT-брокер с докера на `198.18.1.102` в кластер k3s так,
чтобы ни одна железка умного дома не осталась без брокера — включая waterius,
который перенастроить нельзя.

**Архитектура:** `eclipse-mosquitto:2.1.2-alpine` в namespace `home`, конфиг и оба
ACL-файла в ConfigMap, `mosquitto.db` — на NFS тем же inline-томом, что у
zigbee2mqtt (`198.18.1.125:/mnt/HD/HD_a2/k8s/mosquitto-data`). Наружу —
`Service type=LoadBalancer` на MetalLB-VIP `198.18.1.201` с портами 1883 и 1888;
внутрь кластера — ClusterIP `mosquitto.home`. Имя `mqtt.beerloga.su`
переезжает с `.102` на `.201`, а сам `.102` остаётся отвечать на 1883/1888
через два `socat`-юнита — ради waterius, который ходит по литеральному IP.

**Стек:** k3s v1.36.2, MetalLB L2, NFS-шара на `198.18.1.125`, systemd + socat на `.102`,
Keenetic (`198.18.1.1`) как LAN-DNS.

## Global Constraints

- Образ пинуется: `eclipse-mosquitto:2.1.2-alpine`. Тега `2.1.2` не существует:
  ветка 2.1 публикуется только в `-alpine`, и её digest совпадает с `latest`,
  который тянул докер на `.102`. Оставлять `latest` в кластере нельзя.
- Оба листенера обязательны: **1883** с `acl_allow_all.conf`, **1888** с
  `acl_spruthub.conf`. Потеря второго не проявится как ошибка — spruthub просто
  начнёт видеть `espresense/#`.
- `per_listener_settings true`, анонимный доступ на обоих листенерах —
  как сейчас. Аутентификация в область не входит.
- VIP `198.18.1.201` — из пула MetalLB `198.18.1.200-210`, на момент написания
  плана свободен (не отвечает на ping).
- Namespace `home`. Данные — на NFS, поэтому под к ноде не привязывается
  (как zigbee2mqtt и в отличие от Grafana / VictoriaMetrics).
- **Waterius нельзя проверить сразу.** Пока он не выйдет на связь, миграция не
  считается завершённой.
- Правило парка: не перезапускать прод без явного согласия владельца. Окно
  простоя брокера (Task 3) начинать только по команде.
- Git: коммиты и пуш — только по явной команде владельца.

---

### Task 1: манифест брокера в репозитории

Существующий `apps/home/mosquitto.yaml` — заготовка, написанная до того, как
стал известен реальный конфиг: там один листенер, `allow_anonymous true`,
образ `2.0.20`, PVC на storageClass `nfs-client` (в кластере такого нет — есть
только `local-path`) и `TODO` в комментарии. Файл переписывается целиком.

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/home/mosquitto.yaml` (переписать)
- Modify: `ops/nanopi-r5c-k3s/apps/deploy.sh:129` (каталог `smarthome` в `stage_apps`)
- Create (на NAS): `198.18.1.125:/mnt/HD/HD_a2/k8s/mosquitto-data/`

**Interfaces:**
- Produces: `Service mosquitto.home:1883` (ClusterIP) — на него в Task 6
  переключаются пять сервисов smarthome и z2m;
  `Service mosquitto-lan` → `198.18.1.201:1883,1888` — на него в Task 5
  переезжает `mqtt.beerloga.su` и в Task 4 смотрят socat-юниты;
  каталог `mosquitto-data` на NAS — в него в Task 3 кладётся `mosquitto.db`.

- [ ] **Шаг 1: завести каталог на NAS**

Каталог должен существовать до старта пода: inline NFS-том его не создаёт, и
без него под встанет в `ContainerCreating` с ошибкой монтирования. Права на
шаре — `0777`, поэтому uid значения не имеет.

```bash
ssh mmv@198.18.1.51 'sudo mkdir -p /mnt/nastmp && sudo mount -t nfs 198.18.1.125:/mnt/HD/HD_a2/k8s /mnt/nastmp && sudo mkdir -p /mnt/nastmp/mosquitto-data && sudo ls -la /mnt/nastmp && sudo umount /mnt/nastmp'
```

Ожидается, что `mosquitto-data` появился рядом с `zigbee2mqtt-data`,
`registry`, `smarthome` и `backup`.

- [ ] **Шаг 2: переписать манифест**

Содержимое `ops/nanopi-r5c-k3s/apps/home/mosquitto.yaml` целиком:

```yaml
# Mosquitto MQTT broker, migrated off the docker container on 198.18.1.102.
#
# Two listeners, not one. 1883 is open to everything; 1888 exists solely so
# spruthub cannot see espresense/# — the ACL files are the whole point of this
# config, and dropping the second listener would not fail, it would silently
# leak topics.
#
# Data on NFS, same as zigbee2mqtt. mosquitto.db is not SQLite: mosquitto
# rewrites it whole on every autosave, with no locking and no page cache for a
# network filesystem to tear. So the usual reason to avoid NFS does not apply,
# and in exchange the pod is not nailed to whichever node holds the volume.
apiVersion: v1
kind: ConfigMap
metadata:
  name: mosquitto-config
  namespace: home
data:
  # Copied verbatim from /opt/mosquitto/config on 198.18.1.102, minus the
  # `user 1000` directive: the container already runs as uid 1000 via
  # securityContext, and mosquitto only warns when it cannot drop privileges
  # it never had.
  mosquitto.conf: |
    per_listener_settings true

    listener 1883
    listener_allow_anonymous true
    acl_file /mosquitto/config/acl_allow_all.conf

    listener 1888
    listener_allow_anonymous true
    acl_file /mosquitto/config/acl_spruthub.conf

    persistence true
    persistence_file mosquitto.db
    persistence_location /mosquitto/data
    autosave_interval 1800
    autosave_on_changes false

    log_dest stdout
    log_type error
    log_type warning
    connection_messages false
    log_timestamp false
  acl_allow_all.conf: |
    topic readwrite #
  acl_spruthub.conf: |
    topic deny espresense/#
    topic readwrite #
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mosquitto
  namespace: home
spec:
  replicas: 1
  strategy:
    type: Recreate            # one writer for mosquitto.db, one bind of :1883
  selector:
    matchLabels: { app: mosquitto }
  template:
    metadata:
      labels: { app: mosquitto }
    spec:
      securityContext:
        runAsUser: 1000       # same uid the docker container ran as
        fsGroup: 1000
      containers:
        - name: mosquitto
          image: eclipse-mosquitto:2.1.2-alpine
          ports:
            - { containerPort: 1883, name: mqtt }
            - { containerPort: 1888, name: mqtt-spruthub }
          # Three subPath mounts instead of one directory mount, because
          # mosquitto 2.1 refuses to open an acl_file that is a symlink —
          # and a ConfigMap mounted as a directory is nothing but symlinks
          # into ..data. The failure is "Unable to open acl_file", which
          # reads like a permissions problem and is not one: mosquitto.conf
          # itself loads fine through the very same symlink.
          #
          # The cost of subPath: edits to the ConfigMap do not reach the
          # container until the pod restarts. Mosquitto would need a restart
          # to pick up a new ACL anyway.
          volumeMounts:
            - { name: data,   mountPath: /mosquitto/data }
            - { name: config, mountPath: /mosquitto/config/mosquitto.conf,      subPath: mosquitto.conf }
            - { name: config, mountPath: /mosquitto/config/acl_allow_all.conf,  subPath: acl_allow_all.conf }
            - { name: config, mountPath: /mosquitto/config/acl_spruthub.conf,   subPath: acl_spruthub.conf }
          readinessProbe:
            tcpSocket: { port: 1883 }
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests: { cpu: 20m, memory: 32Mi }
            limits:   { memory: 128Mi }
      volumes:
        - name: data
          nfs:
            server: 198.18.1.125
            path: /mnt/HD/HD_a2/k8s/mosquitto-data
        - name: config
          configMap:
            name: mosquitto-config
---
# In-cluster access: z2m and the smarthome services reach the broker by this
# name. They must NOT go through the LoadBalancer VIP — a pod talking to its
# own cluster's MetalLB address leaves the node and comes back, which already
# bit us once with Grafana behind Traefik.
apiVersion: v1
kind: Service
metadata:
  name: mosquitto
  namespace: home
spec:
  selector: { app: mosquitto }
  ports:
    - { name: mqtt, port: 1883, targetPort: 1883 }
---
# LAN access for the smart-home devices. L4, so it bypasses Traefik entirely
# and takes its own MetalLB VIP.
#
# externalTrafficPolicy: Local keeps the client's source address — without it
# kube-proxy SNATs every connection to a node address and the broker's
# connection list stops telling which device is which. Only the node running
# the pod then attracts traffic, which is exactly what MetalLB's L2 speaker
# already does: it announces the VIP from that node and re-announces when the
# pod moves.
apiVersion: v1
kind: Service
metadata:
  name: mosquitto-lan
  namespace: home
  annotations:
    metallb.universe.tf/loadBalancerIPs: 198.18.1.201
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local
  selector: { app: mosquitto }
  ports:
    - { name: mqtt,          port: 1883, targetPort: 1883 }
    - { name: mqtt-spruthub, port: 1888, targetPort: 1888 }
```

- [ ] **Шаг 3: добавить `smarthome` в раскатку**

`stage_apps` перебирает `monitoring home outline vpn` — каталог `smarthome`
туда не попал, хотя пять его манифестов давно на проде. Правки Task 6 в этих
файлах иначе не доедут при пересборке кластера.

В `ops/nanopi-r5c-k3s/apps/deploy.sh` заменить строку

```bash
  for d in monitoring home outline vpn; do
```

на

```bash
  for d in monitoring home smarthome outline vpn; do
```

- [ ] **Шаг 4: проверить, что манифест разбирается**

```bash
kubectl apply --dry-run=client -f ops/nanopi-r5c-k3s/apps/home/mosquitto.yaml
```

Ожидается четыре строки `... configured (dry run)` / `created (dry run)`
(ConfigMap, Deployment и два Service), без ошибок.

- [ ] **Шаг 5: коммит** (по команде владельца)

```bash
git add ops/nanopi-r5c-k3s/apps/home/mosquitto.yaml ops/nanopi-r5c-k3s/apps/deploy.sh docs/superpowers
git commit -m "ops(k3s): real mosquitto manifest with both listeners and a LAN VIP"
```

---

### Task 2: поднять брокер в кластере рядом с работающим

Брокер на `.102` продолжает обслуживать всех: имя `mqtt.beerloga.su` пока
указывает на него. Новый брокер поднимается пустым и проверяется без окна
простоя.

**Files:** нет (только `kubectl`)

**Interfaces:**
- Consumes: манифест из Task 1.
- Produces: работающий под `mosquitto`, VIP `198.18.1.201` с двумя открытыми
  портами.

- [ ] **Шаг 1: применить манифест**

```bash
scp ops/nanopi-r5c-k3s/apps/home/mosquitto.yaml mmv@198.18.1.51:/tmp/mosquitto.yaml
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl apply -f /tmp/mosquitto.yaml'
```

- [ ] **Шаг 2: дождаться пода**

```bash
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home rollout status deploy/mosquitto --timeout=120s'
```

Ожидается `deployment "mosquitto" successfully rolled out`.

- [ ] **Шаг 3: убедиться, что VIP выдан и это `.201`**

```bash
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home get svc mosquitto-lan'
```

Ожидается `EXTERNAL-IP  198.18.1.201` и `1883:...,1888:...`. Если `<pending>` —
проверить `kubectl -n metallb-system logs deploy/metallb-controller`: скорее
всего адрес занят другим Service.

- [ ] **Шаг 4: оба порта отвечают с мака**

```bash
nc -z -G2 198.18.1.201 1883 && echo "1883 ok"; nc -z -G2 198.18.1.201 1888 && echo "1888 ok"
```

Ожидается обе строки `ok`.

- [ ] **Шаг 5: брокер действительно говорит по MQTT, и ACL на 1888 работает**

Проба поднимается в кластере, чтобы не зависеть от наличия `mosquitto_clients`
на маке. Публикуем в `espresense/probe` через 1883 и пытаемся прочитать через
1888 — второй листенер обязан не отдать ничего.

Клиенты `mosquitto_pub`/`mosquitto_sub` есть в самом образе, поэтому проба
идёт через `exec` в работающий под. Отдельный под с `kubectl run -i` для этого
не годится: он подвисает на предупреждении о записи сессии в логи.

```bash
kubectl -n home exec deploy/mosquitto -- sh -c '
mosquitto_pub -h 127.0.0.1 -p 1883 -t espresense/probe -m hello -r
mosquitto_pub -h 127.0.0.1 -p 1883 -t other/probe -m visible -r
echo "--- espresense через 1883:"; mosquitto_sub -h 127.0.0.1 -p 1883 -t "espresense/#" -C 1 -W 3 -v; echo "rc=$?"
echo "--- espresense через 1888 (должно быть пусто):"; mosquitto_sub -h 127.0.0.1 -p 1888 -t "espresense/#" -C 1 -W 3 -v; echo "rc=$?"
echo "--- other через 1888 (должно прийти):"; mosquitto_sub -h 127.0.0.1 -p 1888 -t "other/#" -C 1 -W 3 -v; echo "rc=$?"'
```

Ожидается: `espresense/probe hello` и `rc=0` через 1883; `Timed out` и `rc=27`
через 1888; `other/probe visible` и `rc=0` через 1888. Если espresense
приходит и на 1888 — ACL не подхватился, смотреть логи пода.

- [ ] **Шаг 6: убрать тестовое retained-сообщение**

Иначе оно уедет в перенесённую БД и останется там навсегда.

```bash
kubectl -n home exec deploy/mosquitto -- sh -c '
mosquitto_pub -h 127.0.0.1 -p 1883 -t espresense/probe -r -n
mosquitto_pub -h 127.0.0.1 -p 1883 -t other/probe -r -n
mosquitto_sub -h 127.0.0.1 -p 1883 -t "#" -W 3 -v'
```

Последняя подписка должна отдать `Timed out` — ничего retained не осталось.

**ЧЕКПОЙНТ:** брокер в кластере поднят и проверен, прод не тронут. Дальше
начинается окно простоя — согласовать с владельцем.

---

### Task 3: окно — перенос `mosquitto.db` и остановка докера

Пока брокер меняется, умный дом не обменивается сообщениями: команды не
проходят, состояния не обновляются. Окно — минуты.

**Files:** нет (`kubectl`, `ssh` на `.102`)

**Interfaces:**
- Consumes: каталог `mosquitto-data` на NAS, под из Task 2.
- Produces: перенесённые retained-сообщения; докер-контейнер на `.102`
  остановлен и снят с автозапуска (путь отката).

- [ ] **Шаг 1: остановить докер-контейнер и снять автозапуск**

Сначала останов — чтобы `mosquitto.db` дописался и был консистентным.

```bash
ssh mmv@198.18.1.102 'docker update --restart=no mosquitto && docker stop mosquitto && docker ps -a --filter name=mosquitto --format "{{.Names}} {{.Status}}"'
```

Ожидается `mosquitto Exited (0) ...`.

- [ ] **Шаг 2: погасить под, чтобы он не переписал БД своей пустой**

Mosquitto сохраняет persistence при получении SIGTERM. Копировать в том живого
пода бессмысленно — он затрёт файл на выходе.

```bash
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home scale deploy/mosquitto --replicas=0'
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home wait --for=delete pod -l app=mosquitto --timeout=60s'
```

- [ ] **Шаг 3: перенести БД на NAS**

Том — обычный каталог на шаре, так что вспомогательный под не нужен: файл
переносится напрямую через `.51`, где шара монтируется.

```bash
ssh mmv@198.18.1.102 'sudo md5sum /opt/mosquitto/data/mosquitto.db'
ssh mmv@198.18.1.102 'sudo cat /opt/mosquitto/data/mosquitto.db' | \
  ssh mmv@198.18.1.51 'sudo mount -t nfs 198.18.1.125:/mnt/HD/HD_a2/k8s /mnt/nastmp && sudo tee /mnt/nastmp/mosquitto-data/mosquitto.db >/dev/null && sudo md5sum /mnt/nastmp/mosquitto-data/mosquitto.db && sudo ls -l /mnt/nastmp/mosquitto-data/ && sudo umount /mnt/nastmp'
```

Две суммы md5 должны совпасть, размер — около 880 КБ. Права на шаре `0777`,
поэтому под под uid 1000 файл прочитает и перезапишет.

- [ ] **Шаг 4: вернуть брокер**

```bash
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home scale deploy/mosquitto --replicas=1 && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home rollout status deploy/mosquitto --timeout=120s'
```

- [ ] **Шаг 5: retained-сообщения пережили переезд**

```bash
kubectl -n home exec deploy/mosquitto -- mosquitto_sub -h 127.0.0.1 -p 1883 -t "zigbee2mqtt/bridge/state" -C 1 -W 5
```

Ожидается немедленный ответ вида `{"state":"online"}` — это сообщение
retained, оно приходит из перенесённой БД, а не из живого потока (z2m в этот
момент ещё смотрит на `.102`).

Если пусто — БД не подхватилась: проверить логи пода и права на файл.

**ЧЕКПОЙНТ:** брокер в кластере несёт состояние старого. Железки ещё не
переключены — они стучатся в мёртвый `.102`.

---

### Task 4: вернуть жизнь адресу `198.18.1.102`

Waterius прописан литеральным IP и перенастройке не поддаётся, поэтому
`.102:1883` должен принимать подключения постоянно, а не до конца миграции.
Порт 1888 пробрасывается заодно — на случай, если у какой-то железки остался
старый адрес.

**Files:**
- Create (на `.102`): `/etc/systemd/system/mqtt-forward@.service`

**Interfaces:**
- Consumes: VIP `198.18.1.201` из Task 2.
- Produces: `198.18.1.102:1883` и `:1888` снова принимают TCP.

- [ ] **Шаг 1: поставить socat**

```bash
ssh mmv@198.18.1.102 'sudo apt-get install -y socat && socat -V | head -1'
```

- [ ] **Шаг 2: шаблонный юнит**

Один шаблон на оба порта: имя инстанса и есть номер порта.

```bash
ssh mmv@198.18.1.102 'sudo tee /etc/systemd/system/mqtt-forward@.service >/dev/null <<EOF
[Unit]
# Keeps the pre-migration broker address alive: mosquitto now lives in k3s on
# 198.18.1.201, but waterius has 198.18.1.102 burned in and cannot be
# reconfigured. %i is the port.
#
# socat rather than an nftables DNAT rule: DNAT here needs masquerade anyway
# (the reply would otherwise come from the VIP the client never dialed), so
# both options hide the client address equally — and socat needs no rules in
# the nat table, which docker owns on this host while nftables.service is
# disabled.
Description=MQTT forward 198.18.1.102:%i -> 198.18.1.201:%i
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/socat -d TCP4-LISTEN:%i,reuseaddr,fork,keepalive TCP4:198.18.1.201:%i,keepalive
Restart=always
RestartSec=5
DynamicUser=yes
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF'
```

- [ ] **Шаг 3: включить оба инстанса**

```bash
ssh mmv@198.18.1.102 'sudo systemctl daemon-reload && sudo systemctl enable --now mqtt-forward@1883 mqtt-forward@1888 && systemctl is-active mqtt-forward@1883 mqtt-forward@1888'
```

Ожидается две строки `active`.

- [ ] **Шаг 4: старый адрес снова говорит по MQTT**

Это и есть проверка пути waterius. Клиент берётся из докер-образа, который на
`.102` уже скачан.

```bash
ssh mmv@198.18.1.102 'docker run --rm --network host eclipse-mosquitto:2.1.2-alpine mosquitto_sub -h 198.18.1.102 -p 1883 -t "zigbee2mqtt/bridge/state" -C 1 -W 5'
```

Ожидается `{"state":"online"}` — запрос прошёл `.102` → socat → VIP → под.

- [ ] **Шаг 5: 1888 тоже проброшен**

```bash
ssh mmv@198.18.1.102 'nc -z -w2 198.18.1.102 1888 && echo "1888 ok"'
```

**ЧЕКПОЙНТ:** оба адреса — старый и новый — обслуживают брокер.

---

### Task 5: перевести `mqtt.beerloga.su` на новый VIP

Владелец заранее перевёл spruthub и три ESPresense с литерального IP на имя,
поэтому одна DNS-запись переключает их все. Запись живёт на Keenetic
`198.18.1.1`, TTL 600 — до десяти минут на распространение.

**Files:** нет (веб-интерфейс роутера)

**Interfaces:**
- Consumes: VIP из Task 2.
- Produces: `mqtt.beerloga.su` → `198.18.1.201`.

- [ ] **Шаг 1: зафиксировать текущее значение**

```bash
dig +short mqtt.beerloga.su
```

Ожидается `198.18.1.102` — это значение для отката.

- [ ] **Шаг 2: поменять запись** — действие владельца

На `198.18.1.1`, в списке DNS-записей: `mqtt.beerloga.su` → `198.18.1.201`.
Остальные записи (`*.k3s.beerloga.su` → `198.18.1.200`) не трогать.

- [ ] **Шаг 3: дождаться распространения**

```bash
for i in $(seq 1 20); do a=$(dig +short mqtt.beerloga.su); echo "$a"; [ "$a" = "198.18.1.201" ] && break; sleep 30; done
```

Ожидается, что цикл завершится со значением `198.18.1.201`.

- [ ] **Шаг 4: убедиться, что железки пришли**

Список источников подключений читается из сетевого стека контейнера. Ждать
стоит несколько минут: клиенты переподключаются по своему таймауту, а не
мгновенно.

```bash
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home exec deploy/mosquitto -- netstat -tn | grep -E ":1883|:1888"'
```

Ожидаются подключения с `198.18.1.101` (spruthub, порт 1888) и с `.137`, `.33`,
`.81` (ESPresense, порт 1883) — адреса видны благодаря
`externalTrafficPolicy: Local`. Если вместо них видны адреса нод — политика не
применилась, проверить `kubectl -n home get svc mosquitto-lan -o yaml`.

Если `netstat` в образе нет:

```bash
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home exec deploy/mosquitto -- cat /proc/net/tcp'
```

и разобрать адреса вручную (hex, little-endian).

- [ ] **Шаг 5: espresense снова публикует**

```bash
kubectl -n home exec deploy/mosquitto -- mosquitto_sub -h 127.0.0.1 -p 1883 -t "espresense/#" -C 3 -W 60 -v
```

Ожидаются три строки с топиками `espresense/...` в течение минуты.

- [ ] **Шаг 6: spruthub этих топиков не видит**

Та же подписка, но через 1888 — на живом трафике, а не на подсунутом
сообщении.

```bash
kubectl -n home exec deploy/mosquitto -- sh -c 'mosquitto_sub -h 127.0.0.1 -p 1888 -t "espresense/#" -C 1 -W 30 -v; echo "rc=$?"'
```

Ожидается пусто и `rc=27`, притом что шаг 5 только что дал три сообщения.

**ЧЕКПОЙНТ:** железки на новом брокере, ACL подтверждён на живом трафике.

---

### Task 6: перевести поды кластера на ClusterIP

Пять сервисов smarthome ходят на `mqtt.beerloga.su`, то есть после Task 5 — на
VIP собственного кластера. Работать это, скорее всего, будет, но путь
бессмысленно длинный и уже подводил в связке Grafana↔Traefik. Внутри кластера
правильный адрес — `mosquitto.home`.

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/smarthome/presence.yaml:31`
- Modify: `ops/nanopi-r5c-k3s/apps/smarthome/power.yaml:31`
- Modify: `ops/nanopi-r5c-k3s/apps/smarthome/humidity.yaml:38` (и комментарий в строке 8)
- Modify: `ops/nanopi-r5c-k3s/apps/smarthome/conditioner.yaml:31`
- Modify: `ops/nanopi-r5c-k3s/apps/smarthome/samsung-tv.yaml:44`
- Modify: `ops/nanopi-r5c-k3s/apps/home/zigbee2mqtt.yaml:17` (только комментарий)
- Modify (на NFS): `198.18.1.125:/mnt/HD/HD_a2/k8s/zigbee2mqtt-data/configuration.yaml`

**Interfaces:**
- Consumes: `Service mosquitto.home:1883` из Task 1.

- [ ] **Шаг 1: заменить адрес в пяти манифестах**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/smarthome
grep -rln 'mqtt.beerloga.su' . | xargs sed -i '' 's/^\( *- \)mqtt\.beerloga\.su$/\1mosquitto.home/'
grep -rn 'mqtt' *.yaml
```

Ожидается: во всех пяти файлах после `- --mqtt` идёт `- mosquitto.home`.
Строк с `mqtt.beerloga.su` не остаётся, кроме комментария в `humidity.yaml`.

- [ ] **Шаг 2: поправить комментарий в `humidity.yaml`**

Строка 8 сейчас утверждает, что `mqtt.beerloga.su` резолвится в `198.18.1.102`.
Заменить абзац на:

```yaml
# vm.beerloga.su резолвится с нод в 198.18.1.102 — метрики пока там. Брокер
# переехал в кластер, поэтому MQTT адресуется по внутреннему имени
# mosquitto.home: путь через LAN-VIP собственного кластера длиннее и уже
# подводил в связке Grafana↔Traefik.
```

(если к моменту исполнения VictoriaMetrics уже адресуется иначе — привести
комментарий к фактическому состоянию, но не менять аргументы контейнера.)

- [ ] **Шаг 3: применить**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
tar cf - -C ops/nanopi-r5c-k3s/apps smarthome | ssh mmv@198.18.1.51 'tar xf - -C /tmp'
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl apply -f /tmp/smarthome/'
```

- [ ] **Шаг 4: дождаться перезапуска всех пяти**

```bash
ssh mmv@198.18.1.51 'export KUBECONFIG=/etc/rancher/k3s/k3s.yaml; for d in presence power humidity conditioner samsung-tv; do sudo -E kubectl -n smarthome rollout status deploy/$d --timeout=120s; done'
```

- [ ] **Шаг 5: переключить z2m**

Адрес брокера у z2m лежит не в манифесте, а в `configuration.yaml` внутри его
NFS-тома — это единственный источник правды по договорённости из его миграции.

```bash
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home exec deploy/zigbee2mqtt -- grep -A3 "^mqtt:" /app/data/configuration.yaml'
```

Ожидается `server: mqtt://198.18.1.102:1883`. Заменить на
`mqtt://mosquitto.home:1883` правкой файла на NAS (том смонтирован как
`198.18.1.125:/mnt/HD/HD_a2/k8s/zigbee2mqtt-data`), затем:

```bash
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home rollout restart deploy/zigbee2mqtt && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home rollout status deploy/zigbee2mqtt --timeout=180s'
```

- [ ] **Шаг 6: поправить комментарий в `zigbee2mqtt.yaml`**

Строка 17 называет брокером `mqtt://198.18.1.102:1883, still on the gateway
node`. Заменить на `mqtt://mosquitto.home:1883`, убрав «still on the gateway
node».

- [ ] **Шаг 7: проверить, что все шестеро подключены**

```bash
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home exec deploy/mosquitto -- netstat -tn | grep :1883 | wc -l'
```

Ожидается не меньше девяти подключений: шесть подов + три ESPresense.

```bash
kubectl -n home exec deploy/mosquitto -- mosquitto_sub -h 127.0.0.1 -p 1883 -t "zigbee2mqtt/#" -C 5 -W 120 -v
```

Ожидаются пять сообщений от z2m — значит он публикует уже в новый брокер.

- [ ] **Шаг 8: коммит** (по команде владельца)

```bash
git add ops/nanopi-r5c-k3s/apps/smarthome ops/nanopi-r5c-k3s/apps/home/zigbee2mqtt.yaml
git commit -m "ops(k3s): point cluster pods at the in-cluster MQTT broker"
```

---

### Task 7: сходимость и остатки

**Files:** нет

- [ ] **Шаг 1: логи брокера чистые**

```bash
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home logs deploy/mosquitto --tail=50'
```

Конфиг оставляет только `error` и `warning`, поэтому в норме тут почти пусто.
Строки `Unable to drop privileges` быть не должно — директива `user` убрана.

- [ ] **Шаг 2: под не упирается в лимит памяти**

```bash
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home top pod -l app=mosquitto'
```

Ожидается заметно меньше 128Mi. Если близко к лимиту — поднять лимит в
манифесте, а не оставлять под под OOM.

- [ ] **Шаг 3: БД пишется**

Через час после переезда (`autosave_interval 1800`) файл должен обновиться:

```bash
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home exec deploy/mosquitto -- ls -l /mosquitto/data/'
```

Ожидается свежая mtime и ненулевой размер.

- [ ] **Шаг 4: переживает перезапуск пода**

```bash
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home rollout restart deploy/mosquitto && sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home rollout status deploy/mosquitto --timeout=120s'
ssh mmv@198.18.1.102 'docker run --rm --network host eclipse-mosquitto:2.1.2-alpine mosquitto_sub -h 198.18.1.102 -p 1883 -t "zigbee2mqtt/bridge/state" -C 1 -W 15'
```

Ожидается `{"state":"online"}` — брокер поднялся, retained на месте, и socat
пережил разрыв к поду (`Restart=always` + новый TCP на каждое подключение).

- [ ] **Шаг 5: waterius — ждать**

Проверить наличие его топика можно только после того, как счётчик проснётся.
Топик уточнить у владельца или найти по спискам:

```bash
kubectl -n home exec deploy/mosquitto -- mosquitto_sub -h 127.0.0.1 -p 1883 -t "#" -W 20 -v | cut -d/ -f1 | sort -u
```

Ожидается список корневых топиков; в нём должен со временем появиться
waterius. **До этого миграция не завершена.** Если через сутки показаний воды
нет — путь через socat не работает, откатывать (см. ниже) и разбираться.

- [ ] **Шаг 6: обновить README `apps/`** — добавить строку про `home/mosquitto.yaml`:
  два листенера, VIP `198.18.1.201`, socat на `.102` ради waterius.

- [ ] **Шаг 7: коммит** (по команде владельца)

```bash
git add ops/nanopi-r5c-k3s/apps/README.md docs/superpowers
git commit -m "docs(k3s): describe the MQTT broker layout after the migration"
```

---

## Откат

Полный, на любом шаге после Task 3:

```bash
# 1. вернуть DNS: mqtt.beerloga.su -> 198.18.1.102 (Keenetic)
# 2. погасить брокер в кластере и проброс
ssh mmv@198.18.1.51 'sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n home scale deploy/mosquitto --replicas=0'
ssh mmv@198.18.1.102 'sudo systemctl disable --now mqtt-forward@1883 mqtt-forward@1888'
# 3. поднять докер обратно
ssh mmv@198.18.1.102 'docker update --restart=unless-stopped mosquitto && docker start mosquitto'
```

`/opt/mosquitto` не удаляется. Ценой отката будут сообщения, накопленные в
кластерной БД после переезда: `/opt/mosquitto/data/mosquitto.db` остаётся в
том состоянии, в котором докер его оставил.

Поды кластера после отката указывают на `mosquitto.home`, которого нет —
вернуть им `mqtt.beerloga.su` (`git revert` коммита из Task 6) и восстановить
`configuration.yaml` z2m.

## Что осталось за рамками

- Остальные сервисы на `.102` (outline-обвязка, emby, экспортёры).
- Аутентификация в брокере — как была анонимной, так и остаётся.
- Бэкап `mosquitto.db`: файл восстановим из живого состояния устройств, ночной
  CronJob под него не заводится.
- Развязка `.102` из цепочки: пока waterius жив и не перенастраиваем, узел
  остаётся в пути.
