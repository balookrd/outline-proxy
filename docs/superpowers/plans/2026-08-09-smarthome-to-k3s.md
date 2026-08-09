# Миграция smarthome в k3s: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Перенести пять самописных сервисов умного дома с docker на
`198.18.1.102` в k3s, заведя для этого реестр образов и пересобрав их под arm64.

**Architecture:** Реестр `registry:2` за Traefik с общим wildcard-сертификатом
(containerd доверяет ему без правки `registries.yaml`), данные реестра и
`conf`-каталоги сервисов — на NFS, поэтому PVC не нужны и поды не привязаны к
нодам. Сборка на маке (arm64 нативно), тег по git-sha. Сервисы никого не
слушают: только исходящие MQTT и VictoriaMetrics, оба остаются на `.102`.

**Tech Stack:** k3s v1.36.2 (aarch64), registry:2, Traefik v3.7 basic-auth
middleware, Docker + buildx на маке (arm64), Python 3.14 сервисы.

Спека: [`docs/superpowers/specs/2026-08-09-smarthome-to-k3s-design.md`](../specs/2026-08-09-smarthome-to-k3s-design.md).

## Global Constraints

- Репозиторий кода: `~/Yandex.Disk.localized/IdeaProjects/smarthome` (отдельный
  git, без remote). Манифесты кластера — в `outline-proxy`, каталог
  `ops/nanopi-r5c-k3s/apps/smarthome/`.
- Namespace `smarthome` для сервисов, `registry` для реестра.
- Реестр: `registry.k3s.beerloga.su`, данные —
  `198.18.1.125:/mnt/HD/HD_a2/k8s/registry`. В корне экспорта уже лежат
  `grafana/` и `zigbee2mqtt/` — не трогать.
- `conf` сервисов — `198.18.1.125:/mnt/HD/HD_a2/k8s/smarthome/<name>`, inline
  `nfs`-volume, **без PVC**.
- Тег образов — короткий git-sha репозитория smarthome. `latest` запрещён.
  `imagePullPolicy: IfNotPresent`.
- **Аргументы сервисов не одинаковы** (проверено `docker inspect` на живых
  контейнерах):
  - `presence`, `conditioner`, `samsung_tv`: `--path /app/conf --mqtt mqtt.beerloga.su`
  - `power`, `humidity`: то же + `--victoria vm.beerloga.su`
- Все поды: `runAsUser: 1000`, `TZ=Europe/Moscow`,
  `imagePullSecrets: [registry-creds]`, одна реплика, `Recreate`.
- `samsung_tv` дополнительно: `hostNetwork: true`,
  `dnsPolicy: ClusterFirstWithHostNet`. `/run/udev` не монтируется никому.
- `mqtt.beerloga.su` и `vm.beerloga.su` резолвятся с нод в `198.18.1.102` —
  адреса не менять.
- Управление кластером с мака: `export KUBECONFIG=~/.kube/k3s-home.yaml`.
- Узел-источник: `ssh mmv@198.18.1.102`, `sudo -n`, docker через sudo.
- `/opt/smarthome` на `.102` **не удалять** — путь отката.
- Git: коммиты на английском, без Co-Authored-By и Claude-атрибуции, работа в
  `main` обоих репозиториев. `git commit` — только по явной команде владельца.

---

### Task 1: Синхронизировать репозиторий smarthome с продом

Перед сборкой репозиторий должен содержать ровно тот код, что работает на `.102`.
Иначе соберём `presence` без трекера `maksin_keys` и молча сломаем метки.

**Files:**
- Modify: `~/Yandex.Disk.localized/IdeaProjects/smarthome/services/presence/presence.py`
- Add: `~/Yandex.Disk.localized/IdeaProjects/smarthome/services/samsung_tv/wol.py` (untracked)

**Interfaces:**
- Produces: git-sha, который Задача 4 использует как тег образов.

- [ ] **Step 1: Забрать presence.py с узла**

```bash
SH=~/Yandex.Disk.localized/IdeaProjects/smarthome
ssh mmv@198.18.1.102 'sudo -n cat /opt/smarthome/services/presence/presence.py' > "$SH/services/presence/presence.py"
cd "$SH" && git diff --stat services/presence/presence.py
```

Ожидаемо: изменённый файл, около шести строк различий.

- [ ] **Step 2: Просмотреть diff перед коммитом**

```bash
cd ~/Yandex.Disk.localized/IdeaProjects/smarthome
git diff services/presence/presence.py
```

Ожидаемо: добавлен трекер `maksin_keys`, переименования
`alisa_key → alisa_keys` и `maksim_samsung → maksim_ibeacon`. Ничего другого
быть не должно — если в diff есть иные правки, остановиться и разобраться.

- [ ] **Step 3: Проверить, что остальные файлы совпадают**

```bash
SH=~/Yandex.Disk.localized/IdeaProjects/smarthome
for s in power humidity conditioner samsung_tv; do
  for f in $(cd "$SH/services/$s" && ls *.py); do
    l=$(md5 -q "$SH/services/$s/$f")
    r=$(ssh mmv@198.18.1.102 "md5sum /opt/smarthome/services/$s/$f | cut -d' ' -f1")
    [ "$l" = "$r" ] && echo "  $s/$f ok" || echo "  $s/$f РАЗЛИЧАЕТСЯ"
  done
done
```

Ожидаемо: все `ok`. Расхождение здесь означает, что на узле правили ещё
что-то, — забрать так же, как `presence.py`.

- [ ] **Step 4: Commit**

```bash
cd ~/Yandex.Disk.localized/IdeaProjects/smarthome
git add services/presence/presence.py services/samsung_tv/wol.py
git commit -m "fix(presence): restore the tracker set running in production

The node has been ahead of the repository since 27 July: it tracks maksin_keys
and renames alisa_key/maksim_samsung. Building from the repository as it stood
would have dropped those labels without any error."
git rev-parse --short HEAD
```

Записать полученный sha — он станет тегом образов в Задаче 4.

---

### Task 2: Манифесты реестра

**Files:**
- Create: `ops/nanopi-r5c-k3s/apps/registry/registry.yaml`
- Create: `ops/nanopi-r5c-k3s/apps/registry/README.md`

**Interfaces:**
- Produces: Deployment/Service/Ingress `registry` в ns `registry`, Traefik
  middleware `registry-auth`. Задача 3 их применяет, Задача 4 пушит образы.

- [ ] **Step 1: Создать registry.yaml**

Полное содержимое `ops/nanopi-r5c-k3s/apps/registry/registry.yaml`:

```yaml
# Private image registry for the cluster.
#
# Behind Traefik on purpose: it gets the wildcard *.k3s.beerloga.su certificate
# from the default TLSStore, and containerd trusts an ordinary Let's Encrypt
# certificate — so registries.yaml on the nodes stays untouched. A plain HTTP
# registry would mean editing insecure-registries on all three nodes instead.
#
# Storage is NFS rather than local-path: a registry is blobs on a filesystem,
# with no database and no locking, so a network filesystem is safe here (unlike
# Grafana's and z2m's SQLite). The payoff is that the pod survives losing a node
# and does not depend on which node comes back first after a cluster restart.
apiVersion: v1
kind: Namespace
metadata:
  name: registry
---
# Basic auth: without it anyone on the LAN can push into the registry the
# cluster runs its code from. The Secret holds an htpasswd line and is created
# out of band — see README.md.
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: registry-auth
  namespace: registry
spec:
  basicAuth:
    secret: registry-auth
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: registry
  namespace: registry
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels: { app: registry }
  template:
    metadata:
      labels: { app: registry }
    spec:
      containers:
        - name: registry
          image: registry:2.8.3
          ports:
            - { containerPort: 5000, name: http }
          env:
            - { name: REGISTRY_STORAGE_DELETE_ENABLED, value: "true" }
          volumeMounts:
            - { name: data, mountPath: /var/lib/registry }
          readinessProbe:
            httpGet: { path: /v2/, port: 5000 }
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests: { cpu: 20m, memory: 64Mi }
            limits:   { memory: 256Mi }
      volumes:
        - name: data
          nfs:
            server: 198.18.1.125
            path: /mnt/HD/HD_a2/k8s/registry
---
apiVersion: v1
kind: Service
metadata:
  name: registry
  namespace: registry
spec:
  selector: { app: registry }
  ports:
    - { port: 5000, targetPort: 5000 }
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: registry
  namespace: registry
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: "true"
    traefik.ingress.kubernetes.io/router.middlewares: registry-registry-auth@kubernetescrd
spec:
  ingressClassName: traefik
  rules:
    - host: registry.k3s.beerloga.su
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: registry
                port:
                  number: 5000
```

- [ ] **Step 2: Создать README реестра**

Полное содержимое `ops/nanopi-r5c-k3s/apps/registry/README.md`:

```markdown
# Приватный реестр образов

`registry.k3s.beerloga.su` — реестр для самописных сервисов (`smarthome`).
Живёт за Traefik и получает общий wildcard-сертификат из `TLSStore default`,
поэтому containerd на нодах доверяет ему как обычному сайту: править
`registries.yaml` не нужно.

Данные — NFS на NAS (`198.18.1.125:/mnt/HD/HD_a2/k8s/registry`). Не local-path:
у реестра нет БД и блокировок, только блобы, поэтому сетевая ФС безопасна, а
взамен под переживает потерю ноды.

## Секреты (вне git, до раскатки)

Один пароль используется дважды: для basic-auth на входе и для `imagePullSecret`,
которым поды тянут образы.

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
REG_USER=smarthome
REG_PASS='<придумать пароль>'

# 1. htpasswd для Traefik
kubectl -n registry create secret generic registry-auth \
  --from-literal=users="$(htpasswd -nbB "$REG_USER" "$REG_PASS")"

# 2. imagePullSecret для подов (в namespace, где они запускаются)
kubectl -n smarthome create secret docker-registry registry-creds \
  --docker-server=registry.k3s.beerloga.su \
  --docker-username="$REG_USER" --docker-password="$REG_PASS"

# 3. логин с мака для push
docker login registry.k3s.beerloga.su -u "$REG_USER"
```

`htpasswd` на macOS лежит в `/usr/sbin/htpasswd` и в PATH обычно есть.

## Проверка

```bash
curl -su "$REG_USER:$REG_PASS" https://registry.k3s.beerloga.su/v2/_catalog
curl -so /dev/null -w '%{http_code}\n' https://registry.k3s.beerloga.su/v2/   # 401 без пароля
```

Первый ответ — JSON со списком репозиториев, второй — `401`: значит
basic-auth действительно включён.
```

- [ ] **Step 3: Проверить синтаксис**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/registry
ruby -ryaml -e 'YAML.load_stream(File.read("registry.yaml")); puts "yaml ok"'
```

Ожидаемо: `yaml ok`.

- [ ] **Step 4: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/registry/
git commit -m "ops(k3s): private image registry behind Traefik"
```

---

### Task 3: Поднять реестр и проверить push/pull

**Files:** изменений в git нет.

**Interfaces:**
- Consumes: манифесты из Задачи 2.
- Produces: работающий реестр и Secret `registry-auth`; Задача 4 в него пушит.

- [ ] **Step 1: Создать каталог на NAS**

Экспорт монтируется целиком, поэтому каталог создаётся временным подом:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n default run nas-mkdir --rm -i --restart=Never --image=alpine:3.20 \
  --overrides='{"spec":{"containers":[{"name":"nas-mkdir","image":"alpine:3.20","command":["sh","-c","mkdir -p /nas/registry /nas/smarthome && chmod 777 /nas/registry /nas/smarthome && ls -la /nas"],"volumeMounts":[{"name":"nas","mountPath":"/nas"}]}],"volumes":[{"name":"nas","nfs":{"server":"198.18.1.125","path":"/mnt/HD/HD_a2/k8s"}}]}}'
```

Ожидаемо: листинг с каталогами `registry`, `smarthome`, а также уже
существующими `grafana` и `zigbee2mqtt`.

- [ ] **Step 2: Применить манифесты и создать секреты**

Пароль придумать один раз и сохранить в менеджере паролей — он нужен и для
push, и для pull:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/registry
kubectl apply -f registry.yaml
kubectl create namespace smarthome

REG_USER=smarthome
read -rs REG_PASS   # ввести пароль, он не попадёт в историю shell

kubectl -n registry create secret generic registry-auth \
  --from-literal=users="$(htpasswd -nbB "$REG_USER" "$REG_PASS")"
kubectl -n smarthome create secret docker-registry registry-creds \
  --docker-server=registry.k3s.beerloga.su \
  --docker-username="$REG_USER" --docker-password="$REG_PASS"

kubectl -n registry rollout status deploy/registry --timeout=300s
```

Ожидаемо: `deployment "registry" successfully rolled out`.

- [ ] **Step 3: Проверить, что basic-auth работает**

```bash
curl -so /dev/null -w 'без пароля: %{http_code}\n' https://registry.k3s.beerloga.su/v2/
curl -su "$REG_USER:$REG_PASS" -w '\nс паролем: %{http_code}\n' https://registry.k3s.beerloga.su/v2/_catalog
```

Ожидаемо: `401` без пароля и `200` с паролем плюс `{"repositories":[]}`.
Если без пароля приходит `200` — middleware не подключилась; проверить
аннотацию `router.middlewares` (формат `<namespace>-<name>@kubernetescrd`).

- [ ] **Step 4: Проверить push/pull сквозняком**

```bash
docker login registry.k3s.beerloga.su -u "$REG_USER"
docker pull alpine:3.20
docker tag alpine:3.20 registry.k3s.beerloga.su/probe:1
docker push registry.k3s.beerloga.su/probe:1
curl -su "$REG_USER:$REG_PASS" https://registry.k3s.beerloga.su/v2/_catalog
```

Ожидаемо: push проходит, каталог содержит `probe`.

Затем — что кластер умеет тянуть из реестра с секретом:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome run pull-probe --restart=Never --image=registry.k3s.beerloga.su/probe:1 \
  --overrides='{"spec":{"imagePullSecrets":[{"name":"registry-creds"}],"containers":[{"name":"pull-probe","image":"registry.k3s.beerloga.su/probe:1","command":["sh","-c","echo pull ok"]}]}}'
kubectl -n smarthome wait --for=jsonpath='{.status.phase}'=Succeeded pod/pull-probe --timeout=180s
kubectl -n smarthome logs pull-probe
kubectl -n smarthome delete pod pull-probe
```

Ожидаемо: `pull ok`. `ImagePullBackOff` означает, что `registry-creds` не создан
или пароль не совпадает с htpasswd.

- [ ] **Step 5: Убрать пробный образ**

```bash
docker rmi registry.k3s.beerloga.su/probe:1 alpine:3.20 2>/dev/null || true
```

Блоб останется в реестре — это безвредно; чистка реестра в этот план не входит.

Коммита нет.

---

### Task 4: Скрипт сборки и первая публикация образов

**Files:**
- Create: `~/Yandex.Disk.localized/IdeaProjects/smarthome/build-and-push.sh`

**Interfaces:**
- Consumes: git-sha из Задачи 1, работающий реестр из Задачи 3.
- Produces: пять образов `registry.k3s.beerloga.su/<name>:<sha>` — их
  используют манифесты Задачи 5.

- [ ] **Step 1: Написать скрипт**

Полное содержимое `~/Yandex.Disk.localized/IdeaProjects/smarthome/build-and-push.sh`:

```bash
#!/usr/bin/env bash
#
# build-and-push.sh — собрать образы сервисов и отправить их в кластерный реестр.
#
# Запускается с мака: он arm64, как и ноды k3s, поэтому сборка нативная и
# эмуляция не нужна. Тег — короткий git-sha: с плавающим latest непонятно, что
# именно раскатано, и некуда откатываться.
#
#   ./build-and-push.sh              # все сервисы
#   ./build-and-push.sh humidity     # только указанные
set -euo pipefail
cd "$(dirname "$0")"

REGISTRY=${REGISTRY:-registry.k3s.beerloga.su}
ALL="presence power humidity conditioner samsung_tv"

services=("$@")
[ ${#services[@]} -eq 0 ] && read -ra services <<< "$ALL"

# Собирать из грязного дерева — значит получить образ, которого нет ни в одном
# коммите, и потом гадать, что в нём.
if [ -n "$(git status --porcelain -- services libs)" ]; then
	echo "рабочее дерево грязное (services/ или libs/) — закоммить или спрячь изменения" >&2
	git status --short -- services libs >&2
	exit 1
fi

TAG="$(git rev-parse --short HEAD)"
echo "==> тег: $TAG"

for s in "${services[@]}"; do
	[ -f "services/$s/Dockerfile" ] || { echo "нет services/$s/Dockerfile" >&2; exit 1; }
	echo "==> $s"
	docker build -f "services/$s/Dockerfile" -t "$REGISTRY/$s:$TAG" .
	docker push "$REGISTRY/$s:$TAG"
done

echo
echo "==> готово. Тег $TAG. Прописать в манифестах:"
for s in "${services[@]}"; do
	echo "      image: $REGISTRY/$s:$TAG"
done
```

- [ ] **Step 2: Проверить синтаксис и защиту от грязного дерева**

```bash
cd ~/Yandex.Disk.localized/IdeaProjects/smarthome
chmod +x build-and-push.sh
bash -n build-and-push.sh && echo "bash ok"
```

Ожидаемо: `bash ok`. Если в `services/` есть незакоммиченные правки
(`.sh`-скрипты из Задачи 1 остались изменёнными), скрипт откажется работать —
это и есть задуманное поведение; спрятать их `git stash` либо закоммитить.

- [ ] **Step 3: Собрать и опубликовать все пять образов**

```bash
cd ~/Yandex.Disk.localized/IdeaProjects/smarthome
./build-and-push.sh
```

Ожидаемо: пять успешных сборок и push'ей, в конце — список строк `image:` с
тегом. Записать тег: он идёт в манифесты Задачи 5.

- [ ] **Step 4: Проверить, что образы в реестре и они arm64**

```bash
curl -su "smarthome:$REG_PASS" https://registry.k3s.beerloga.su/v2/_catalog
docker manifest inspect registry.k3s.beerloga.su/humidity:$(cd ~/Yandex.Disk.localized/IdeaProjects/smarthome && git rev-parse --short HEAD) | grep -A2 platform
```

Ожидаемо: в каталоге пять репозиториев, в манифесте — `"architecture": "arm64"`.
`amd64` означает, что сборка шла не на маке или с явным `--platform`.

- [ ] **Step 5: Commit**

```bash
cd ~/Yandex.Disk.localized/IdeaProjects/smarthome
git add build-and-push.sh
git commit -m "build: add a script that builds and pushes service images

Tags by short git sha rather than latest, and refuses to build from a dirty
tree — otherwise the image contains code that exists in no commit."
```

---

### Task 5: Манифесты сервисов

**Files:**
- Create: `ops/nanopi-r5c-k3s/apps/smarthome/humidity.yaml`
- Create: `ops/nanopi-r5c-k3s/apps/smarthome/power.yaml`
- Create: `ops/nanopi-r5c-k3s/apps/smarthome/conditioner.yaml`
- Create: `ops/nanopi-r5c-k3s/apps/smarthome/presence.yaml`
- Create: `ops/nanopi-r5c-k3s/apps/smarthome/samsung-tv.yaml`

**Interfaces:**
- Consumes: тег образов из Задачи 4, Secret `registry-creds` из Задачи 3.
- Produces: пять Deployment в ns `smarthome`; Задачи 6–8 их поднимают.

Ниже `<TAG>` — короткий git-sha из Задачи 4; подставить фактическое значение.

- [ ] **Step 1: Создать humidity.yaml**

Полное содержимое `ops/nanopi-r5c-k3s/apps/smarthome/humidity.yaml`:

```yaml
# humidity — телеметрия влажности: читает MQTT, пишет в VictoriaMetrics.
#
# Никаких портов: сервис только исходящий, поэтому ни Service, ни Ingress.
# conf лежит на NFS, а не в PVC: devices.json — состояние, которое сервис
# переписывает атомарно (.new -> rename -> .old), блокировок нет, писатель один,
# так что сетевая ФС безопасна и пода не привязывает к ноде.
#
# mqtt.beerloga.su и vm.beerloga.su резолвятся с нод в 198.18.1.102 — брокер и
# VictoriaMetrics остались на шлюзовом узле.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: humidity
  namespace: smarthome
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels: { app: humidity }
  template:
    metadata:
      labels: { app: humidity }
    spec:
      securityContext:
        runAsUser: 1000
        runAsGroup: 1000
      imagePullSecrets:
        - name: registry-creds
      containers:
        - name: humidity
          image: registry.k3s.beerloga.su/humidity:<TAG>
          imagePullPolicy: IfNotPresent
          args:
            - --path
            - /app/conf
            - --mqtt
            - mqtt.beerloga.su
            - --victoria
            - vm.beerloga.su
          env:
            - { name: TZ, value: Europe/Moscow }
          volumeMounts:
            - { name: conf, mountPath: /app/conf }
          resources:
            requests: { cpu: 20m, memory: 64Mi }
            limits:   { memory: 192Mi }
      volumes:
        - name: conf
          nfs:
            server: 198.18.1.125
            path: /mnt/HD/HD_a2/k8s/smarthome/humidity
```

- [ ] **Step 2: Создать power.yaml**

То же самое с заменой имени; `power` тоже пишет в VictoriaMetrics.

Полное содержимое `ops/nanopi-r5c-k3s/apps/smarthome/power.yaml`:

```yaml
# power — учёт потребления: читает MQTT, пишет в VictoriaMetrics.
# Устройство то же, что у humidity: без портов, conf на NFS.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: power
  namespace: smarthome
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels: { app: power }
  template:
    metadata:
      labels: { app: power }
    spec:
      securityContext:
        runAsUser: 1000
        runAsGroup: 1000
      imagePullSecrets:
        - name: registry-creds
      containers:
        - name: power
          image: registry.k3s.beerloga.su/power:<TAG>
          imagePullPolicy: IfNotPresent
          args:
            - --path
            - /app/conf
            - --mqtt
            - mqtt.beerloga.su
            - --victoria
            - vm.beerloga.su
          env:
            - { name: TZ, value: Europe/Moscow }
          volumeMounts:
            - { name: conf, mountPath: /app/conf }
          resources:
            requests: { cpu: 20m, memory: 64Mi }
            limits:   { memory: 192Mi }
      volumes:
        - name: conf
          nfs:
            server: 198.18.1.125
            path: /mnt/HD/HD_a2/k8s/smarthome/power
```

- [ ] **Step 3: Создать conditioner.yaml**

У `conditioner` **нет** `--victoria` — только MQTT.

Полное содержимое `ops/nanopi-r5c-k3s/apps/smarthome/conditioner.yaml`:

```yaml
# conditioner — управление кондиционером через MQTT.
# В VictoriaMetrics не пишет, поэтому аргумента --victoria здесь нет.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: conditioner
  namespace: smarthome
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels: { app: conditioner }
  template:
    metadata:
      labels: { app: conditioner }
    spec:
      securityContext:
        runAsUser: 1000
        runAsGroup: 1000
      imagePullSecrets:
        - name: registry-creds
      containers:
        - name: conditioner
          image: registry.k3s.beerloga.su/conditioner:<TAG>
          imagePullPolicy: IfNotPresent
          args:
            - --path
            - /app/conf
            - --mqtt
            - mqtt.beerloga.su
          env:
            - { name: TZ, value: Europe/Moscow }
          volumeMounts:
            - { name: conf, mountPath: /app/conf }
          resources:
            requests: { cpu: 20m, memory: 64Mi }
            limits:   { memory: 192Mi }
      volumes:
        - name: conf
          nfs:
            server: 198.18.1.125
            path: /mnt/HD/HD_a2/k8s/smarthome/conditioner
```

- [ ] **Step 4: Создать presence.yaml**

У `presence` тоже нет `--victoria`.

Полное содержимое `ops/nanopi-r5c-k3s/apps/smarthome/presence.yaml`:

```yaml
# presence — присутствие по iBeacon/ESPresense, публикует в MQTT.
# В VictoriaMetrics не пишет, поэтому аргумента --victoria здесь нет.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: presence
  namespace: smarthome
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels: { app: presence }
  template:
    metadata:
      labels: { app: presence }
    spec:
      securityContext:
        runAsUser: 1000
        runAsGroup: 1000
      imagePullSecrets:
        - name: registry-creds
      containers:
        - name: presence
          image: registry.k3s.beerloga.su/presence:<TAG>
          imagePullPolicy: IfNotPresent
          args:
            - --path
            - /app/conf
            - --mqtt
            - mqtt.beerloga.su
          env:
            - { name: TZ, value: Europe/Moscow }
          volumeMounts:
            - { name: conf, mountPath: /app/conf }
          resources:
            requests: { cpu: 20m, memory: 64Mi }
            limits:   { memory: 192Mi }
      volumes:
        - name: conf
          nfs:
            server: 198.18.1.125
            path: /mnt/HD/HD_a2/k8s/smarthome/presence
```

- [ ] **Step 5: Создать samsung-tv.yaml**

Единственный из пяти, кому нужен `hostNetwork`.

Полное содержимое `ops/nanopi-r5c-k3s/apps/smarthome/samsung-tv.yaml`:

```yaml
# samsung_tv — управление телевизором, включая Wake-on-LAN.
#
# hostNetwork здесь не роскошь: WoL шлётся как sendto(('255.255.255.255', 9))
# с SO_BROADCAST, а из pod-сети 10.42.0.0/16 такой бродкаст в LAN не уйдёт.
# dnsPolicy обязателен вместе с hostNetwork — иначе под теряет кластерный DNS.
#
# /run/udev, который монтировал docker-скрипт, не переносится: в коде нет ни
# одного обращения к нему.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: samsung-tv
  namespace: smarthome
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels: { app: samsung-tv }
  template:
    metadata:
      labels: { app: samsung-tv }
    spec:
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      securityContext:
        runAsUser: 1000
        runAsGroup: 1000
      imagePullSecrets:
        - name: registry-creds
      containers:
        - name: samsung-tv
          image: registry.k3s.beerloga.su/samsung_tv:<TAG>
          imagePullPolicy: IfNotPresent
          args:
            - --path
            - /app/conf
            - --mqtt
            - mqtt.beerloga.su
          env:
            - { name: TZ, value: Europe/Moscow }
          volumeMounts:
            - { name: conf, mountPath: /app/conf }
          resources:
            requests: { cpu: 20m, memory: 64Mi }
            limits:   { memory: 192Mi }
      volumes:
        - name: conf
          nfs:
            server: 198.18.1.125
            path: /mnt/HD/HD_a2/k8s/smarthome/samsung_tv
```

- [ ] **Step 6: Проверить синтаксис и подстановку тега**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/smarthome
ruby -ryaml -e 'Dir["*.yaml"].each { |f| YAML.load_stream(File.read(f)) }; puts "yaml ok"'
grep -l "<TAG>" *.yaml && echo "ОСТАЛСЯ ПЛЕЙСХОЛДЕР — подставить тег" || echo "тег подставлен везде"
```

Ожидаемо: `yaml ok` и `тег подставлен везде`.

- [ ] **Step 7: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/smarthome/
git commit -m "ops(k3s): manifests for the smarthome services"
```

---

### Task 6: Переезд humidity (обкатка пайплайна)

Первый сервис едет отдельной задачей: на нём проверяется весь путь — pull из
реестра, NFS-том, подключение к брокеру и запись в VictoriaMetrics. Если что-то
не так, остальные четыре продолжают работать в docker.

**Files:** изменений в git нет.

- [ ] **Step 1: Зафиксировать эталон и остановить контейнер**

```bash
ssh mmv@198.18.1.102 'sudo -n md5sum /opt/smarthome/services/humidity/conf/devices.json; sudo -n docker update --restart=no humidity >/dev/null && sudo -n docker stop humidity >/dev/null && sudo -n docker inspect -f "{{.State.Status}} restart={{.HostConfig.RestartPolicy.Name}}" humidity'
```

Ожидаемо: md5 файла и `exited restart=no`.

- [ ] **Step 2: Скопировать conf на NAS**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
ssh mmv@198.18.1.102 'cd /opt/smarthome/services/humidity && sudo -n tar czf /tmp/humidity-conf.tar.gz -C conf . && sudo -n chown mmv:mmv /tmp/humidity-conf.tar.gz'
scp mmv@198.18.1.102:/tmp/humidity-conf.tar.gz /tmp/
kubectl -n default run nas-load --rm -i --restart=Never --image=alpine:3.20 \
  --overrides='{"spec":{"containers":[{"name":"nas-load","image":"alpine:3.20","command":["sh","-c","mkdir -p /nas/smarthome/humidity && cat > /tmp/c.tgz && tar xzf /tmp/c.tgz -C /nas/smarthome/humidity && chown -R 1000:1000 /nas/smarthome/humidity && ls -l /nas/smarthome/humidity"],"stdin":true,"volumeMounts":[{"name":"nas","mountPath":"/nas"}]}],"volumes":[{"name":"nas","nfs":{"server":"198.18.1.125","path":"/mnt/HD/HD_a2/k8s"}}]}}' < /tmp/humidity-conf.tar.gz
rm -f /tmp/humidity-conf.tar.gz
ssh mmv@198.18.1.102 'rm -f /tmp/humidity-conf.tar.gz'
```

Ожидаемо: листинг с `devices.json` и `devices.json.old`, владелец `1000:1000`.

Если `chown` не сработал (NAS сквошит владельца) — проверить, что каталог
доступен на запись: `chmod 777 /nas/smarthome/humidity`. Сервис пишет под uid
1000, и без права записи он упадёт при первом сохранении состояния.

- [ ] **Step 3: Поднять под**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/smarthome
kubectl apply -f humidity.yaml
kubectl -n smarthome rollout status deploy/humidity --timeout=300s
kubectl -n smarthome get pods -l app=humidity
```

Ожидаемо: `successfully rolled out`, под `1/1 Running`.
`ImagePullBackOff` — не создан `registry-creds` либо тег в манифесте не
совпадает с тем, что в реестре.

- [ ] **Step 4: Проверить логи и запись состояния**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome logs deploy/humidity --tail=20
kubectl -n smarthome exec deploy/humidity -- ls -l /app/conf
```

Ожидаемо: в логе нет трассировок и отказов подключения; в `/app/conf` —
`devices.json`, доступный на запись.

- [ ] **Step 5: Проверить, что метрики доехали до VictoriaMetrics**

```bash
ssh mmv@198.18.1.102 "curl -sG 'http://127.0.0.1:8428/api/v1/query' --data-urlencode 'query=count({__name__=~\"humidity.*\"})'" | python3 -m json.tool | head -12
```

Ожидаемо: непустой `result`. Пусто — сервис не пишет; смотреть логи пода и
проверять, что `vm.beerloga.su` резолвится изнутри пода
(`kubectl -n smarthome exec deploy/humidity -- getent hosts vm.beerloga.su`).

- [ ] **Step 6: Откат, если не поехало**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome scale deploy/humidity --replicas=0
ssh mmv@198.18.1.102 'sudo -n docker update --restart=unless-stopped humidity && sudo -n docker start humidity'
```

Коммита нет.

---

### Task 7: Переезд power, conditioner, presence

Пайплайн уже проверен на `humidity`, поэтому три сервиса едут одной задачей —
но по очереди, с проверкой каждого перед следующим.

**Files:** изменений в git нет.

- [ ] **Step 1: Перенести power**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
s=power
ssh mmv@198.18.1.102 "sudo -n md5sum /opt/smarthome/services/$s/conf/devices.json; sudo -n docker update --restart=no $s >/dev/null && sudo -n docker stop $s >/dev/null"
ssh mmv@198.18.1.102 "cd /opt/smarthome/services/$s && sudo -n tar czf /tmp/$s-conf.tar.gz -C conf . && sudo -n chown mmv:mmv /tmp/$s-conf.tar.gz"
scp mmv@198.18.1.102:/tmp/$s-conf.tar.gz /tmp/
kubectl -n default run nas-load-$s --rm -i --restart=Never --image=alpine:3.20 \
  --overrides="{\"spec\":{\"containers\":[{\"name\":\"nas-load\",\"image\":\"alpine:3.20\",\"command\":[\"sh\",\"-c\",\"mkdir -p /nas/smarthome/$s && cat > /tmp/c.tgz && tar xzf /tmp/c.tgz -C /nas/smarthome/$s && chown -R 1000:1000 /nas/smarthome/$s && ls -l /nas/smarthome/$s\"],\"stdin\":true,\"volumeMounts\":[{\"name\":\"nas\",\"mountPath\":\"/nas\"}]}],\"volumes\":[{\"name\":\"nas\",\"nfs\":{\"server\":\"198.18.1.125\",\"path\":\"/mnt/HD/HD_a2/k8s\"}}]}}" < /tmp/$s-conf.tar.gz
rm -f /tmp/$s-conf.tar.gz; ssh mmv@198.18.1.102 "rm -f /tmp/$s-conf.tar.gz"
kubectl apply -f /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/smarthome/$s.yaml
kubectl -n smarthome rollout status deploy/$s --timeout=300s
```

Ожидаемо: под поднялся.

- [ ] **Step 2: Проверить power**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome logs deploy/power --tail=15
ssh mmv@198.18.1.102 "curl -sG 'http://127.0.0.1:8428/api/v1/query' --data-urlencode 'query=count({__name__=~\"power.*\"})'" | python3 -m json.tool | head -12
```

Ожидаемо: логи без ошибок, непустой `result` в VictoriaMetrics.

- [ ] **Step 3: Перенести conditioner**

Те же команды с `s=conditioner`:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
s=conditioner
ssh mmv@198.18.1.102 "sudo -n md5sum /opt/smarthome/services/$s/conf/devices.json; sudo -n docker update --restart=no $s >/dev/null && sudo -n docker stop $s >/dev/null"
ssh mmv@198.18.1.102 "cd /opt/smarthome/services/$s && sudo -n tar czf /tmp/$s-conf.tar.gz -C conf . && sudo -n chown mmv:mmv /tmp/$s-conf.tar.gz"
scp mmv@198.18.1.102:/tmp/$s-conf.tar.gz /tmp/
kubectl -n default run nas-load-$s --rm -i --restart=Never --image=alpine:3.20 \
  --overrides="{\"spec\":{\"containers\":[{\"name\":\"nas-load\",\"image\":\"alpine:3.20\",\"command\":[\"sh\",\"-c\",\"mkdir -p /nas/smarthome/$s && cat > /tmp/c.tgz && tar xzf /tmp/c.tgz -C /nas/smarthome/$s && chown -R 1000:1000 /nas/smarthome/$s && ls -l /nas/smarthome/$s\"],\"stdin\":true,\"volumeMounts\":[{\"name\":\"nas\",\"mountPath\":\"/nas\"}]}],\"volumes\":[{\"name\":\"nas\",\"nfs\":{\"server\":\"198.18.1.125\",\"path\":\"/mnt/HD/HD_a2/k8s\"}}]}}" < /tmp/$s-conf.tar.gz
rm -f /tmp/$s-conf.tar.gz; ssh mmv@198.18.1.102 "rm -f /tmp/$s-conf.tar.gz"
kubectl apply -f /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/smarthome/$s.yaml
kubectl -n smarthome rollout status deploy/$s --timeout=300s
kubectl -n smarthome logs deploy/$s --tail=15
```

Ожидаемо: под поднялся, в логах нет ошибок. `conditioner` в VictoriaMetrics не
пишет — проверять его только по логам и по MQTT (следующий шаг).

- [ ] **Step 4: Перенести presence**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
s=presence
ssh mmv@198.18.1.102 "sudo -n md5sum /opt/smarthome/services/$s/conf/devices.json; sudo -n docker update --restart=no $s >/dev/null && sudo -n docker stop $s >/dev/null"
ssh mmv@198.18.1.102 "cd /opt/smarthome/services/$s && sudo -n tar czf /tmp/$s-conf.tar.gz -C conf . && sudo -n chown mmv:mmv /tmp/$s-conf.tar.gz"
scp mmv@198.18.1.102:/tmp/$s-conf.tar.gz /tmp/
kubectl -n default run nas-load-$s --rm -i --restart=Never --image=alpine:3.20 \
  --overrides="{\"spec\":{\"containers\":[{\"name\":\"nas-load\",\"image\":\"alpine:3.20\",\"command\":[\"sh\",\"-c\",\"mkdir -p /nas/smarthome/$s && cat > /tmp/c.tgz && tar xzf /tmp/c.tgz -C /nas/smarthome/$s && chown -R 1000:1000 /nas/smarthome/$s && ls -l /nas/smarthome/$s\"],\"stdin\":true,\"volumeMounts\":[{\"name\":\"nas\",\"mountPath\":\"/nas\"}]}],\"volumes\":[{\"name\":\"nas\",\"nfs\":{\"server\":\"198.18.1.125\",\"path\":\"/mnt/HD/HD_a2/k8s\"}}]}}" < /tmp/$s-conf.tar.gz
rm -f /tmp/$s-conf.tar.gz; ssh mmv@198.18.1.102 "rm -f /tmp/$s-conf.tar.gz"
kubectl apply -f /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/smarthome/$s.yaml
kubectl -n smarthome rollout status deploy/$s --timeout=300s
kubectl -n smarthome logs deploy/$s --tail=15
```

Ожидаемо: под поднялся, в логах нет ошибок.

- [ ] **Step 5: Проверить, что все трое живут в MQTT**

```bash
ssh mmv@198.18.1.102 'timeout 120 sudo -n docker exec mosquitto mosquitto_sub -h localhost -t "#" -C 10 -v 2>&1 | cut -c1-100'
```

Ожидаемо: среди сообщений есть топики от перенесённых сервисов. Подписка на
`#` берёт всё дерево — односегментный `+` пропустил бы вложенные топики.

Коммита нет.

---

### Task 8: Переезд samsung_tv и проверка WoL

**Выполняется отдельно, после всех остальных и только когда владелец готов
подойти к телевизорам.** Samsung привязывает токен авторизации к клиенту, а
клиент меняется: раньше подключался `.102`, теперь — нода кластера. С высокой
вероятностью каждый телевизор при первом подключении покажет запрос
«разрешить устройство», и его надо подтвердить пультом. Пока это не сделано,
сервис будет висеть без управления, хотя под выглядит здоровым.

Отсюда же следует, что откат тут дороже остальных: вернувшись на `.102`,
возможно, придётся авторизоваться ещё раз.

**Files:** изменений в git нет.

- [ ] **Step 1: Перенести сервис**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
s=samsung_tv
ssh mmv@198.18.1.102 "sudo -n md5sum /opt/smarthome/services/$s/conf/devices.json; sudo -n docker update --restart=no $s >/dev/null && sudo -n docker stop $s >/dev/null"
ssh mmv@198.18.1.102 "cd /opt/smarthome/services/$s && sudo -n tar czf /tmp/$s-conf.tar.gz -C conf . && sudo -n chown mmv:mmv /tmp/$s-conf.tar.gz"
scp mmv@198.18.1.102:/tmp/$s-conf.tar.gz /tmp/
kubectl -n default run nas-load-tv --rm -i --restart=Never --image=alpine:3.20 \
  --overrides="{\"spec\":{\"containers\":[{\"name\":\"nas-load\",\"image\":\"alpine:3.20\",\"command\":[\"sh\",\"-c\",\"mkdir -p /nas/smarthome/$s && cat > /tmp/c.tgz && tar xzf /tmp/c.tgz -C /nas/smarthome/$s && chown -R 1000:1000 /nas/smarthome/$s && ls -l /nas/smarthome/$s\"],\"stdin\":true,\"volumeMounts\":[{\"name\":\"nas\",\"mountPath\":\"/nas\"}]}],\"volumes\":[{\"name\":\"nas\",\"nfs\":{\"server\":\"198.18.1.125\",\"path\":\"/mnt/HD/HD_a2/k8s\"}}]}}" < /tmp/$s-conf.tar.gz
rm -f /tmp/$s-conf.tar.gz; ssh mmv@198.18.1.102 "rm -f /tmp/$s-conf.tar.gz"
kubectl apply -f /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/smarthome/samsung-tv.yaml
kubectl -n smarthome rollout status deploy/samsung-tv --timeout=300s
```

Ожидаемо: под поднялся.

- [ ] **Step 2: Убедиться, что hostNetwork действительно включён**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome get pod -l app=samsung-tv -o jsonpath='{.items[0].status.podIP} {.items[0].status.hostIP}{"\n"}'
```

Ожидаемо: оба адреса одинаковые и равны адресу ноды (`198.18.1.5x`). Если
podIP из диапазона `10.42.x` — `hostNetwork` не применился, и WoL работать не
будет.

- [ ] **Step 3: Проверить, что DNS не потерялся**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome exec deploy/samsung-tv -- getent hosts mqtt.beerloga.su
```

Ожидаемо: `198.18.1.102`. Пусто — забыт `dnsPolicy: ClusterFirstWithHostNet`.

- [ ] **Step 4: Авторизоваться на телевизорах**

Подойти к каждому телевизору и подтвердить запрос на подключение, если он
появился. Проверить в логах:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome logs deploy/samsung-tv --tail=30
```

Ожидаемо: нет повторяющихся отказов авторизации. Если сервис пишет о неудачном
подключении к ТВ — токен не принят, нужно подтверждение на экране.

- [ ] **Step 5: Проверить WoL вживую**

Выключить телевизор и отправить команду включения тем же способом, что и
обычно (через MQTT-топик сервиса или из UI умного дома).

Ожидаемо: телевизор включается. Это единственная проверка, которую нельзя
свести к команде: бродкаст теперь уходит с адреса ноды, а не с `.102`, и если
его фильтрует сеть или сам ТВ — увидим только глазами.

Не сработало — откат:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome scale deploy/samsung-tv --replicas=0
ssh mmv@198.18.1.102 'sudo -n docker update --restart=unless-stopped samsung_tv && sudo -n docker start samsung_tv'
```

- [ ] **Step 6: Проверить итоговое состояние**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome get pods
ssh mmv@198.18.1.102 'for c in presence power humidity conditioner samsung_tv; do printf "%-12s " "$c"; sudo -n docker inspect -f "{{.State.Status}} restart={{.HostConfig.RestartPolicy.Name}}" $c; done'
```

Ожидаемо: пять подов `Running`, пять контейнеров `exited restart=no`.

Коммита нет.

---

### Task 9: Документация

**Files:**
- Create: `ops/nanopi-r5c-k3s/apps/smarthome/README.md`
- Modify: `ops/nanopi-r5c-k3s/apps/README.md`

- [ ] **Step 1: Создать README сервисов**

Полное содержимое `ops/nanopi-r5c-k3s/apps/smarthome/README.md`:

~~~markdown
# Сервисы умного дома

Пять самописных Python-сервисов, мигрированных с `198.18.1.102` 2026-08-09:
`humidity`, `power`, `conditioner`, `presence`, `samsung-tv`. Код — в отдельном
репозитории `~/Yandex.Disk.localized/IdeaProjects/smarthome`.

Сервисы **никого не слушают**: только исходящие соединения к брокеру и
VictoriaMetrics, поэтому ни Service, ни Ingress у них нет. `mqtt.beerloga.su` и
`vm.beerloga.su` резолвятся с нод в `198.18.1.102` — брокер и VictoriaMetrics
остались на шлюзовом узле, адреса при переезде не менялись.

Аргументы **не одинаковы**: `--victoria` есть только у `power` и `humidity`,
остальные три работают через MQTT.

`samsung-tv` — единственный с `hostNetwork: true`: Wake-on-LAN шлётся бродкастом
на `255.255.255.255`, а из pod-сети такое в LAN не уходит. Вместе с hostNetwork
обязателен `dnsPolicy: ClusterFirstWithHostNet`, иначе под теряет кластерный DNS.

## Обновление кода

```bash
cd ~/Yandex.Disk.localized/IdeaProjects/smarthome
git commit -am "..."            # скрипт откажется собирать грязное дерево
./build-and-push.sh humidity    # или без аргументов — все пять
```

Скрипт печатает тег (короткий git-sha). Его надо прописать в `image:`
соответствующего манифеста и применить:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl apply -f humidity.yaml
```

Тег — не `latest` сознательно: иначе непонятно, что именно раскатано, и некуда
откатываться.

## Данные

`conf` каждого сервиса — каталог на NAS
(`198.18.1.125:/mnt/HD/HD_a2/k8s/smarthome/<name>`), inline `nfs`-том, без PVC.
Там лежит `devices.json` — состояние, которое сервис переписывает сам. NFS, а не
local-path: писатель один, блокировок нет, зато под не привязан к ноде.

Обратная сторона: при недоступности NAS сервисы встают. Раньше они это
переживали.

## Откат на docker

`/opt/smarthome` на `.102` не тронут, контейнеры остановлены со снятым
автозапуском:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome scale deploy/<name> --replicas=0
ssh mmv@198.18.1.102 'sudo docker update --restart=unless-stopped <name> && sudo docker start <name>'
```

Порядок важен: сначала погасить под, потом поднять контейнер, иначе оба будут
писать в один брокер.
~~~

- [ ] **Step 2: Дополнить apps/README.md**

После абзаца про zigbee2mqtt добавить:

```markdown
Сервисы умного дома (`humidity`, `power`, `conditioner`, `presence`,
`samsung-tv`) мигрированы с `198.18.1.102` 2026-08-09 — namespace `smarthome`,
подробности в [`smarthome/README.md`](smarthome/README.md). Образы собираются на
маке и лежат в кластерном реестре `registry.k3s.beerloga.su`
(см. [`registry/README.md`](registry/README.md)).
```

- [ ] **Step 3: Проверить ссылки**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
ls ops/nanopi-r5c-k3s/apps/smarthome/ ops/nanopi-r5c-k3s/apps/registry/
```

Ожидаемо: в `smarthome/` — пять манифестов и `README.md`, в `registry/` —
`registry.yaml` и `README.md`.

- [ ] **Step 4: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/smarthome/README.md ops/nanopi-r5c-k3s/apps/README.md
git commit -m "docs(k3s): describe the smarthome services and their rollout"
```

---

## Известные ограничения

- **NAS — точка отказа для шести подов** (реестр и пять сервисов). Взамен ни
  один не привязан к ноде.
- **`.102` остаётся зависимостью**: mosquitto и VictoriaMetrics там же.
- **Сборка ручная**, с мака. CI в этот план не входит.
- **Чистка реестра** не настроена: старые теги копятся. При нехватке места
  удалять вручную (`REGISTRY_STORAGE_DELETE_ENABLED=true` уже выставлен).
- **`.sh`-скрипты запуска** в репозитории smarthome остаются как путь отката и
  расходятся с манифестами — это осознанно.
