# k3s → k3s.beerloga.su + TLS: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Перевести ingress домашнего k3s-кластера с плейсхолдерных имён `*.k3s.local`
на реальные `*.k3s.beerloga.su` и отдавать их по HTTPS с сертификатом Let's Encrypt.

**Architecture:** Имена резолвятся только внутри LAN (Keenetic → VIP Traefik
`198.18.1.200`). Wildcard-сертификат выпускает `lego` на узле `.102` тем же
DNS-01-провайдером `regru`, которым уже продлеваются боевые серты парка, и
публикует его в кластер узким ServiceAccount-токеном. Traefik раздаёт этот
сертификат всем Ingress'ам через `TLSStore default`, поэтому Secret существует в
единственном экземпляре и не копируется по namespace'ам. cert-manager в кластер
не вводится.

**Tech Stack:** k3s (3 ноды aarch64), Traefik v3 (helm chart), MetalLB (L2),
`goacme/lego` в Docker на `.102` (amd64), Keenetic как LAN-резолвер.

Спека: [`docs/superpowers/specs/2026-08-09-k3s-tls-beerloga-design.md`](../specs/2026-08-09-k3s-tls-beerloga-design.md).

## Global Constraints

- Домен кластера: `k3s.beerloga.su`. Сервисы: `grafana.k3s.beerloga.su`,
  `z2m.k3s.beerloga.su`. Публичных A-записей не заводить.
- Сертификат: один wildcard `*.k3s.beerloga.su` + apex `k3s.beerloga.su` в SAN.
- Имя Secret'а с сертификатом: `k3s-wildcard-tls`, namespace `traefik`.
  Имя ServiceAccount: `cert-publisher`, namespace `traefik`.
- VIP Traefik: `198.18.1.200`. Пул MetalLB: `198.18.1.200–210`.
- Узел выпуска: `198.18.1.102` (`ssh mmv@198.18.1.102`), пользователь `mmv`,
  uid:gid для контейнера lego — `1000:1001`, каталог состояния
  `/opt/beerloga/.lego`, cron владельца `mmv` в `33 0 * * *`.
- Нода кластера для kubectl/helm: `198.18.1.51` (`ssh mmv@198.18.1.51`),
  `sudo` без пароля (`sudo -n`), `KUBECONFIG=/etc/rancher/k3s/k3s.yaml`,
  бинарь — `k3s kubectl`.
- **Состояние кластера на 2026-08-09 (проверено):** 3 ноды `k3s-1/2/3`, все
  control-plane+etcd, k3s `v1.36.2+k3s1`, возраст 4д20ч. Namespace'ов
  приложений НЕТ (только `default`, `kube-system`, `kube-public`,
  `kube-node-lease`) — `apps/deploy.sh` не применялся ни разу: нет ни MetalLB,
  ни Traefik, ни `monitoring`/`home`, ни самих Grafana/zigbee2mqtt. `helm` на
  ноде отсутствует.
- Следствие: сквозная проверка доходит до сертификата и редиректа, но `200` от
  Grafana недостижим, пока workloads не развёрнуты — Traefik вернёт `404`.
  Раскатка workloads в этот план не входит.
- **Пароль reg.ru не тиражировать**: в скриптах он уже есть, брать оттуда;
  в git, логи и вывод команд не копировать.
- **Не трогать боевой `update-certs.sh` до зелёной ручной проверки** — он
  продлевает `ss`/`ss2`, от которых зависит домашний вход.
- Git: коммиты на английском, без Co-Authored-By и без Claude-атрибуции.
  Работаем в `main`, ветку не создаём. `git commit` — только по явной команде
  владельца; шаги «Commit» готовят изменения и показывают diff.
- `ops/nanopi-r5c-k3s/` ведётся только по-русски, EN-пары заводить не нужно.

---

### Task 1: Проверить wildcard в DNS Keenetic

Состояние кластера уже снято (см. Global Constraints) — остаётся единственное
неизвестное, от которого зависит Задача 6.

**Files:** нет изменений.

**Interfaces:**
- Produces: `WILDCARD_OK` да/нет — определяет, одна запись в DNS роутера или две.

- [x] **Step 1: Проверить wildcard в DNS Keenetic**

В веб-интерфейсе роутера завести тестовую запись `*.k3s.beerloga.su →
198.18.1.200`. Если поле не принимает `*` — фиксируем `WILDCARD_OK=нет`.
Проверка с мака:

```bash
dig +short probe.k3s.beerloga.su @198.18.1.1
```

Ожидаемо `198.18.1.200` при `WILDCARD_OK=да`; пусто — значит фолбэк на две явные
записи (`grafana.k3s.beerloga.su`, `z2m.k3s.beerloga.su`) в Задаче 6.

Коммита нет.

---

### Task 2: Манифесты и values в репозитории

Все изменения кластерных объектов кладём в git до того, как что-либо применяем.

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml`
- Modify: `ops/nanopi-r5c-k3s/apps/ingress/traefik.values.yaml`
- Create: `ops/nanopi-r5c-k3s/apps/ingress/tls-store.yaml`
- Create: `ops/nanopi-r5c-k3s/apps/ingress/cert-publisher.rbac.yaml`
- Modify: `ops/nanopi-r5c-k3s/apps/deploy.sh` (функция `stage_ingress`, строки 106–109)

**Interfaces:**
- Produces: Secret `k3s-wildcard-tls` (ns `traefik`) как контракт между
  Задачей 4 (создаёт), Задачей 6 (обновляет) и `TLSStore default` (читает);
  ServiceAccount `cert-publisher` и токен в Secret `cert-publisher-token`.

- [x] **Step 1: Переписать ingress-routes.yaml**

Полное содержимое `ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml`:

```yaml
# HTTP ingress objects. All resolve to the Traefik VIP 198.18.1.200; Traefik
# routes by Host header. Point *.k3s.beerloga.su at 198.18.1.200 in DNS (see
# README) — LAN-only, no public record.
#
# TLS: no per-Ingress secretName here on purpose. The wildcard certificate is
# served by the `default` TLSStore (tls-store.yaml), so the Secret lives once in
# the traefik namespace instead of being copied into monitoring/home.
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
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: zigbee2mqtt
  namespace: home
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.tls: "true"
spec:
  ingressClassName: traefik
  rules:
    - host: z2m.k3s.beerloga.su
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: zigbee2mqtt
                port:
                  number: 8080
```

- [x] **Step 2: Создать tls-store.yaml**

Полное содержимое `ops/nanopi-r5c-k3s/apps/ingress/tls-store.yaml`:

```yaml
# Default certificate for every TLS router in the cluster. Ingress objects opt
# into HTTPS with the router.tls annotation and get this certificate — no
# per-namespace copies of the Secret, no reflector.
#
# The Secret itself is produced outside the cluster: lego on 198.18.1.102 issues
# *.k3s.beerloga.su and publish-cert.sh pushes it here (see ingress/README.md).
apiVersion: traefik.io/v1alpha1
kind: TLSStore
metadata:
  name: default
  namespace: traefik
spec:
  defaultCertificate:
    secretName: k3s-wildcard-tls
```

- [x] **Step 3: Создать cert-publisher.rbac.yaml**

Полное содержимое `ops/nanopi-r5c-k3s/apps/ingress/cert-publisher.rbac.yaml`:

```yaml
# Credentials for the off-cluster certificate publisher (lego on 198.18.1.102).
#
# Deliberately narrow: no `create` verb — it cannot be restricted by
# resourceNames, so the first k3s-wildcard-tls Secret is created by hand during
# rollout and this token can only refresh that one object. Nothing else in the
# cluster is reachable with it.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cert-publisher
  namespace: traefik
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cert-publisher
  namespace: traefik
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["k3s-wildcard-tls"]
    verbs: ["get", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cert-publisher
  namespace: traefik
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: cert-publisher
subjects:
  - kind: ServiceAccount
    name: cert-publisher
    namespace: traefik
---
# Long-lived token: Kubernetes 1.24+ no longer mints one per ServiceAccount
# automatically, and a `kubectl create token` TTL would silently expire the
# nightly renewal.
apiVersion: v1
kind: Secret
metadata:
  name: cert-publisher-token
  namespace: traefik
  annotations:
    kubernetes.io/service-account.name: cert-publisher
type: kubernetes.io/service-account-token
```

- [x] **Step 4: Обновить traefik.values.yaml**

Полное содержимое `ops/nanopi-r5c-k3s/apps/ingress/traefik.values.yaml`:

```yaml
# Helm values for Traefik (traefik/traefik chart, v3).
# Install:
#   helm install traefik traefik/traefik -n traefik --create-namespace \
#     -f traefik.values.yaml
#
# LAN-only, HTTPS. The wildcard certificate for *.k3s.beerloga.su comes from
# lego on 198.18.1.102 via the `default` TLSStore (tls-store.yaml); there is no
# cert-manager and no ACME resolver configured here.

deployment:
  # Single replica is fine for a home LAN; MetalLB moves the VIP on node loss,
  # and Traefik reschedules. Bump to 2 if you want zero-blip ingress.
  replicas: 1

service:
  type: LoadBalancer
  annotations:
    metallb.universe.tf/loadBalancerIPs: 198.18.1.200

ports:
  web:
    port: 8000
    exposedPort: 80        # LAN clients hit :80 on 198.18.1.200
    expose:
      default: true
    redirectTo:
      port: websecure      # plain HTTP always bounces to TLS
  websecure:
    port: 8443
    exposedPort: 443
    expose:
      default: true
    tls:
      enabled: true
  traefik:
    expose:
      default: false       # dashboard/API stays internal (port-forward to view)

providers:
  kubernetesIngress:
    enabled: true          # watch standard Ingress objects
  kubernetesCRD:
    enabled: true          # IngressRoute + TLSStore CRDs

# 4 GB nodes — keep Traefik lean.
resources:
  requests:
    cpu: 50m
    memory: 64Mi
  limits:
    memory: 192Mi

logs:
  general:
    level: INFO
  access:
    enabled: false         # turn on only when debugging routing
```

- [x] **Step 5: Расширить stage_ingress в deploy.sh**

Заменить в `ops/nanopi-r5c-k3s/apps/deploy.sh` функцию `stage_ingress`
(строки 106–109) на:

```bash
stage_ingress() {
  log "cert publisher RBAC + default TLSStore"
  apply_file ingress/cert-publisher.rbac.yaml
  apply_file ingress/tls-store.yaml
  log "HTTP ingress routes"
  apply_file ingress/ingress-routes.yaml
}
```

Порядок важен: TLSStore ссылается на Secret `k3s-wildcard-tls`, а Ingress'ы —
на TLSStore. Отсутствующий Secret не ломает apply, Traefik просто отдаёт
self-signed до первой публикации серта.

- [x] **Step 6: Добавить стадию `edge` в deploy.sh**

Слой входа (MetalLB + Traefik + ingress-объекты) поднимается независимо от
приложений — про их раскатку говорим отдельно. Стадии для этого уже раздельные — не хватает только группы, чтобы
не звать три команды подряд и не задеть `apps`.

Ingress'ы живут в `monitoring`/`home`, поэтому namespace'ы нужны и слою входа, а
создаёт их сейчас только `stage_apps` вместе с workloads. Выносим их в
отдельную функцию — рядом с `stage_apps` (строка 96):

```bash
stage_namespaces() {
  log "namespaces"
  kubectl apply -f namespaces.yaml
}

stage_apps() {
  stage_namespaces
  local d
  for d in monitoring home outline vpn; do
    log "workloads: $d"
    apply_dir "$d"
  done
}
```

В `main()` (строки 111–126) добавить ветку `edge` перед `all` и упомянуть её в
сообщении об ошибке:

```bash
    edge)    stage_repos; stage_metallb; stage_traefik; stage_namespaces; stage_ingress ;;
    all)     stage_repos; stage_storage; stage_metallb; stage_traefik; stage_apps; stage_ingress ;;
    *)       die "unknown stage '$stage' (repos|storage|metallb|traefik|apps|ingress|edge|all)" ;;
```

И в шапке скрипта (строка 12) заменить строку использования на:

```bash
#   ./deploy.sh metallb         # one stage: repos|storage|metallb|traefik|apps|ingress
#   ./deploy.sh edge            # ingress layer only: MetalLB + Traefik + routes
```

- [x] **Step 7: Проверить синтаксис манифестов локально**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps
python3 -c "import sys,yaml;[list(yaml.safe_load_all(open(f))) for f in sys.argv[1:]];print('yaml ok')" ingress/ingress-routes.yaml ingress/tls-store.yaml ingress/cert-publisher.rbac.yaml ingress/traefik.values.yaml
bash -n deploy.sh && echo "bash ok"
```

Ожидаемо: `yaml ok` и `bash ok`.

- [x] **Step 8: Убедиться, что имя k3s.local нигде не осталось в манифестах**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s
grep -rn "k3s\.local" apps/*.yaml apps/*/*.yaml apps/deploy.sh
```

Ожидаемо: пусто (в README имя ещё останется — их правит Задача 7).

- [ ] **Step 9: Commit**

```bash
git add ops/nanopi-r5c-k3s/apps/ingress/ ops/nanopi-r5c-k3s/apps/deploy.sh
git commit -m "ops(k3s): serve ingress on k3s.beerloga.su over TLS

Replace the k3s.local placeholder with the real subdomain and switch the
Traefik entrypoint to websecure. The wildcard certificate is issued off-cluster
by lego and published into a single Secret, served to every router through the
default TLSStore, so no namespace needs its own copy."
```

---

### Task 3: Скрипт публикации сертификата

Отдельная задача: ревьюер может принять манифесты, но забраковать скрипт.

**Files:**
- Create: `ops/nanopi-r5c-k3s/apps/ingress/publish-cert.sh`

**Interfaces:**
- Consumes: Secret `k3s-wildcard-tls` в ns `traefik` (создаёт Задача 4),
  kubeconfig `/opt/beerloga/k3s-cert.kubeconfig` на `.102` (Задача 4).
- Produces: исполняемый `publish-cert.sh`, который Задача 6 разворачивает на
  `.102` и вызывает из `update-certs.sh`.

- [x] **Step 1: Написать скрипт**

Полное содержимое `ops/nanopi-r5c-k3s/apps/ingress/publish-cert.sh`:

```bash
#!/usr/bin/env bash
#
# Push the *.k3s.beerloga.su certificate issued by lego into the cluster.
#
# Runs on 198.18.1.102 (where lego and the reg.ru credentials already live),
# called from /opt/beerloga/update-certs.sh right after renewal. Deployed copy:
#   /opt/beerloga/publish-cert.sh
#
# Idempotent: when the certificate has not changed, `apply` is a no-op, so this
# can run on every nightly pass without churning the Secret.
#
# The kubeconfig carries the cert-publisher ServiceAccount token, which may only
# get/update/patch this one Secret — see apps/ingress/cert-publisher.rbac.yaml.
set -euo pipefail

CERT_DIR=${CERT_DIR:-/opt/beerloga/.lego/certificates}
KUBECONFIG_FILE=${KUBECONFIG_FILE:-/opt/beerloga/k3s-cert.kubeconfig}
NAMESPACE=traefik
SECRET=k3s-wildcard-tls

# lego stores wildcards with '_' in place of '*'.
CRT="$CERT_DIR/_.k3s.beerloga.su.crt"
KEY="$CERT_DIR/_.k3s.beerloga.su.key"

for f in "$CRT" "$KEY" "$KUBECONFIG_FILE"; do
  [ -s "$f" ] || { echo "publish-cert: missing or empty $f" >&2; exit 1; }
done

kubectl --kubeconfig="$KUBECONFIG_FILE" -n "$NAMESPACE" \
  create secret tls "$SECRET" --cert="$CRT" --key="$KEY" \
  --dry-run=client -o yaml \
  | kubectl --kubeconfig="$KUBECONFIG_FILE" apply -f -
```

- [x] **Step 2: Сделать исполняемым и проверить синтаксис**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/ingress
chmod +x publish-cert.sh
bash -n publish-cert.sh && echo "bash ok"
```

Ожидаемо: `bash ok`.

- [x] **Step 3: Проверить, что скрипт падает понятно при отсутствии файлов**

```bash
CERT_DIR=/nonexistent KUBECONFIG_FILE=/nonexistent ./publish-cert.sh; echo "exit=$?"
```

Ожидаемо: `publish-cert: missing or empty /nonexistent/_.k3s.beerloga.su.crt` и
`exit=1` — раньше, чем скрипт дойдёт до kubectl.

- [ ] **Step 4: Commit**

```bash
git add ops/nanopi-r5c-k3s/apps/ingress/publish-cert.sh
git commit -m "ops(k3s): add off-cluster certificate publisher

Runs on the node that already holds the reg.ru credentials and pushes the
renewed wildcard into the cluster Secret. Fails loudly on missing inputs rather
than pushing an empty certificate."
```

---

### Task 4: Выпустить wildcard-сертификат на .102

**Files:** изменений в git нет; создаются файлы на `.102`:
`/opt/beerloga/.lego/certificates/_.k3s.beerloga.su.{crt,key,json,issuer.crt}`.

**Interfaces:**
- Produces: файлы сертификата, которые читают Задачи 5 и 6.

- [x] **Step 1: Прогнать выпуск на staging-эндпоинте**

Staging кладём в отдельный каталог, иначе тестовый серт перезапишет боевой файл
того же имени. Пароль reg.ru берём из существующего
`/opt/beerloga/update-certs.sh` — в командную строку и логи он не попадает:

```bash
ssh mmv@198.18.1.102
cd /opt/beerloga
mkdir -p .lego-staging
export EMAIL=balookrd@yandex.ru
export REGRU_PASSWORD="$(grep -oP '(?<=^REGRU_PASSWORD=).*' /opt/beerloga/update-certs.sh)"
docker run --rm \
  -e REGRU_USERNAME="$EMAIL" \
  -e REGRU_PASSWORD="$REGRU_PASSWORD" \
  -e REGRU_PROPAGATION_TIMEOUT=3600 \
  -e REGRU_TTL=300 \
  -v /opt/beerloga/.lego-staging:/.lego \
  -u 1000:1001 \
  goacme/lego run -a --email "$EMAIL" \
    --server https://acme-staging-v02.api.letsencrypt.org/directory \
    --dns regru --dns.resolvers ns1.reg.ru:53 --dns.resolvers ns2.reg.ru:53 \
    -d '*.k3s.beerloga.su' -d k3s.beerloga.su
```

Ожидаемо: `[*.k3s.beerloga.su] acme: Obtaining bundled SAN certificate` и в
конце `Server responded with a certificate`. Если reg.ru отвечает ошибкой на
создание TXT — дальше не идём, это упирается в API регистратора.

- [x] **Step 2: Выпустить боевой сертификат**

```bash
docker run --rm \
  -e REGRU_USERNAME="$EMAIL" \
  -e REGRU_PASSWORD="$REGRU_PASSWORD" \
  -e REGRU_PROPAGATION_TIMEOUT=3600 \
  -e REGRU_TTL=300 \
  -v /opt/beerloga/.lego:/.lego \
  -v /opt/beerloga/.certs:/.certs \
  -u 1000:1001 \
  goacme/lego run -a --email "$EMAIL" \
    --dns regru --dns.resolvers ns1.reg.ru:53 --dns.resolvers ns2.reg.ru:53 \
    -d '*.k3s.beerloga.su' -d k3s.beerloga.su
unset REGRU_PASSWORD
```

- [x] **Step 3: Проверить SAN и срок**

```bash
openssl x509 -in /opt/beerloga/.lego/certificates/_.k3s.beerloga.su.crt \
  -noout -subject -issuer -dates -ext subjectAltName
```

Ожидаемо: issuer — Let's Encrypt (`R1x`/`E1x`), в `subjectAltName` обе записи:
`DNS:*.k3s.beerloga.su, DNS:k3s.beerloga.su`, `notAfter` ≈ +90 дней.

- [x] **Step 4: Проверить права на файлы**

```bash
ls -l /opt/beerloga/.lego/certificates/_.k3s.beerloga.su.*
```

Ожидаемо: владелец `mmv`, группа `certs`, как у соседних `ss.beerloga.su.*`.
Если ключ создан с `600` и от другого владельца — прогнать
`/opt/beerloga/permission-certs.sh` под sudo.

- [x] **Step 5: Убрать staging-каталог**

```bash
rm -rf /opt/beerloga/.lego-staging
```

Коммита нет — изменений в репозитории не было.

---

### Task 5: Поднять слой входа и выдать токен на .102

Порядок внутри задачи важен: namespace `traefik` и CRD `TLSStore` появляются
только вместе с helm-релизом Traefik, поэтому сначала helm, потом объекты.

**Files:** изменений в git нет; создаётся `/opt/beerloga/k3s-cert.kubeconfig`
на `.102`.

**Interfaces:**
- Consumes: манифесты из Задачи 2, сертификат из Задачи 4.
- Produces: Secret `k3s-wildcard-tls`, SA `cert-publisher` с токеном,
  `TLSStore default`, поднятый Traefik на VIP, kubeconfig на `.102` — всё это
  использует Задача 6.

- [x] **Step 1: Подготовить helm и kubeconfig на маке**

На ноде `helm` нет, ставить его туда незачем — управляем кластером с мака:

```bash
brew install helm
mkdir -p ~/.kube
ssh mmv@198.18.1.51 'sudo -n cat /etc/rancher/k3s/k3s.yaml' \
  | sed 's#https://127.0.0.1:6443#https://198.18.1.51:6443#' > ~/.kube/k3s-home.yaml
chmod 600 ~/.kube/k3s-home.yaml
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl get nodes
```

Ожидаемо: `k3s-1/2/3` в `Ready`.

- [x] **Step 2: Забрать сертификат с .102**

```bash
ssh mmv@198.18.1.102 'cat /opt/beerloga/.lego/certificates/_.k3s.beerloga.su.crt' > /tmp/k3s-wildcard.crt
ssh mmv@198.18.1.102 'cat /opt/beerloga/.lego/certificates/_.k3s.beerloga.su.key' > /tmp/k3s-wildcard.key
test -s /tmp/k3s-wildcard.crt && test -s /tmp/k3s-wildcard.key && echo "cert ok"
```

Ожидаемо: `cert ok`.

- [x] **Step 3: Создать namespace traefik и Secret с сертификатом**

Namespace заводим заранее, чтобы Secret лёг до того, как Traefik начнёт искать
свой `defaultCertificate`. Это единственное ручное создание Secret'а: RBAC из
Задачи 2 намеренно не даёт `create`, дальше он только обновляется.

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl create namespace traefik
kubectl -n traefik create secret tls k3s-wildcard-tls \
  --cert=/tmp/k3s-wildcard.crt --key=/tmp/k3s-wildcard.key
kubectl -n traefik get secret k3s-wildcard-tls
```

Ожидаемо: `secret/k3s-wildcard-tls created`, тип `kubernetes.io/tls`.

- [x] **Step 4: Поднять слой входа**

Приложения (`monitoring`/`home`/`outline`/`vpn`) в этот план не входят, поэтому
зовём стадию `edge` из Задачи 2 — она не вызывает `stage_apps`:

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps
export KUBECONFIG=~/.kube/k3s-home.yaml
./deploy.sh edge
```

Ожидаемо: MetalLB поднялся, пул применился, `Traefik EXTERNAL-IP = 198.18.1.200`,
затем `created` для RBAC, TLSStore и обоих Ingress.

Ingress'ы ссылаются на сервисы `grafana`/`zigbee2mqtt`, которых пока нет —
`apply` это не ломает, Traefik просто отдаст `404` на такой Host. Namespace'ы
`monitoring`/`home` стадия создаёт сама (`stage_namespaces`), workloads не
трогает.

- [x] **Step 5: Проверить VIP и что приложения не тронуты**

```bash
kubectl -n traefik get svc traefik -o jsonpath='{.status.loadBalancer.ingress[0].ip}{"\n"}'
nc -z -G3 198.18.1.200 443 && echo "VIP:443 open" || echo "VIP:443 closed"
kubectl get pods -A | grep -Ev 'kube-system|metallb-system|traefik|NAME' || echo "no app pods — as intended"
```

Ожидаемо: `198.18.1.200`, `VIP:443 open`, `no app pods — as intended`.
Если EXTERNAL-IP выдан, а порт закрыт — MetalLB не анонсирует адрес: сверить
интерфейс в `ingress/metallb-pool.yaml` (там прописан `wan0`) с реальным именем
интерфейса на нодах.

- [x] **Step 6: Собрать kubeconfig для .102**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
TOKEN=$(kubectl -n traefik get secret cert-publisher-token -o jsonpath='{.data.token}' | base64 -d)
CA=$(kubectl -n traefik get secret cert-publisher-token -o jsonpath='{.data.ca\.crt}')
printf 'apiVersion: v1
kind: Config
clusters:
  - name: k3s
    cluster:
      server: https://198.18.1.51:6443
      certificate-authority-data: %s
users:
  - name: cert-publisher
    user:
      token: %s
contexts:
  - name: cert-publisher@k3s
    context:
      cluster: k3s
      user: cert-publisher
      namespace: traefik
current-context: cert-publisher@k3s
' "$CA" "$TOKEN" > /tmp/k3s-cert.kubeconfig
```

Если `TOKEN` пуст — контроллер ещё не заполнил Secret; подождать пару секунд и
повторить.

- [x] **Step 7: Доставить kubeconfig на .102 и убрать временные файлы**

```bash
scp /tmp/k3s-cert.kubeconfig mmv@198.18.1.102:/opt/beerloga/k3s-cert.kubeconfig
ssh mmv@198.18.1.102 'chmod 600 /opt/beerloga/k3s-cert.kubeconfig'
rm -f /tmp/k3s-cert.kubeconfig /tmp/k3s-wildcard.crt /tmp/k3s-wildcard.key
```

- [x] **Step 8: Поставить kubectl на .102**

`.102` — amd64:

```bash
ssh -t mmv@198.18.1.102 'curl -fsSLo /tmp/kubectl "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && sudo install -m 0755 /tmp/kubectl /usr/local/bin/kubectl && rm -f /tmp/kubectl && kubectl version --client'
```

Ожидаемо: `Client Version: v1.3x.y`.

Коммита нет.

---

### Task 6: DNS на Keenetic и сквозная проверка HTTPS

**Files:** изменений в git нет.

**Interfaces:**
- Consumes: всё из Задач 4–5.
- Produces: подтверждение, что путь рабочий, — предусловие Задачи 7 (правка
  боевого cron).

- [x] **Step 1: Завести запись в DNS роутера**

При `WILDCARD_OK=да` (Задача 1): `*.k3s.beerloga.su → 198.18.1.200`.
При `WILDCARD_OK=нет`: две записи — `grafana.k3s.beerloga.su` и
`z2m.k3s.beerloga.su`, обе на `198.18.1.200`.

- [x] **Step 2: Проверить резолв с мака**

```bash
dig +short grafana.k3s.beerloga.su @198.18.1.1
dig +short z2m.k3s.beerloga.su
```

Ожидаемо: `198.18.1.200` в обоих случаях. Второй запрос идёт через системный
резолвер — если он пуст, а первый отвечает, мак ходит мимо роутера (проверить
`scutil --dns`).

- [x] **Step 3: Проверить сертификат на VIP**

```bash
openssl s_client -connect 198.18.1.200:443 -servername grafana.k3s.beerloga.su </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName
```

Ожидаемо: issuer Let's Encrypt, SAN `*.k3s.beerloga.su`. Если пришёл
`TRAEFIK DEFAULT CERT` — TLSStore не подхватился: проверить, что Secret и
TLSStore в ns `traefik` и что имя store ровно `default`.

- [x] **Step 4: Проверить HTTPS и редирект**

```bash
curl -sI http://grafana.k3s.beerloga.su | head -3
curl -s -o /dev/null -w '%{http_code} %{ssl_verify_result}\n' https://grafana.k3s.beerloga.su
```

Ожидаемо: `308 Permanent Redirect` с `Location: https://…`; затем
`404 0`. Именно `404`, а не `200`: Grafana не развёрнута, бэкенда за Ingress'ом
нет. Значение имеет `ssl_verify_result=0` — цепочка проверена системным
доверием, без `-k`. Это и есть доказательство, что TLS-путь рабочий.

- [x] **Step 5: Проверить сквозной путь временным бэкендом**

`404` подтверждает TLS, но не то, что запрос доходит до пода. Поднимаем
`whoami` на пару минут в `default` — приложений из плана он не касается:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl create deployment whoami --image=traefik/whoami
kubectl expose deployment whoami --port=80
kubectl create ingress whoami --class=traefik \
  --rule="whoami.k3s.beerloga.su/*=whoami:80" \
  --annotation traefik.ingress.kubernetes.io/router.entrypoints=websecure \
  --annotation traefik.ingress.kubernetes.io/router.tls=true
kubectl rollout status deployment/whoami --timeout=120s
```

Проверка (при `WILDCARD_OK=нет` сначала добавить запись `whoami.k3s` на
Keenetic либо подставить `--resolve`):

```bash
curl -s -w '\n%{http_code} %{ssl_verify_result}\n' https://whoami.k3s.beerloga.su
```

Ожидаемо: тело с `Hostname: whoami-…`, затем `200 0`.

Убрать за собой:

```bash
kubectl delete ingress whoami; kubectl delete svc whoami; kubectl delete deployment whoami
```

- [x] **Step 6: Проверить с телефона**

Открыть `https://whoami.k3s.beerloga.su` (пока не удалён) в браузере телефона в
домашней сети — замок без предупреждений. Это и есть смысл всей работы: на
`.local` этот путь не работал вовсе.

Коммита нет.

---

### Task 7: Интеграция в ежесуточное продление на .102

Только после зелёной Задачи 6 — здесь мы трогаем скрипт, от которого зависят
боевые `ss`/`ss2`.

**Files:**
- Modify (на узле `.102`): `/opt/beerloga/update-certs.sh`
- Deploy (на узел `.102`): `/opt/beerloga/publish-cert.sh` из Задачи 3

**Interfaces:**
- Consumes: `publish-cert.sh` (Задача 3), kubeconfig и Secret (Задача 5).

- [x] **Step 1: Сохранить резервную копию боевого скрипта**

```bash
ssh mmv@198.18.1.102 'cp -a /opt/beerloga/update-certs.sh /opt/beerloga/update-certs.sh.bak-2026-08-09 && ls -l /opt/beerloga/update-certs.sh.bak-2026-08-09'
```

- [x] **Step 2: Развернуть publish-cert.sh**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/ingress
scp publish-cert.sh mmv@198.18.1.102:/opt/beerloga/publish-cert.sh
ssh mmv@198.18.1.102 'chmod 750 /opt/beerloga/publish-cert.sh'
```

- [x] **Step 3: Проверить публикацию вручную и её идемпотентность**

```bash
ssh mmv@198.18.1.102 '/opt/beerloga/publish-cert.sh'
ssh mmv@198.18.1.102 '/opt/beerloga/publish-cert.sh'
```

Ожидаемо: первый прогон — `secret/k3s-wildcard-tls configured` (или
`unchanged`, если Задача 5 уже положила тот же серт), второй — обязательно
`secret/k3s-wildcard-tls unchanged`. Любой другой вывод на втором прогоне
означает, что apply не идемпотентен, и ежесуточный запуск будет дёргать Traefik.

- [x] **Step 4: Негативная проверка прав токена**

```bash
ssh mmv@198.18.1.102 'kubectl --kubeconfig=/opt/beerloga/k3s-cert.kubeconfig -n traefik get secret cert-publisher-token; echo "exit=$?"'
ssh mmv@198.18.1.102 'kubectl --kubeconfig=/opt/beerloga/k3s-cert.kubeconfig get nodes; echo "exit=$?"'
```

Ожидаемо оба раза: `Error from server (Forbidden)` и `exit=1`. Если токен читает
чужие секреты или ноды — Role шире, чем задумано, и `resourceNames` не
применился; чинить до перехода к Шагу 5.

- [x] **Step 5: Добавить выпуск и публикацию в update-certs.sh**

Дописать в `/opt/beerloga/update-certs.sh` после существующего цикла
`for DOMAIN in ss ss2 … done` (пароль в скрипте уже есть в переменной выше по
тексту — новых копий не заводим):

```bash
# k3s cluster wildcard: separate call because it needs two -d flags, and the
# loop above builds names as $DOMAIN.beerloga.su. Published into the cluster
# right after renewal; publish-cert.sh is a no-op when nothing changed.
docker run --rm \
  -e REGRU_USERNAME=$EMAIL \
  -e REGRU_PASSWORD=$REGRU_PASSWORD \
  -e REGRU_PROPAGATION_TIMEOUT=3600 \
  -e REGRU_TTL=300 \
  -v /opt/beerloga/.lego:/.lego \
  -v /opt/beerloga/.certs:/.certs \
  -u 1000:1001 \
  goacme/lego run -a --email $EMAIL \
    --dns regru --dns.resolvers ns1.reg.ru:53 --dns.resolvers ns2.reg.ru:53 \
    -d '*.k3s.beerloga.su' -d k3s.beerloga.su >> $LOG 2>&1
/opt/beerloga/publish-cert.sh >> $LOG 2>&1
```

Если в скрипте пароль задан литералом прямо в `docker run` (как сейчас), а не
переменной — вынести его в `REGRU_PASSWORD=` один раз наверху и сослаться из
обоих вызовов, чтобы не держать две копии.

- [x] **Step 6: Прогнать скрипт целиком и проверить, что боевые серты целы**

```bash
ssh mmv@198.18.1.102 '/opt/beerloga/update-certs.sh; cat /opt/beerloga/update-certs.status'
```

Ожидаемо: для `ss`/`ss2` — `Skip renewal: The certificate expires at …` (они не
подошли к окну продления), для `*.k3s` — `Skip renewal` либо тишина, затем
`secret/k3s-wildcard-tls unchanged`. Появление ошибок у `ss`/`ss2` означает, что
правка задела боевую часть: откатиться на `update-certs.sh.bak-2026-08-09`.

- [x] **Step 7: Убедиться, что cron не менялся**

```bash
ssh mmv@198.18.1.102 'crontab -l | grep cert'
```

Ожидаемо: прежняя строка `33 0 * * * /opt/beerloga/update-certs.sh` — новых
записей не нужно, wildcard продлевается тем же заходом.

Коммита нет: `/opt/beerloga/` не под git. Каноничная копия скрипта публикации
уже лежит в репозитории (Задача 3).

---

### Task 8: Документация

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/ingress/README.md` (секция «DNS», строки 52–63)
- Modify: `ops/nanopi-r5c-k3s/apps/README.md:67`
- Modify: `ops/nanopi-r5c-k3s/README.md:862`

- [x] **Step 1: Переписать секцию DNS в apps/ingress/README.md**

Заменить блок «## DNS» (строки 52–63) на (внешний fence `~~~` — внутри есть
вложенные блоки кода):

~~~markdown
## DNS и TLS

Кластерные имена живут в поддомене `k3s.beerloga.su` и резолвятся **только
внутри LAN**: wildcard `*.k3s.beerloga.su → 198.18.1.200` на Keenetic.
Публичных A-записей нет — снаружи имена не существуют.

Почему не `*.k3s.local`, как было раньше: `.local` зарезервирован RFC 6762 под
mDNS, и macOS/Avahi/systemd-resolved резолвят такие имена мультикастом, минуя
unicast-DNS роутера — wildcard на Keenetic до них просто не доезжает.

Если прошивка роутера не принимает `*` в DNS-хостах, завести две явные записи
(`grafana.k3s.beerloga.su`, `z2m.k3s.beerloga.su`) — при добавлении сервиса не
забыть третью.

Сертификат — настоящий Let's Encrypt, wildcard `*.k3s.beerloga.su` (+ apex в
SAN). Выпускает его **не кластер**: `lego` на `198.18.1.102` по DNS-01 через
API reg.ru, тем же ежесуточным `/opt/beerloga/update-certs.sh`, который
продлевает боевые серты парка. Готовый серт заливается в Secret
`k3s-wildcard-tls` (ns `traefik`) скриптом `publish-cert.sh` из этого каталога;
токен у него узкий — только `get/update/patch` этого одного Secret'а
(`cert-publisher.rbac.yaml`).

Раздаёт серт `TLSStore` с именем `default` (`tls-store.yaml`), поэтому Ingress'ы
в `monitoring`/`home` не носят `spec.tls` и не требуют копий Secret'а в своих
namespace'ах — достаточно двух аннотаций:

```yaml
traefik.ingress.kubernetes.io/router.entrypoints: websecure
traefik.ingress.kubernetes.io/router.tls: "true"
```

cert-manager сознательно не используется: у него нет solver'а под reg.ru, а
HTTP-01 недоступен — VIP приватный, Let's Encrypt до него не достучится.

Проверка входа:

```bash
curl -sI http://grafana.k3s.beerloga.su          # 308 → https
curl -s -o /dev/null -w '%{http_code}\n' https://grafana.k3s.beerloga.su
openssl s_client -connect 198.18.1.200:443 -servername grafana.k3s.beerloga.su \
  </dev/null 2>/dev/null | openssl x509 -noout -issuer -ext subjectAltName
```
~~~

- [x] **Step 2: Поправить apps/README.md**

Строку 67 (`DNS: *.k3s.local → …`) привести к:

```markdown
Пул MetalLB `198.18.1.200–210` **исключить из DHCP роутера**. DNS: wildcard
`*.k3s.beerloga.su → 198.18.1.200` на Keenetic, только внутри LAN. Сертификат
`*.k3s.beerloga.su` выпускает lego на `.102` и заливает в Secret
`k3s-wildcard-tls` — подробности в [`ingress/README.md`](ingress/README.md).

Слой входа поднимается отдельно от приложений: `./deploy.sh edge` ставит
MetalLB, Traefik, namespace'ы и ingress-объекты, не трогая workloads. Пока
приложения не развёрнуты, Ingress'ы штатно отдают `404` — сертификат при этом
уже валидный.
```

- [x] **Step 3: Поправить корневой README.md**

Строку 862 (`- завести DNS *.k3s.local → 198.18.1.200;`) заменить на две:

```markdown
- завести на Keenetic DNS `*.k3s.beerloga.su → 198.18.1.200` (LAN-only);
- выпустить wildcard-серт на `.102` и залить его в Secret `k3s-wildcard-tls`
  (см. [`apps/ingress/README.md`](apps/ingress/README.md));
```

- [x] **Step 4: Проверить, что имя `k3s.local` исчезло из репозитория**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
grep -rn "k3s\.local" ops/ docs/ | grep -v "docs/superpowers"
```

Ожидаемо: пусто. Упоминания в спеке и плане остаются — они описывают, от чего
уходим.

- [ ] **Step 5: Commit**

```bash
git add ops/nanopi-r5c-k3s/README.md ops/nanopi-r5c-k3s/apps/README.md ops/nanopi-r5c-k3s/apps/ingress/README.md
git commit -m "docs(k3s): document the beerloga.su ingress names and TLS path

Explain why .local was a bad placeholder (RFC 6762 mDNS), where the certificate
comes from, and why cert-manager is not in the picture."
```

---

## Известные ограничения раскатки

- **Приложения не входят в этот план.** Поднимается только слой входа
  (`./deploy.sh edge`): MetalLB, Traefik, namespace'ы, ingress-объекты. Grafana,
  zigbee2mqtt, outline, ocserv, NFS-provisioner остаются неразвёрнутыми — до
  этого Ingress'ы отдают `404`, и это ожидаемо. Раскатка workloads обсуждается
  отдельно; у неё свои предусловия (NFS `198.18.1.125:/nfs/k8s`, секреты из
  `*.secret.example.yaml`, `<PLACEHOLDER>` в манифестах `outline/`).
- `.102` — единственная точка выпуска. Если узел умрёт, серт перестанет
  продлеваться; окно до истечения — 30 дней, восстановление ручное.
- Rate limit Let's Encrypt: 5 одинаковых сертификатов в неделю. Отладка выпуска
  — только на staging (Задача 4, Шаг 1).
- Пароль reg.ru остаётся открытым текстом на четырёх узлах парка. Смена пароля и
  переезд на scoped-креды (acme-dns) — отдельная работа, см. спеку.
