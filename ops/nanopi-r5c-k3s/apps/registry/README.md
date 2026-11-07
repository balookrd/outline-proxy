# Приватный реестр образов

`registry.k3s.fleet.example` — реестр для самописных сервисов (`smarthome`).
Живёт за Traefik и получает общий wildcard-сертификат из `TLSStore default`,
поэтому containerd на нодах доверяет ему как обычному сайту: править
`registries.yaml` не нужно.

Реальные имена узлов, домены и адреса парка в этом документе заменены условными: `fleet.example` — домен парка; `198.51.100.0/24` — домашняя сеть (`.102`, `.104` и т. д. — последний октет). Соответствие — в локальном некоммитируемом `FLEET.local.md`.

Данные — NFS на NAS (`198.51.100.125:/mnt/HD/HD_a2/k8s/registry`), inline-том без PVC.
Не local-path: у реестра нет БД и блокировок, только блобы, поэтому сетевая ФС
безопасна, а под переживает потерю ноды и не зависит от того, какая нода поднялась
первой после рестарта кластера.

`../deploy.sh` этот каталог не применяет. Раскатка:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl apply -f registry.yaml      # namespace registry, Middleware, Deployment, Service, Ingress
```

## Секреты (вне git, до раскатки)

Один пароль используется дважды: для basic-auth на входе и для
`imagePullSecret`, которым поды тянут образы.

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
REG_USER=smarthome
read -rs REG_PASS     # ввод не попадёт в историю shell

# 1. htpasswd для Traefik
kubectl -n registry create secret generic registry-auth \
  --from-literal=users="$(htpasswd -nbB "$REG_USER" "$REG_PASS")"

# 2. imagePullSecret для подов (в namespace, где они запускаются)
kubectl -n smarthome create secret docker-registry registry-creds \
  --docker-server=registry.k3s.fleet.example \
  --docker-username="$REG_USER" --docker-password="$REG_PASS"

# 3. логин с мака для push
docker login registry.k3s.fleet.example -u "$REG_USER"
```

`htpasswd` на macOS лежит в `/usr/sbin/htpasswd`.

Без `registry-creds` в namespace пода под встаёт в `ImagePullBackOff` с `401`, хотя
сам реестр работает. Секрет нужен в каждом namespace, где поды тянут образы из
реестра: `smarthome` и `monitoring` (outline-ui).

## Проверка

```bash
curl -so /dev/null -w 'без пароля: %{http_code}\n' https://registry.k3s.fleet.example/v2/
curl -su "$REG_USER:$REG_PASS" https://registry.k3s.fleet.example/v2/_catalog
```

Ожидается `401` в первом случае и список репозиториев во втором. Если без пароля
приходит `200` — middleware не подключилась; проверить аннотацию
`router.middlewares` (формат `<namespace>-<name>@kubernetescrd`).

## Публикация образов

Сборка — на маке, он arm64, как и ноды: см. `build-and-push.sh` в репозитории
smarthome. Тег — короткий git-sha, `latest` не используется.

## Чистка

Удаление включено (`REGISTRY_STORAGE_DELETE_ENABLED=true`). DELETE манифеста через
Registry API только отвязывает манифест, блобы остаются на NFS до сборки мусора.
Сборку мусора делает CronJob `registry-gc` из
[`ops/k3s/registry-gc-cronjob.yaml`](../../../k3s/registry-gc-cronjob.yaml):
по воскресеньям (`0 4 * * 0`, по комментарию в манифесте — 04:00 UTC) запускает
`registry garbage-collect --delete-untagged` на том же NFS-томе. Реестр на время
сборки в read-only не переводится, поэтому push, совпавший со сборкой, теоретически
может потерять только что загруженный блоб. Старые теги CronJob не удаляет — их
удалять вручную через Registry API.
