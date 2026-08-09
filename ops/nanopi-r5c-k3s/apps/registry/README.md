# Приватный реестр образов

`registry.k3s.beerloga.su` — реестр для самописных сервисов (`smarthome`).
Живёт за Traefik и получает общий wildcard-сертификат из `TLSStore default`,
поэтому containerd на нодах доверяет ему как обычному сайту: править
`registries.yaml` не нужно.

Данные — NFS на NAS (`198.18.1.125:/mnt/HD/HD_a2/k8s/registry`). Не local-path:
у реестра нет БД и блокировок, только блобы, поэтому сетевая ФС безопасна, а
взамен под переживает потерю ноды и не зависит от того, какая нода поднялась
первой после рестарта кластера.

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
  --docker-server=registry.k3s.beerloga.su \
  --docker-username="$REG_USER" --docker-password="$REG_PASS"

# 3. логин с мака для push
docker login registry.k3s.beerloga.su -u "$REG_USER"
```

`htpasswd` на macOS лежит в `/usr/sbin/htpasswd`.

Забыть `registry-creds` — самая частая ошибка: под встаёт в `ImagePullBackOff`
с `401`, хотя сам реестр работает.

## Проверка

```bash
curl -so /dev/null -w 'без пароля: %{http_code}\n' https://registry.k3s.beerloga.su/v2/
curl -su "$REG_USER:$REG_PASS" https://registry.k3s.beerloga.su/v2/_catalog
```

Ожидаемо `401` в первом случае и список репозиториев во втором. Если без пароля
приходит `200` — middleware не подключилась; проверить аннотацию
`router.middlewares` (формат `<namespace>-<name>@kubernetescrd`).

## Публикация образов

Сборка — на маке, он arm64, как и ноды: см. `build-and-push.sh` в репозитории
smarthome. Тег — короткий git-sha, `latest` не используется.

## Чистка

Удаление включено (`REGISTRY_STORAGE_DELETE_ENABLED=true`), но автоматической
сборки мусора нет: старые теги копятся. При нехватке места удалять вручную
через Registry API, затем запускать `registry garbage-collect` внутри пода.
