# Сервисы умного дома

Самописные Python-сервисы, мигрированные с `198.18.1.102` 2026-08-09. Код — в
отдельном репозитории `~/Yandex.Disk.localized/IdeaProjects/smarthome`.

| Сервис | Где | Пишет в VictoriaMetrics |
|---|---|---|
| `humidity` | кластер | да (`CurrentRelativeHumidity`, `CurrentTemperature`, …) |
| `power` | кластер | да (`power_watt`) |
| `conditioner` | кластер | нет |
| `presence` | кластер | нет |
| `samsung-tv` | **ещё в docker на `.102`** | нет |

Сервисы **никого не слушают**: только исходящие соединения к брокеру и
VictoriaMetrics, поэтому ни Service, ни Ingress у них нет. `mqtt.beerloga.su` и
`vm.beerloga.su` резолвятся с нод в `198.18.1.102` — брокер и VictoriaMetrics
остались на шлюзовом узле, адреса при переезде не менялись.

Аргументы **не одинаковы**: `--victoria` есть только у `power` и `humidity`.

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
откатываться. Образы лежат в кластерном реестре, см.
[`../registry/README.md`](../registry/README.md).

## Данные

`conf` каждого сервиса — каталог на NAS
(`198.18.1.125:/mnt/HD/HD_a2/k8s/smarthome/<name>`), inline `nfs`-том, без PVC.
Там лежит `devices.json` — состояние, которое сервис переписывает сам. NFS, а не
local-path: писатель один, блокировок нет, зато под не привязан к ноде.

Обратная сторона: при недоступности NAS сервисы встают. Раньше они это
переживали.

## samsung-tv — отдельно

Не перенесён намеренно. Две причины:

1. **hostNetwork.** Wake-on-LAN шлётся бродкастом на `255.255.255.255:9`, а из
   pod-сети `10.42.0.0/16` такое в LAN не уходит. В манифесте уже прописаны
   `hostNetwork: true` и `dnsPolicy: ClusterFirstWithHostNet` (второе
   обязательно, иначе под теряет кластерный DNS).
2. **Авторизация на телевизорах.** Samsung привязывает токен к клиенту, а клиент
   сменится: был `.102`, станет нода. Телевизоры, скорее всего, потребуют
   подтверждения на экране — раскатывать, когда есть возможность подойти к ним с
   пультом.

Токены лежат в `devices.json` и переедут вместе с ним, так что есть шанс, что
подтверждение не понадобится. Проверяется только вживую.

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

## Проверка

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome get pods
kubectl -n smarthome logs deploy/power --tail=20

# метрики (только power и humidity)
ssh mmv@198.18.1.102 "curl -sG 'http://127.0.0.1:8428/api/v1/query' --data-urlencode 'query=power_watt'"
```

Мгновенный `count()` по метрике показывает меньше серий, чем есть: датчики шлют
по изменению, а не периодически. Смотреть `count(count_over_time(...[1h]))`.
