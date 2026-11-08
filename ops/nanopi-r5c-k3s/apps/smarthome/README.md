# Сервисы умного дома

Самописные Python-сервисы, перенесённые с `198.51.100.102` 2026-08-09, namespace
`smarthome`. Код — в отдельном репозитории
`~/Yandex.Disk.localized/IdeaProjects/smarthome`.

Реальные имена узлов, домены и адреса парка в этом документе заменены условными: `fleet.example` — домен парка; `198.51.100.0/24` — домашняя сеть (`.102`, `.104` и т. д. — последний октет). Соответствие — в локальном некоммитируемом `FLEET.local.md`.

| Сервис | Манифест | Пишет в VictoriaMetrics |
|---|---|---|
| `humidity` | `humidity.yaml` | да (`CurrentRelativeHumidity`, `CurrentTemperature`, …) |
| `power` | `power.yaml` | да (`power_watt`) |
| `conditioner` | `conditioner.yaml` | нет |
| `presence` | `presence.yaml` | нет |
| `samsung-tv` | `samsung-tv.yaml` | нет |

Сервисы ничего не слушают: только исходящие соединения к брокеру и
VictoriaMetrics, поэтому ни Service, ни Ingress у них нет. Брокер и VictoriaMetrics
тоже в кластере, и сервисы ходят к ним по ClusterIP: `--mqtt mosquitto.home` у всех
пяти, `--victoria victoria-metrics.monitoring` только у `power` и `humidity`. Внешние
имена (`mqtt.fleet.example`) из пода не используются: путь через LAN-VIP собственного
кластера длиннее, и на связке Grafana↔Traefik такой путь уже давал `5xx`.

## Обновление кода

```bash
cd ~/Yandex.Disk.localized/IdeaProjects/smarthome
git commit -am "..."            # скрипт откажется собирать грязное дерево
./build-and-push.sh humidity    # или без аргументов — все пять
```

Скрипт печатает тег (короткий git-sha). Пропишите его в `image:`
соответствующего манифеста и примените:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl apply -f humidity.yaml
```

Тег не `latest`: иначе непонятно, что именно раскатано, и некуда
откатываться. Образы лежат в кластерном реестре, см.
[`../registry/README.md`](../registry/README.md).

## Данные

`conf` каждого сервиса — каталог на NAS
(`198.51.100.105:/volume1/k8s/smarthome/<name>`), inline `nfs`-том, без PVC.
Там лежит `devices.json` — состояние, которое сервис переписывает сам. NFS, а не
local-path: писатель один, блокировок нет, зато под не привязан к ноде.

Обратная сторона: при недоступности NAS сервисы останавливаются. На `.102` в docker
они это переживали.

## Liveness

У всех пяти сервисов `livenessProbe` смотрит на mtime файла
`/tmp/<name>.heartbeat` (у `samsung-tv` — `/tmp/samsung_tv.heartbeat`): главный цикл
трогает его каждые 0.5–2 секунды (`asyncio.sleep` главного цикла в репозитории
smarthome), порог — 60 секунд, проба раз в 30 секунд. Тот же порог зашит в `HEALTHCHECK` образа, но в k8s Docker-инструкция
не действует, и до появления пробы heartbeat писался в пустоту.

Проба закрывает зависание главного цикла — например, на записи в NFS. Задачу,
упавшую с исключением, `TaskSupervisor` гасит сам: процесс завершается, под
поднимает kubelet. Зависание остальных worker'ов проба не видит — heartbeat
трогают не они (у `samsung-tv` это `listen_command` и `publish_command`).

## samsung-tv: hostNetwork и авторизация по IP

Перенесён последним из-за двух отличий от остальных сервисов:

1. hostNetwork. Wake-on-LAN шлётся бродкастом на `255.255.255.255:9`, а из
   pod-сети `10.42.0.0/16` такое в LAN не уходит. В манифесте уже прописаны
   `hostNetwork: true` и `dnsPolicy: ClusterFirstWithHostNet` (второе
   обязательно, иначе под теряет кластерный DNS).
2. Авторизация привязана к IP. Samsung выдаёт токен на пару «телевизор +
   клиент», а клиента различает по адресу — в кластере это адрес ноды. Поэтому
   сервис хранит токены словарём `tokens: {ip: token}` и выбирает нужный по
   фактическому исходящему адресу (`local_ip_for` — UDP-connect к телевизору,
   пакетов не шлёт, только выясняет маршрут).

   При первом появлении пода на новой ноде телевизор один раз попросит
   подтверждение на экране; дальше возвраты на эту ноду проходят молча. Все три
   ноды авторизованы 2026-08-09, в `tokens` у каждого ТВ по три ключа.

   Раньше токен был один на устройство, и авторизация на второй ноде затирала
   первую — переезд туда-обратно требовал подтверждения каждый раз.

   В логе ошибки теперь есть `src=` и `token=есть/нет`: без них
   `ms.channel.timeOut` («запрос висел на экране, его не подтвердили»)
   неотличим от «токена для этого адреса не было», а чинятся они по-разному.

## Откат на docker

`/opt/smarthome` на `.102` не тронут, контейнеры остановлены со снятым
автозапуском:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome scale deploy/<name> --replicas=0
ssh mmv@198.51.100.102 'sudo docker update --restart=unless-stopped <name> && sudo docker start <name>'
```

Порядок важен: сначала погасить под, потом поднять контейнер, иначе оба будут
писать в один брокер.

## Проверка

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome get pods
kubectl -n smarthome logs deploy/power --tail=20

# метрики (только power и humidity)
curl -sG 'https://vm.k3s.fleet.example/api/v1/query' --data-urlencode 'query=power_watt'
```

Мгновенный `count()` по метрике показывает меньше серий, чем есть: датчики шлют
по изменению, а не периодически. Смотреть `count(count_over_time(...[1h]))`.
