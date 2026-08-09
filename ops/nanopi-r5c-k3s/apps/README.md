# Workload-манифесты кластера NanoPi R5C

Деплой-дерево для k3s-кластера, поднятого по [`../README.md`](../README.md). Runbook
там — про железо и кластер; здесь — только нагрузка и её storage.

## Storage-модель (решение)

Два StorageClass, оба почти бесплатны по RAM/CPU — на 4 ГБ ноды это главный критерий.
Longhorn/Ceph сознательно не используются: все нагрузки — синглтоны, HA им даёт не
репликация диска, а **быстрый failover + ночной бэкап**.

| Класс | Носитель | Кому |
|---|---|---|
| `local-path` (default, встроен в k3s) | локальный NVMe ноды | только IOPS-heavy: VictoriaMetrics |
| `nfs-client` | внешний NAS по NFS | всё остальное stateful — переезжает за подом |

Почему так: см. рассуждение в шапке каждого манифеста. Коротко — синглтон нельзя
запустить в двух репликах (z2m подерётся за координатор, VM за базу), поэтому HA = один
под + том, видимый со всех нод (NFS) + `strategy: Recreate`. VM — исключение: её запись
нельзя гнать по 2.5GbE, держим на NVMe и спасаем бэкапом.

Failover при смерти ноды занимает ~5 мин (дефолтный `node-monitor-grace-period` +
eviction). Для дома нормально; тюнить на слабом железе не стоит — ложные срабатывания
на флапах дороже.

## Порядок применения

Всё раскатывает [`deploy.sh`](deploy.sh) — идемпотентно (`helm upgrade --install`,
`kubectl apply`), можно гонять повторно. На ноде:

```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
./deploy.sh              # все стадии по порядку
./deploy.sh metallb      # одна стадия: repos|storage|metallb|traefik|apps|ingress
```

Стадии: NFS-провижнер → MetalLB (+ пул, с ожиданием webhook) → Traefik (+ ожидание VIP)
→ namespaces + нагрузка → HTTP-роуты. Требует `kubectl` и `helm` в PATH.

**Guard.** Скрипт не применяет `*.example.yaml` (шаблоны секретов) и любой манифест с
незаполненными `<PLACEHOLDER>` — вместо битого объекта печатает `[skip]`. Сейчас
пропускаются `outline/*` и `ocserv` (`<REGISTRY>/<TAG>`) — заполнишь значения,
повторный прогон их подхватит.

**Секреты — до раскатки, вне git.** Секреты Grafana (`grafana-smtp`,
`grafana-alerting`) создаются скриптами из [`ops/grafana/`](../../grafana/) —
см. тамошний README. Пароля администратора среди них нет намеренно: он живёт в
перенесённой БД, а `GF_SECURITY_ADMIN_PASSWORD` сбрасывал бы его при каждом
старте пода. Остальное — из шаблонов `*.secret.example.yaml` (ocserv-certs,
когда дойдёт до ocserv).

Grafana мигрирована с `198.18.1.102` 2026-08-09: данные — SQLite на
`local-path` (PV несёт node-affinity, поэтому под приколочен к своей ноде),
конфигурация — ConfigMap `grafana-datasources` и `grafana-dashboard-provider`,
дашборды — по ConfigMap на файл, алертинг — Secret `grafana-alerting`. Ночной
бэкап на NAS — CronJob `grafana-backup`.

zigbee2mqtt мигрирован с `198.18.1.102` 2026-08-09. Координатор сетевой
(`tcp://198.18.1.106:8888`), поэтому под не привязан к железу. Настройки — в
`configuration.yaml` внутри PVC, а НЕ в переменных окружения: там же лежат
`network_key` и `pan_id`, без которых сеть из 22 устройств не соберётся.
Брокер mosquitto **остался на `.102`** вместе с шестью контейнерами умного дома
и четырьмя внешними клиентами; z2m ходит на него по прежнему адресу.

Данные — NFS (`198.18.1.125:/mnt/HD/HD_a2/k8s/zigbee2mqtt-data`), inline
`nfs`-том без PVC: `database.db` у z2m — JSON-lines, а не SQLite, поэтому
блокировок нет и сетевая ФС безопасна, зато под не привязан к ноде. Ночного
бэкапа у z2m нет — снят сознательно, копия на `.102` в `/opt/zigbee2mqtt`
осталась замороженной на момент переезда.

Сервисы умного дома (`humidity`, `power`, `conditioner`, `presence`) мигрированы
с `198.18.1.102` 2026-08-09 — namespace `smarthome`, подробности в
[`smarthome/README.md`](smarthome/README.md). `samsung-tv` пока остался в docker:
ему нужен hostNetwork для Wake-on-LAN и, вероятно, повторная авторизация на
телевизорах. Образы собираются на маке и лежат в кластерном реестре
`registry.k3s.beerloga.su` (см. [`registry/README.md`](registry/README.md)).

`local-path` уже встроен в k3s и смотрит в `/var/lib/rancher/k3s/storage` — то есть в
смонтированный NVMe (шаг 8 runbook). Отдельно ставить нечего.

## Вход трафика

Три класса, три пути — детали в [`ingress/README.md`](ingress/README.md):

| Класс | Путь | Адрес |
|---|---|---|
| HTTP (Grafana, z2m frontend) | Traefik Ingress | `198.18.1.200` (VIP MetalLB) |
| MQTT L4 (внешние клиенты) | LoadBalancer мимо Traefik | `198.18.1.201` |
| VictoriaMetrics | ClusterIP, наружу нет | — |
| outline-ss/ws, ocserv | hostNetwork, свои порты | IP прибитой ноды |

Пул MetalLB `198.18.1.200–210` **исключить из DHCP роутера**. DNS: wildcard
`*.k3s.beerloga.su → 198.18.1.200` на Keenetic, только внутри LAN. Сертификат
`*.k3s.beerloga.su` выпускает lego на `.102` и заливает в Secret
`k3s-wildcard-tls` — подробности в [`ingress/README.md`](ingress/README.md).

Слой входа поднимается отдельно от приложений: `./deploy.sh edge` ставит
MetalLB, Traefik, namespace'ы и ingress-объекты, не трогая workloads. Пока
приложения не развёрнуты, Ingress'ы штатно отдают `404` — сертификат при этом
уже валидный.

## Что заполнить перед деплоем (открытые вопросы)

Помечено `TODO` / `<...>` в файлах:

- **`<NAS_IP>` / `<EXPORT_PATH>`** — экспорт NFS с NAS (`storage/nfs-provisioner.values.yaml`).
- **outline-топология** — `outline-ws-rust` привязан к одному uplink или к каждой ноде?
  От этого DaemonSet vs pinned Deployment (`outline/`).
- **VM retention/объём** — влезает ли в NVMe-раздел, нужен ли отдельный
  (`monitoring/victoria-metrics.yaml`).
- **Конфликт порта 443** — ocserv слушает 443 tcp+udp; если outline/ingress уже
  заняли 443 под `hostNetwork`, развести по портам или нодам (`vpn/ocserv.yaml`).
- **Нет доверенного arm64-образа ocserv** — собрать свой (`vpn/ocserv.yaml`).

## Раскладка по классам данных

| Сервис | /данные | Носитель |
|---|---|---|
| VictoriaMetrics | TSDB | local-path NVMe, pinned |
| Grafana, mosquitto, zigbee2mqtt, python | стейт | NFS RWO |
| ocserv | `ocpasswd` | NFS RWO (мелкий) |
| outline-ss/ws, ocserv | сертификаты/конфиг | Secret/ConfigMap, без PVC |

## Конвенции

- Namespace на домен: `monitoring`, `home`, `outline`, `vpn`.
- Все stateful-синглтоны — `replicas: 1`, `strategy: Recreate`, `accessModes: [ReadWriteOnce]`.
- Секреты (PSK, токены, пароли Grafana) — **не в git**; здесь только `Secret`-скелеты с
  плейсхолдерами, реальные значения через `kubectl create secret` или SOPS.
- Образы — arm64 (проверено: VM, z2m, mosquitto, grafana тянут arm64-манифесты).
