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
пропускаются `zigbee2mqtt` (`<COORDINATOR_IP>`), `outline/*` и `ocserv` (`<REGISTRY>/<TAG>`)
— заполнишь значения, повторный прогон их подхватит.

**Секреты — до раскатки, вне git.** Создать из шаблонов `*.secret.example.yaml`:

```bash
kubectl -n monitoring create secret generic grafana-admin \
  --from-literal=password='<STRONG_PASSWORD>'
# ocserv-certs — когда дойдёт до ocserv (см. vpn/ocserv-certs.secret.example.yaml)
```

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

Пул MetalLB `198.18.1.200–210` **исключить из DHCP роутера**. DNS: `*.k3s.local →
198.18.1.200`.

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
