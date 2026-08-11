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
| `nfs-client` | NAS `198.18.1.125:/mnt/HD/HD_a2/k8s/pvc` (NFSv3) | всё остальное stateful — переезжает за подом |

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
`configuration.yaml` внутри тома, а НЕ в переменных окружения: там же лежат
`network_key` и `pan_id`, без которых сеть из 22 устройств не соберётся. Там же
и адрес брокера — теперь `mqtt://mosquitto.home:1883`.

Данные — NFS (`198.18.1.125:/mnt/HD/HD_a2/k8s/zigbee2mqtt-data`), inline
`nfs`-том без PVC: `database.db` у z2m — JSON-lines, а не SQLite, поэтому
блокировок нет и сетевая ФС безопасна, зато под не привязан к ноде. Ночного
бэкапа у z2m нет — снят сознательно, копия на `.102` в `/opt/zigbee2mqtt`
осталась замороженной на момент переезда.

Сервисы умного дома (`humidity`, `power`, `conditioner`, `presence`) мигрированы
с `198.18.1.102` 2026-08-09 — namespace `smarthome`, подробности в
[`smarthome/README.md`](smarthome/README.md). `samsung-tv` тоже в кластере: ему нужен
hostNetwork для Wake-on-LAN, а токены авторизации Samsung хранятся отдельно на
каждый исходящий IP — иначе переезд пода на другую ноду требовал бы повторного
подтверждения на экране телевизора. Образы собираются на маке и лежат в кластерном реестре
`registry.k3s.beerloga.su` (см. [`registry/README.md`](registry/README.md)).

mosquitto мигрирован с `198.18.1.102` 2026-08-10 — namespace `home`, данные на
NFS (`mosquitto-data`), образ `eclipse-mosquitto:2.1.2-alpine` (тега без
`-alpine` в ветке 2.1 не существует). **Два листенера:** 1883 для всех и 1888
для spruthub, которому ACL закрывает `espresense/#`; потеря второго не даст
ошибки, только утечку чужих топиков. ConfigMap монтируется тремя `subPath`, а
не каталогом: mosquitto 2.1 отказывается открывать `acl_file`, если это
симлинк, а каталог ConfigMap состоит из симлинков.

Наружу — `Service type=LoadBalancer` на VIP `198.18.1.201` (`mqtt.beerloga.su`),
`externalTrafficPolicy: Local`, иначе адреса железок подменяются адресами нод.
Внутри кластера поды ходят на ClusterIP `mosquitto.home`, а не на VIP.

На `.102` остались два юнита `mqtt-forward@1883` и `mqtt-forward@1888` — socat
на VIP. Они существуют ради **waterius**: счётчик воды прописан литеральным
`198.18.1.102`, просыпается редко и перенастройке не поддаётся. Всё, что идёт
через них, брокер видит как `.102`.

VictoriaMetrics мигрирована с `198.18.1.102` 2026-08-09 — namespace
`monitoring`, под прибит к `k3s-1`, данные на `local-path` (NVMe). Здесь
сознательно НЕ NFS: у TSDB поток мелких записей с fsync, сетевая ФС для этого не
годится — в отличие от z2m и smarthome, где она уместна.

В кластере обращаться по `http://victoria-metrics.monitoring:8428`, снаружи —
`https://vm.k3s.beerloga.su`. Ночной бэкап — CronJob `vmbackup` (снапшот через
API, инкрементально).

**Скрейпить сервисы кластера надо по ClusterIP, а не через ingress.** Запрос из
пода на MetalLB-VIP собственного кластера уходит наружу и возвращается; Traefik
на таком hairpin отвечает `5xx`, при этом снаружи тот же URL даёт `200`. На этом
отвалился скрейп Grafana сразу после переезда — цель переведена на
`grafana.monitoring:3000`.

Метрики самих нод собирает DaemonSet `node-exporter` (версия 1.11.1, как на
парке; `hostNetwork` + `hostPID`, иначе отдавал бы метрики контейнера). Цели
дописаны в существующий job `node-exporter` рядом с остальными узлами.

**Раскладка на NAS:** данные лежат в корне экспорта (`registry/`, `smarthome/`,
`zigbee2mqtt-data/`), бэкапы — в `backup/` (`backup/grafana/`,
`backup/victoria-metrics/`).

**Все stateful-поды на `k3s-1`** — VictoriaMetrics, Grafana, samsung-tv. Одна
нода, одно место для данных и для восстановления; плата — её потеря затрагивает
всех троих.

`local-path` уже встроен в k3s и смотрит в `/var/lib/rancher/k3s/storage` — то есть в
смонтированный NVMe (шаг 8 runbook). Отдельно ставить нечего.

`nfs-client` ставится чартом (`./deploy.sh storage`). Автосозданные тома идут в
подкаталог `pvc/`, отдельно от каталогов, заведённых руками при переездах с
`.102` (`zigbee2mqtt-data`, `mosquitto-data`, `registry`, `smarthome`) и от
`backup/`. NAS отвечает **только по NFSv3** — на `nfsvers=4.1` и `nfsvers=4`
монтирование падает с «Protocol not supported»; эта ошибка про версию
протокола, а не про путь. Тот же каталог доступен и по короткому алиасу
`198.18.1.125:/nfs/k8s` (так его монтирует autofs на `.102`), хотя
`showmount -e` показывает только канонический путь. Root не сквошится, поэтому
провижнер может выставлять права на то, что создал.

Тома z2m и mosquitto подключены **inline** (`nfs:` в манифесте), а не через
`nfs-client`: их данные перенесены руками и лежат в каталогах с осмысленными
именами, тогда как провижнер называет каталоги по uid тома.

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
