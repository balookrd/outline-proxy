# Workload-манифесты кластера NanoPi R5C

Деплой-дерево для k3s-кластера, поднятого по [`../README.md`](../README.md). Runbook
там — про железо и кластер; здесь — только нагрузка и её storage.

Реальные имена узлов, домены и адреса парка в этом документе заменены условными: `fleet.example` — домен парка; `198.51.100.0/24` — домашняя сеть (`.102`, `.104` и т. д. — последний октет). Соответствие — в локальном некоммитируемом `FLEET.local.md`.

## Storage-модель

Два StorageClass плюс inline NFS-тома без PVC. Критерий выбора — расход RAM/CPU на
ноде с 4 ГБ; Longhorn/Ceph не используются. Все нагрузки — синглтоны, поэтому
доступность им даёт не репликация диска, а перезапуск пода на другой ноде и ночной
бэкап.

| Хранилище | Где лежат данные | Кто использует |
|---|---|---|
| `local-path` (default, встроен в k3s) | локальный NVMe ноды | VictoriaMetrics, Grafana (под прибит к `k3s-1`) |
| `nfs-client` | NAS `198.51.100.105:/volume1/k8s/pvc` (NFSv3) | PVC `ocserv-passwd` |
| inline `nfs:` без PVC | каталоги на том же NAS | zigbee2mqtt, mosquitto, сервисы `smarthome`, реестр |

Синглтон нельзя запустить в двух репликах (z2m подерётся за координатор, VM — за
базу), поэтому схема такая: один под, том, видимый со всех нод (NFS), и
`strategy: Recreate`. Исключения — VictoriaMetrics и Grafana: запись TSDB и SQLite
нельзя гнать по 2.5GbE на NAS, поэтому они на NVMe `k3s-1` и спасаются бэкапом.
Подробности — в шапке каждого манифеста.

Время переезда пода с упавшей ноды:

- поды с `tolerationSeconds: 60` на `node.kubernetes.io/unreachable` и `not-ready`
  (mosquitto, zigbee2mqtt, сервисы `smarthome`, реестр, outline-ui) — около 1.7 мин
  (≈40 с до `NotReady` плюс 60 с, по комментарию в манифестах);
- остальные — по дефолту k3s, около 5 мин;
- VictoriaMetrics и Grafana не переезжают: `nodeSelector` на `k3s-1` и PV
  `local-path` с node-affinity.

Уменьшать задержку дальше не стоит: на флапах сети ложные переезды обходятся дороже.

## Порядок применения

Всё раскатывает [`deploy.sh`](deploy.sh), идемпотентно (`helm upgrade --install`,
`kubectl apply`), можно гонять повторно. На ноде:

```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
./deploy.sh              # все стадии по порядку
./deploy.sh metallb      # одна стадия: repos|storage|metallb|traefik|apps|ingress
```

Стадии: NFS-провижнер → MetalLB (+ пул, с ожиданием webhook) → Traefik (+ ожидание VIP)
→ namespaces + нагрузка (`monitoring`, `home`, `smarthome`, `outline`, `vpn`) →
HTTP-роуты. Требует `kubectl` и `helm` в PATH. Каталог `registry/` скрипт не
применяет — `kubectl apply -f registry/registry.yaml` отдельно.

Скрипт не применяет `*.example.yaml` (шаблоны секретов) и любой манифест с
незаполненными `<PLACEHOLDER>` — вместо битого объекта печатает `[skip]`. Сейчас
пропускаются `outline/*` и `vpn/ocserv.yaml` (`<REGISTRY>/<TAG>`); после заполнения
значений повторный прогон их подхватит.

Namespace `monitoring`, `home`, `smarthome`, `outline` и `vpn` создаёт
`namespaces.yaml`, его применяет первая стадия `./deploy.sh apps`.

Секреты создаются до раскатки, вне git. `grafana-alerting` создаёт
[`ops/grafana/alerting/deploy.sh`](../../grafana/alerting/deploy.sh); `grafana-smtp`
монтируется в `monitoring/grafana.yaml` [проверить: чем создаётся Secret
`grafana-smtp` — в `ops/grafana/` описан только docker-вариант на `.102`]. Пароля
администратора среди секретов нет намеренно: он живёт в перенесённой БД, а
`GF_SECURITY_ADMIN_PASSWORD` сбрасывал бы его при каждом старте пода. Остальное —
из шаблонов `*.secret.example.yaml` (`ocserv-certs`, когда дойдёт до ocserv).

## Перенесённые сервисы

Grafana перенесена с `198.51.100.102` 2026-08-09: данные — SQLite на
`local-path` (PV несёт node-affinity, поэтому под приколочен к своей ноде),
конфигурация — ConfigMap `grafana-datasources` и `grafana-dashboard-provider`,
дашборды — по ConfigMap на файл, алертинг — Secret `grafana-alerting`. Ночной
бэкап на NAS — CronJob `grafana-backup` (расписание `30 3 * * *`).

zigbee2mqtt перенесён с `198.51.100.102` 2026-08-09. Координатор сетевой
(`tcp://198.51.100.106:8888`), поэтому под не привязан к железу. Настройки — в
`configuration.yaml` внутри тома, а не в переменных окружения: там же лежат
`network_key` и `pan_id`, без которых сеть из 22 устройств не соберётся. Там же
и адрес брокера — `mqtt://mosquitto.home:1883`.

Единственная переменная окружения — `Z2M_WATCHDOG=default`: z2m читает watchdog
только из env, аналога в `configuration.yaml` нет. Координатор висит на
serial-to-Ethernet мосту Ebyte EBT3001, и раз в несколько часов ASH ловит
таймаут — z2m пишет `Adapter disconnected, stopping` и выходит с кодом 2. Без
watchdog это стоило рестарта контейнера (31 штука за 8 дней к 2026-08-26) и
обрывало лог; с ним z2m переподключается внутри процесса через 2 с, а лог
переживает переподключение.

Данные z2m — NFS (`198.51.100.105:/volume1/k8s/zigbee2mqtt-data`), inline
`nfs`-том без PVC: `database.db` у z2m — JSON-lines, а не SQLite, поэтому
блокировок нет и сетевая ФС безопасна, а под не привязан к ноде. Ночного
бэкапа у z2m нет — снят сознательно, копия на `.102` в `/opt/zigbee2mqtt`
осталась замороженной на момент переезда.

Сервисы умного дома (`humidity`, `power`, `conditioner`, `presence`, `samsung-tv`)
перенесены с `198.51.100.102` 2026-08-09 — namespace `smarthome`, подробности в
[`smarthome/README.md`](smarthome/README.md). `samsung-tv` работает с hostNetwork
ради Wake-on-LAN, а токены авторизации Samsung хранит отдельно на каждый исходящий
IP — иначе переезд пода на другую ноду требовал бы повторного подтверждения на
экране телевизора. Образы собираются на маке и лежат в кластерном реестре
`registry.k3s.fleet.example` (см. [`registry/README.md`](registry/README.md)).

mosquitto перенесён с `198.51.100.102` 2026-08-10 — namespace `home`, данные на
NFS (`mosquitto-data`), образ `eclipse-mosquitto:2.1.2-alpine` (тега без
`-alpine` в ветке 2.1 не существует). Листенеров два: 1883 для всех и 1888
для spruthub, которому ACL закрывает `espresense/#`; потеря второго не даст
ошибки, только утечку чужих топиков. ConfigMap монтируется тремя `subPath`, а
не каталогом: mosquitto 2.1 отказывается открывать `acl_file`, если это
симлинк, а каталог ConfigMap состоит из симлинков.

Наружу — `Service type=LoadBalancer` на VIP `198.51.100.201` (`mqtt.fleet.example`),
`externalTrafficPolicy: Local`, иначе адреса железок подменяются адресами нод.
Внутри кластера поды ходят на ClusterIP `mosquitto.home`, а не на VIP.

На `.102` остались два юнита `mqtt-forward@1883` и `mqtt-forward@1888` — socat
на VIP. Они нужны для waterius: счётчик воды прописан литеральным
`198.51.100.102`, просыпается редко и перенастройке не поддаётся. Всё, что идёт
через них, брокер видит как `.102`.

VictoriaMetrics перенесена с `198.51.100.102` 2026-08-09 — namespace
`monitoring`, под прибит к `k3s-1`, данные на `local-path` (NVMe), retention 90
дней, PVC 20 ГиБ. NFS здесь не используется: у TSDB поток мелких записей с fsync,
сетевая ФС для этого не годится — в отличие от z2m и smarthome.

В кластере обращаться по `http://victoria-metrics.monitoring:8428`, снаружи —
`https://vm.k3s.fleet.example`. Ночной бэкап — CronJob `vmbackup` (расписание `15 4 * * *`, снапшот
через API, инкрементально).

Скрейпить сервисы кластера надо по ClusterIP, а не через ingress. Запрос из
пода на MetalLB-VIP собственного кластера уходит наружу и возвращается; Traefik
на таком hairpin отвечает `5xx`, при этом снаружи тот же URL даёт `200`. На этом
отвалился скрейп Grafana сразу после переезда — цель переведена на
`grafana.monitoring:3000`.

Метрики самих нод собирает DaemonSet `node-exporter` (версия 1.11.1, как на
парке; `hostNetwork` + `hostPID`, иначе отдавал бы метрики контейнера). Цели
дописаны в существующий job `node-exporter` рядом с остальными узлами.

## Раскладка на NAS

NAS — UGREEN DXP4800 Plus `.105` (до 2026-11-08 — WD MyCloud `.125`, план
переезда: `docs/superpowers/plans/2026-11-08-k3s-nfs-125-to-105.md`). Данные
лежат в корне экспорта `/volume1/k8s` (`registry/`, `smarthome/`,
`zigbee2mqtt-data/`, `mosquitto-data/`), бэкапы — в `backup/` (`backup/grafana/`,
`backup/victoria-metrics/`), тома `nfs-client` — в `pvc/`.

Stateful-поды на `local-path` — VictoriaMetrics и Grafana — оба на `k3s-1`.
Данные и восстановление в одном месте; потеря `k3s-1` останавливает оба сервиса.

`local-path` встроен в k3s и смотрит в `/var/lib/rancher/k3s/storage` — то есть в
смонтированный NVMe (шаг 8 runbook). Отдельно ставить нечего.

`nfs-client` ставится чартом (`./deploy.sh storage`). Автосозданные тома идут в
подкаталог `pvc/`, отдельно от каталогов, заведённых руками при переездах с
`.102` (`zigbee2mqtt-data`, `mosquitto-data`, `registry`, `smarthome`) и от
`backup/`.

Свойства экспорта (настраиваются в UGOS, в правах NFS общей папки `k8s`):

| Параметр | Значение | Что делает |
|---|---|---|
| Клиенты | `198.51.100.0/24` | маска `198.51.100.*` не годится: nfs-utils сравнивает её с именем из обратного DNS, а узлы разрешаются в `k3s-1..3` — монтирование падает с `access denied by server` |
| Маппинг | «все пользователи → администратор» (`all_squash,anonuid=1000,anongid=10`) | любой uid клиента, включая root, пишет как `1000:10`; без этого ACL UGOS (`system.ugacl_self`) пускает на запись только root и uid 1000 независимо от POSIX-прав |
| Версия | NFSv3 | v4 на `/volume1/k8s` сервер отклоняет (`No such file or directory`), inline-тома без `mountOptions` сами откатываются на v3 |

Следствие маппинга: `chown` с клиента возвращает `EPERM`, а все файлы на
экспорте принадлежат `1000:10`. Провижнер делает только `chmod`, ему этого
хватает. Копировать данные на экспорт — `rsync -rlptH`, без `-o -g`.

Тома z2m, mosquitto, smarthome и реестра подключены inline (`nfs:` в манифесте), а
не через `nfs-client`: их данные перенесены руками и лежат в каталогах с
осмысленными именами, тогда как провижнер называет каталоги по uid тома.

## outline-ui

Web-UI парка: оба дашборда одним сервисом — `/ws` (аплинки, топология, потери) и
`/ss` (управление юзерами). Манифесты — [`monitoring/outline-ui.yaml`](monitoring/outline-ui.yaml),
вход — `https://ui.k3s.fleet.example`.

Secret `outline-ui-tokens` держит control-токены всего парка — одиннадцать ключей:
`ui-token` (токен самого UI) и по одному на каждый инстанс из ConfigMap (четыре
`ws-*` и шесть `ss-*`). Достать токен для входа в панель:

```bash
KUBECONFIG=~/.kube/k3s-home.yaml kubectl -n monitoring \
  get secret outline-ui-tokens -o jsonpath='{.data.ui-token}' | base64 -d; echo
```

В браузере это форма входа: имя пользователя любое, пароль — токен.

Три вещи, на которых спотыкается раскатка:

- Реестр за basic-auth, поэтому поду нужен `imagePullSecrets: registry-creds`;
  секрет должен существовать в namespace `monitoring` (копируется из `smarthome`).
- `allowed_hosts` в конфиге обязан включать и публичное имя, и Service-DNS
  (`outline-ui.monitoring`) — иначе запрос изнутри кластера с валидным токеном
  получает 403 от origin policy.
- Конфиг читается один раз при старте: правка ConfigMap применяется только
  `kubectl -n monitoring rollout restart deploy/outline-ui`.

Подробности — [`bins/outline-ui/README.ru.md`](../../../bins/outline-ui/README.ru.md).

## Вход трафика

Детали — в [`ingress/README.md`](ingress/README.md):

| Класс | Путь | Адрес |
|---|---|---|
| HTTP (Grafana, outline-ui, z2m frontend, VictoriaMetrics, реестр) | Traefik Ingress | `198.51.100.200` (VIP MetalLB) |
| MQTT L4 (внешние клиенты) | LoadBalancer мимо Traefik | `198.51.100.201` |
| outline-ss/ws, ocserv | hostNetwork, свои порты | IP прибитой ноды |

Пул MetalLB `198.51.100.200–210` исключить из DHCP роутера. DNS: wildcard
`*.k3s.fleet.example → 198.51.100.200` на Keenetic, только внутри LAN. Сертификат
`*.k3s.fleet.example` выпускает lego на `.102` и заливает в Secret
`k3s-wildcard-tls` — подробности в [`ingress/README.md`](ingress/README.md).

Слой входа поднимается отдельно от приложений: `./deploy.sh edge` ставит
MetalLB, Traefik, namespace'ы, RBAC публикатора сертификата, `TLSStore` и
Ingress-объекты, не трогая workloads. Пока приложения не развёрнуты, Ingress'ы
отдают `404` — сертификат при этом уже валидный.

## Что заполнить перед деплоем

Помечено `TODO` / `<...>` в файлах:

- Топология outline: `outline-ws-rust` привязан к одному uplink или к каждой ноде?
  От этого зависит выбор между DaemonSet и pinned Deployment (`outline/`).
- Конфликт порта 443: ocserv слушает 443 tcp+udp; если outline/ingress уже
  заняли 443 под `hostNetwork`, развести по портам или нодам (`vpn/ocserv.yaml`).
- Нет доверенного arm64-образа ocserv — собрать свой (`vpn/ocserv.yaml`).
- Конфиги ocserv, `outline-ss-rust` и `outline-ws-rust` в ConfigMap — заглушки
  (`vpn/ocserv.yaml`, `outline/*.yaml`).

## Раскладка по классам данных

| Сервис | Данные | Хранилище |
|---|---|---|
| VictoriaMetrics | TSDB | `local-path` NVMe, pinned `k3s-1` |
| Grafana | SQLite | `local-path` NVMe, pinned `k3s-1` |
| mosquitto, zigbee2mqtt, сервисы `smarthome`, реестр | стейт | inline NFS-том |
| ocserv | `ocpasswd` | PVC `nfs-client` (мелкий) |
| outline-ss/ws, ocserv | сертификаты/конфиг | Secret/ConfigMap, без PVC |

## Конвенции

- Namespace на домен: `monitoring`, `home`, `smarthome`, `registry`, `outline`, `vpn`.
- Все stateful-синглтоны — `replicas: 1`, `strategy: Recreate`; PVC — `ReadWriteOnce`.
- Секреты (PSK, токены, пароли Grafana) — не в git; здесь только `Secret`-скелеты с
  плейсхолдерами, реальные значения через `kubectl create secret`.
- Образы — arm64 (проверено: VM, z2m, mosquitto, grafana тянут arm64-манифесты).
