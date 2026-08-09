# k3s: переход с `k3s.local` на `k3s.beerloga.su` + TLS

Дата: 2026-08-09. Область: `ops/nanopi-r5c-k3s/` и узел `198.18.1.102`.

## Проблема

Раскладка ingress домашнего k3s-кластера использует имена `*.k3s.local`
([`apps/ingress/ingress-routes.yaml`](../../../ops/nanopi-r5c-k3s/apps/ingress/ingress-routes.yaml)),
выбранные как плейсхолдер под посылку «LAN-only, без TLS». Две беды:

1. **`.local` зарезервирован RFC 6762 под mDNS.** macOS (mDNSResponder), Avahi и
   systemd-resolved резолвят такие имена мультикастом, минуя unicast-DNS
   роутера. Рекомендация из README «wildcard `*.k3s.local` на Keenetic» на маке
   владельца, скорее всего, не сработает вовсе — отсюда и второй вариант в том
   же README, правка `/etc/hosts` на клиентах.
2. **Нет TLS.** Grafana и zigbee2mqtt отдаются голым HTTP.

У владельца есть настоящий домен `beerloga.su` (NS — `ns1/ns2.reg.ru`).

## Решение — общая форма

Поддомен `k3s.beerloga.su`, резолвится **только внутри LAN** (Keenetic), TLS —
настоящий Let's Encrypt через уже работающий на парке механизм: `lego` с
DNS-01-провайдером `regru`. Сертификат выпускается на `.102` и заливается в
кластер отдельным Secret'ом; cert-manager в кластер не вводим.

### Почему не cert-manager

Публичных A-записей нет, поэтому HTTP-01 невозможен — только DNS-01. У
cert-manager нет нативного solver'а под reg.ru (есть cloudflare, route53,
azuredns, clouddns, acmedns, digitalocean, rfc2136), а у `lego` — есть, и он уже
восемь месяцев продлевает `ss`/`ss2`/`cloud1`/`cloud`/`any2` на четырёх узлах
парка (`/opt/beerloga/update-certs.sh`, cron ежесуточно).

Рассмотренные и отклонённые альтернативы:

- **acme-dns + встроенный `acmeDNS`-solver** — работает и в cert-manager, и в
  lego; попутно убрал бы пароль reg.ru с узлов. Отклонено как избыточное для
  текущей задачи: новый сервис на VPS, NS-делегация, разовый CNAME на каждое
  имя. Остаётся кандидатом для отдельной работы по миграции всего парка.
- **Перенос зоны `beerloga.su` на Cloudflare** — нативный solver и scoped-токен,
  но Cloudflare free не даёт зону-поддомен, переезжает вся зона.
- **cert-manager + community-webhook для reg.ru** — неподдерживаемый код с
  доступом к API всего аккаунта регистратора.
- **Свой CA** — Android 7+ не доверяет пользовательским CA в приложениях.

## Компоненты

### 1. DNS (Keenetic)

Wildcard-запись `*.k3s.beerloga.su → 198.18.1.200` (VIP Traefik). Публичных
записей в reg.ru не заводим: TXT `_acme-challenge.k3s.beerloga.su` для
валидации lego создаёт и удаляет сам через API.

**Риск:** wildcard в DNS-хостах поддерживают не все прошивки Keenetic. Проверить
первым шагом; фолбэк — две явные записи (`grafana.k3s`, `z2m.k3s`), имён всего
два. Ограничение зафиксировать в README.

### 2. Сертификат

Один wildcard на `*.k3s.beerloga.su` + apex `k3s.beerloga.su` в SAN. Wildcard, а
не перечисление имён: новый сервис получает HTTPS без нового выпуска, и имена
внутренних сервисов не попадают в публичные CT-логи.

Выпуск — на `.102`, **отдельным блоком** в `/opt/beerloga/update-certs.sh`: в
существующий цикл `for DOMAIN in ss ss2` он не встраивается, там имя строится
как `$DOMAIN.beerloga.su`, а здесь нужен вызов с двумя `-d`. Форму вызова
копируем с работающих доменов (docker `goacme/lego`, `-u 1000:1001`, те же
`--dns regru --dns.resolvers ns1.reg.ru:53 --dns.resolvers ns2.reg.ru:53`).

lego сохраняет wildcard с подчёркиванием вместо звёздочки:
`/opt/beerloga/.lego/certificates/_.k3s.beerloga.su.{crt,key}`.

### 3. Публикация в кластер

Новый `publish-cert.sh` (в git, копия разворачивается на `.102`):

```bash
kubectl --kubeconfig=/opt/beerloga/k3s-cert.kubeconfig -n traefik \
  create secret tls k3s-wildcard-tls --cert=… --key=… --dry-run=client -o yaml \
  | kubectl --kubeconfig=… apply -f -
```

Идемпотентно: если серт не менялся, `apply` — no-op, поэтому вызывается
ежесуточно вместе с продлением, без проверки «а обновилось ли». Traefik следит
за Secret и подхватывает новый серт без рестарта.

На `.102` сейчас нет `kubectl` — ставим бинарь (amd64).

### 4. Доступ `.102` в кластер

Не полный kubeconfig, а узкий ServiceAccount `cert-publisher` в ns `traefik`:

| Объект | Содержание |
|---|---|
| ServiceAccount | `cert-publisher` |
| Role | `secrets: get, update, patch`, `resourceNames: [k3s-wildcard-tls]` |
| RoleBinding | Role → SA |
| Secret | тип `kubernetes.io/service-account-token`, аннотация `kubernetes.io/service-account.name` — долгоживущий токен (k8s 1.24+ не создаёт его автоматически) |

Глагол `create` **не выдаётся**: его нельзя ограничить по `resourceNames`.
Первый Secret создаётся руками при раскатке, дальше токен умеет ровно одно —
обновлять этот конкретный серт. `kubectl apply` над существующим объектом
обходится `get` + `patch`.

kubeconfig на `.102` — режим 600, владелец `mmv`.

### 5. Traefik

`TLSStore` с именем `default` в ns `traefik`, `defaultCertificate.secretName:
k3s-wildcard-tls`. Тогда сертификат существует в единственном экземпляре, а
Ingress'ы в `monitoring` и `home` включают HTTPS аннотациями:

```yaml
traefik.ingress.kubernetes.io/router.entrypoints: websecure
traefik.ingress.kubernetes.io/router.tls: "true"
```

без `spec.tls` и без копирования Secret по namespace'ам. Вариант с
`secretName` в каждом Ingress отклонён: он требует reflector либо ручных копий
серта в каждый ns.

В values включается `websecure` (`expose.default: true`, exposedPort 443) и
редирект `web → websecure`.

## Изменения в репозитории

| Файл | Что |
|---|---|
| `apps/ingress/ingress-routes.yaml` | хосты `grafana.k3s.beerloga.su`, `z2m.k3s.beerloga.su` + TLS-аннотации |
| `apps/ingress/traefik.values.yaml` | websecure + redirect; снять «no TLS yet» |
| `apps/ingress/tls-store.yaml` | новый — TLSStore `default` |
| `apps/ingress/cert-publisher.rbac.yaml` | новый — SA + Role + RoleBinding + token Secret |
| `apps/ingress/publish-cert.sh` | новый — публикация серта, исполняется на `.102` |
| `apps/deploy.sh` | `stage_ingress` применяет новые манифесты; `stage_namespaces` выделена из `stage_apps`; новая стадия-группа `edge` = repos + metallb + traefik + namespaces + ingress |
| `apps/ingress/README.md` | раздел DNS/TLS, ограничение Keenetic, процедура |
| `apps/README.md` | карта адресов и предусловия |
| `README.md` | предраскаточный чеклист (`*.k3s.beerloga.su`, серт) |

`ops/nanopi-r5c-k3s/` ведётся только по-русски, EN-пары нет — правило
двуязычной документации здесь не применяется.

## Порядок раскатки

1. Проверить, поддерживает ли Keenetic wildcard в DNS-хостах.
2. Выпустить серт на `.102` вручную, проверить файлы и SAN.
3. Применить в кластере: Secret (первое создание), TLSStore, RBAC; забрать токен
   в kubeconfig на `.102`.
4. `helm upgrade` Traefik с новыми values + новые ingress-routes.
5. Завести DNS-запись на Keenetic.
6. Проверка с мака: `curl -v https://grafana.k3s.beerloga.su` — валидная цепочка,
   200; `http://…` редиректит на https.
7. **Только после зелёной проверки** дописать выпуск и publish-шаг в
   `update-certs.sh` на `.102`.

Порядок именно такой, чтобы боевой cron не трогать, пока путь не проверен
вручную: сейчас он продлевает `ss`/`ss2`, от которых зависит домашний вход, и
ломать его ради Grafana нельзя.

## Проверки

- `openssl s_client -connect 198.18.1.200:443 -servername grafana.k3s.beerloga.su`
  — цепочка от Let's Encrypt, SAN содержит `*.k3s.beerloga.su`.
- `curl -sI http://grafana.k3s.beerloga.su` — 301/308 на https.
- `curl -s https://z2m.k3s.beerloga.su` — 200.
- `kubectl -n traefik get secret k3s-wildcard-tls -o jsonpath='{.metadata.managedFields[*].time}'`
  после повторного прогона `publish-cert.sh` — время не меняется (apply — no-op).
- Прогон `publish-cert.sh` с токеном `cert-publisher` против чужого Secret
  должен получить `forbidden` — подтверждение, что права действительно узкие.

## Что НЕ входит

- cert-manager, acme-dns, перенос зоны на Cloudflare.
- Миграция парка (`cloud1`/`cloud2`/`.102`/`.104`) на другой DNS-01-провайдер.
- HA публикации серта: `.102` — единственная точка выпуска. Окно до истечения —
  30 дней, восстановление ручное и дешёвое.
- Вынос наружу VictoriaMetrics и `outline-ss/ws`/`ocserv` (они на hostNetwork,
  мимо ingress).

## Открытые риски

- **Пароль reg.ru лежит открытым текстом** в `update-certs.sh` на всех четырёх
  узлах парка — это учётка кабинета регистратора, а не scoped-токен:
  компрометация любого узла даёт контроль над всеми доменами аккаунта. Пароль
  дополнительно прошёл через контекст ассистента 2026-08-09. Смена пароля —
  отдельная задача, но откладывать её не стоит.
- **Кластер пустой** (проверено 2026-08-09): 3 ноды `k3s-1/2/3`,
  `v1.36.2+k3s1`, но `apps/deploy.sh` не применялся ни разу — нет ни MetalLB, ни
  Traefik, ни namespace'ов приложений, ни Grafana/zigbee2mqtt; `helm` на нодах
  отсутствует. Отсюда две правки к плану выше: слой входа поднимается стадией
  `edge` **отдельно от приложений** (их раскатка — другая работа со своими
  предусловиями: NFS, секреты, `<PLACEHOLDER>` в `outline/`), а сквозная
  проверка упирается в `404` от Traefik, потому что бэкендов нет. Настоящий
  `200` по HTTPS проверяется временным подом `traefik/whoami`, который затем
  удаляется.
- **Rate limits Let's Encrypt:** 5 одинаковых сертификатов в неделю. При отладке
  выпуска пользоваться staging-эндпоинтом.
- **Wildcard на Keenetic** — см. фолбэк выше.
