# Вход трафика: MetalLB + Traefik (LAN-only)

Bare-metal кластер — облачного LoadBalancer нет. Внешние адреса раздаёт MetalLB
(L2/ARP-режим, анонс только на `wan0`) из пула в домашней подсети; Traefik сидит на одном VIP и разбирает
HTTP по хостам. Только LAN, но по HTTPS: wildcard-сертификат `*.k3s.fleet.example`
выпускается вне кластера (lego на `.102`) — см. [DNS и TLS](#dns-и-tls).

Реальные имена узлов, домены и адреса парка в этом документе заменены условными: `fleet.example` — домен парка; `198.51.100.0/24` — домашняя сеть (`.102`, `.104` и т. д. — последний октет). Соответствие — в локальном некоммитируемом `FLEET.local.md`.

## Карта адресов

Домашняя подсеть `198.51.100.0/24` (ноды `.51–.53`, NAS `.105`). Пул MetalLB —
`198.51.100.200–210`.

| VIP | Кому | Через что |
|---|---|---|
| `198.51.100.200` | Traefik — единая точка входа для всего HTTP | Ingress |
| `198.51.100.201` | mosquitto MQTT (`mqtt.fleet.example`) для клиентов вне кластера | L4 LoadBalancer, мимо Traefik |

**Внимание:** диапазон `.200–210` исключить из DHCP-пула роутера — иначе роутер
выдаст адрес из него случайному устройству, и VIP с ним столкнётся (конфликт IP). То же
правило, что и для резерваций нод.

MQTT идёт мимо Traefik, чтобы рестарт ingress не рвал MQTT-сессии внешних клиентов:
сырой TCP отдан отдельным LoadBalancer-сервисом. Внутри кластера z2m и сервисы
`smarthome` ходят в mosquitto по ClusterIP `mosquitto.home` — внешний VIP нужен только
для не-кластерных MQTT-клиентов (ESP, HA вне k3s).

## HTTP-имена за Traefik

| Имя | Namespace / Service | Где объявлен Ingress |
|---|---|---|
| `grafana.k3s.fleet.example` | `monitoring/grafana` | `ingress-routes.yaml` |
| `z2m.k3s.fleet.example` | `home/zigbee2mqtt` | `ingress-routes.yaml` |
| `ui.k3s.fleet.example` | `monitoring/outline-ui` | `ingress-routes.yaml` |
| `vm.k3s.fleet.example` | `monitoring/victoria-metrics` | `../monitoring/victoria-metrics.yaml` |
| `registry.k3s.fleet.example` | `registry/registry` (basic-auth) | `../registry/registry.yaml` |
| `jellyfin.k3s.fleet.example` | `home/jellyfin` → Jellyfin на NAS (`:8899`), EndpointSlice вручную | `../home/jellyfin.yaml` |

Внутри кластера к VictoriaMetrics и Grafana обращаться по ClusterIP
(`victoria-metrics.monitoring:8428`, `grafana.monitoring:3000`), а не через эти
имена: hairpin через VIP собственного кластера Traefik отдаёт `5xx`.

## Что не через ingress

- outline-ss/ws, ocserv — `hostNetwork`, свои публичные порты на прибитой ноде,
  минуют и MetalLB, и Traefik.

## Установка

То же самое делает `../deploy.sh edge` (плюс namespace'ы, `cert-publisher.rbac.yaml` и
`tls-store.yaml`). Вручную:

```bash
# 1. MetalLB
helm repo add metallb https://metallb.github.io/metallb
helm install metallb metallb/metallb -n metallb-system --create-namespace
kubectl -n metallb-system rollout status deploy/metallb-controller
kubectl apply -f metallb-pool.yaml            # пул + L2-анонс

# 2. Traefik (мы ставили k3s с --disable=traefik — возвращаем под своим контролем)
helm repo add traefik https://traefik.github.io/charts
helm install traefik traefik/traefik -n traefik --create-namespace \
  -f traefik.values.yaml
kubectl -n traefik get svc traefik            # EXTERNAL-IP должен стать 198.51.100.200

# 3. Ingress-объекты сервисов
kubectl apply -f ingress-routes.yaml
```

## DNS и TLS

Кластерные имена живут в поддомене `k3s.fleet.example` и резолвятся только
внутри LAN: wildcard `*.k3s.fleet.example → 198.51.100.200` на Keenetic.
Публичных A-записей нет — снаружи имена не существуют.

Раньше имена были в `*.k3s.local`. От них отказались: `.local` зарезервирован
RFC 6762 под mDNS, и macOS/Avahi/systemd-resolved резолвят такие имена мультикастом,
минуя unicast-DNS роутера, — wildcard на Keenetic до них не доходит.

Если прошивка роутера не принимает `*` в DNS-хостах, завести явные записи на все
имена из таблицы выше и добавлять новую при каждом новом Ingress.

Сертификат — Let's Encrypt, wildcard `*.k3s.fleet.example` (+ apex в
SAN). Выпускает его не кластер, а `lego` на `198.51.100.102` по DNS-01 через
API reg.ru, тем же ежесуточным `/opt/fleet/update-certs.sh`, который
продлевает боевые серты парка. Готовый серт заливается в Secret
`k3s-wildcard-tls` (ns `traefik`) скриптом [`publish-cert.sh`](publish-cert.sh);
токен у него узкий — только `get/update/patch` этого одного Secret'а
([`cert-publisher.rbac.yaml`](cert-publisher.rbac.yaml)).

Раздаёт серт `TLSStore` с именем `default` ([`tls-store.yaml`](tls-store.yaml)),
поэтому Ingress'ы в `monitoring`/`home`/`registry` не носят `spec.tls` и не требуют копий
Secret'а в своих namespace'ах — достаточно двух аннотаций:

```yaml
traefik.ingress.kubernetes.io/router.entrypoints: websecure
traefik.ingress.kubernetes.io/router.tls: "true"
```

cert-manager не используется: у него нет solver'а под reg.ru, а
HTTP-01 недоступен — VIP приватный, Let's Encrypt до него не достучится.

Проверка входа:

```bash
curl -sI http://grafana.k3s.fleet.example          # 308 → https
curl -s -o /dev/null -w '%{http_code}\n' https://grafana.k3s.fleet.example
openssl s_client -connect 198.51.100.200:443 -servername grafana.k3s.fleet.example \
  </dev/null 2>/dev/null | openssl x509 -noout -issuer -ext subjectAltName
```

Пока workloads не развёрнуты, второй запрос вернёт `404` — это Traefik без
бэкенда, а не проблема TLS; сертификат в третьей команде уже валидный.
