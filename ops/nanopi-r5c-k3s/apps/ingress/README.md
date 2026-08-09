# Вход трафика: MetalLB + Traefik (LAN-only)

Bare-metal кластер — облачного LoadBalancer нет. Внешние адреса раздаёт **MetalLB**
(L2/ARP-режим) из пула в домашней подсети; **Traefik** сидит на одном VIP и разбирает
HTTP по хостам. Только LAN, но по HTTPS: wildcard-сертификат `*.k3s.beerloga.su`
выпускается вне кластера (lego на `.102`) — см. [DNS и TLS](#dns-и-tls).

## Карта адресов

Домашняя подсеть `198.18.1.0/24` (ноды `.51–.53`, NAS `.125`). Пул MetalLB —
`198.18.1.200–210`.

| VIP | Кому | Через что |
|---|---|---|
| `198.18.1.200` | Traefik — единая точка входа для всего HTTP | Ingress |
| `198.18.1.201` | mosquitto MQTT (только если есть клиенты вне кластера) | L4 LoadBalancer, мимо Traefik |

⚠️ **Диапазон `.200–210` обязательно исключить из DHCP-пула роутера** — иначе роутер
выдаст `.200` случайному устройству и получишь конфликт IP. То же правило, что и для
резерваций нод.

Почему MQTT мимо Traefik: z2m↔mosquitto — критичная для умного дома пара, и ставить её
в зависимость от рестарта ingress незачем. Сырой TCP проще и надёжнее отдать отдельным
LoadBalancer-сервисом. Внутри кластера z2m всё равно ходит в mosquitto по ClusterIP —
внешний VIP нужен только для не-кластерных MQTT-клиентов (ESP, HA вне k3s).

## Что НЕ через ingress

- **VictoriaMetrics** — остаётся ClusterIP, наружу не выставляется (Grafana берёт её
  как datasource внутри кластера). Нужен доступ для отладки — `kubectl port-forward`.
- **outline-ss/ws, ocserv** — `hostNetwork`, свои публичные порты на прибитой ноде,
  минуют и MetalLB, и Traefik целиком.

## Установка (порядок)

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
kubectl -n traefik get svc traefik            # EXTERNAL-IP должен стать 198.18.1.200

# 3. Ingress-объекты сервисов
kubectl apply -f ingress-routes.yaml
```

## DNS и TLS

Кластерные имена живут в поддомене `k3s.beerloga.su` и резолвятся **только
внутри LAN**: wildcard `*.k3s.beerloga.su → 198.18.1.200` на Keenetic.
Публичных A-записей нет — снаружи имена не существуют.

Почему не `*.k3s.local`, как было раньше: `.local` зарезервирован RFC 6762 под
mDNS, и macOS/Avahi/systemd-resolved резолвят такие имена мультикастом, минуя
unicast-DNS роутера — wildcard на Keenetic до них просто не доезжает.

Если прошивка роутера не принимает `*` в DNS-хостах, завести две явные записи
(`grafana.k3s.beerloga.su`, `z2m.k3s.beerloga.su`) — при добавлении сервиса не
забыть третью.

Сертификат — настоящий Let's Encrypt, wildcard `*.k3s.beerloga.su` (+ apex в
SAN). Выпускает его **не кластер**: `lego` на `198.18.1.102` по DNS-01 через
API reg.ru, тем же ежесуточным `/opt/beerloga/update-certs.sh`, который
продлевает боевые серты парка. Готовый серт заливается в Secret
`k3s-wildcard-tls` (ns `traefik`) скриптом [`publish-cert.sh`](publish-cert.sh);
токен у него узкий — только `get/update/patch` этого одного Secret'а
([`cert-publisher.rbac.yaml`](cert-publisher.rbac.yaml)).

Раздаёт серт `TLSStore` с именем `default` ([`tls-store.yaml`](tls-store.yaml)),
поэтому Ingress'ы в `monitoring`/`home` не носят `spec.tls` и не требуют копий
Secret'а в своих namespace'ах — достаточно двух аннотаций:

```yaml
traefik.ingress.kubernetes.io/router.entrypoints: websecure
traefik.ingress.kubernetes.io/router.tls: "true"
```

cert-manager сознательно не используется: у него нет solver'а под reg.ru, а
HTTP-01 недоступен — VIP приватный, Let's Encrypt до него не достучится.

Проверка входа:

```bash
curl -sI http://grafana.k3s.beerloga.su          # 308 → https
curl -s -o /dev/null -w '%{http_code}\n' https://grafana.k3s.beerloga.su
openssl s_client -connect 198.18.1.200:443 -servername grafana.k3s.beerloga.su \
  </dev/null 2>/dev/null | openssl x509 -noout -issuer -ext subjectAltName
```

Пока workloads не развёрнуты, второй запрос вернёт `404` — это Traefik без
бэкенда, а не проблема TLS; сертификат в третьей команде уже валидный.
