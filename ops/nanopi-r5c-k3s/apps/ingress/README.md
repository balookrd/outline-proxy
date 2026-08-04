# Вход трафика: MetalLB + Traefik (LAN-only)

Bare-metal кластер — облачного LoadBalancer нет. Внешние адреса раздаёт **MetalLB**
(L2/ARP-режим) из пула в домашней подсети; **Traefik** сидит на одном VIP и разбирает
HTTP по хостам. Только LAN, без TLS (добавить cert-manager позже, если понадобится).

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

## DNS

LAN-only, поэтому имена `*.k3s.local` должны резолвиться в `198.18.1.200`. Варианты:

- запись на роутере: wildcard `*.k3s.local → 198.18.1.200` (Keenetic умеет);
- либо `/etc/hosts` на клиентах: `198.18.1.200 grafana.k3s.local z2m.k3s.local`.

Проверка входа:

```bash
curl -H 'Host: grafana.k3s.local' http://198.18.1.200/
```
