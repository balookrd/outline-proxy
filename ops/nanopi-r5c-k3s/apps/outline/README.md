# outline на кластере

`outline-ss-rust` (сервер data plane) и `outline-ws-rust` (клиент SOCKS5/TUN) —
**без PVC**: состояния на диске нет, конфиг через ConfigMap/Secret. Вопрос только в
топологии размещения, а не в storage.

## Развилка размещения (TODO — подтвердить)

Оба бинаря сетевые, поэтому размещение решает не CPU, а к чему привязан трафик:

- **Одинаковая роль на всех нодах** (например, `ss-rust` как edge на каждой) →
  `DaemonSet`, `hostNetwork: true`.
- **Привязка к конкретному uplink конкретной ноды** (`ws-rust` поднимает TUN к
  определённому аплинку одной платы) → `Deployment` с `nodeSelector`/`nodeAffinity`
  на эту ноду, `replicas: 1`.

Файлы-скелеты ниже дают оба варианта; лишний удалить после решения.

## Общие требования (оба бинаря, TUN-путь)

- `securityContext.capabilities: [NET_ADMIN]` (у `ws-rust` ещё и TUN ingress);
- `/dev/net/tun` через `hostPath` или device-plugin;
- `hostNetwork: true`, если нужен доступ к физическому uplink/fwmark-роутингу;
- конфиг — ConfigMap, секреты (PSK/UUID/токены) — Secret **вне git**.

Не логировать PSK/UUID/токены (инвариант репо), metrics labels — low-cardinality.
