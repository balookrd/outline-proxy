# outline на кластере

`outline-ss-rust` (сервер data plane) и `outline-ws-rust` (клиент SOCKS5/TUN) работают
без PVC: состояния на диске нет, конфиг через ConfigMap, секреты через Secret. Открыт
только вопрос размещения.

## Развилка размещения (TODO — подтвердить)

Оба бинаря сетевые, поэтому размещение определяет не CPU, а к чему привязан трафик:

- Одинаковая роль на всех нодах (например, `ss-rust` как edge на каждой) →
  `DaemonSet`, `hostNetwork: true`.
- Привязка к конкретному uplink конкретной ноды (`ws-rust` поднимает TUN к
  определённому аплинку одной платы) → `Deployment` с `nodeSelector`/`nodeAffinity`
  на эту ноду, `replicas: 1`.

Скелеты в каталоге:

| Файл | Объект | Что уже задано |
|---|---|---|
| `outline-ss-rust.daemonset.yaml` | `DaemonSet` | `hostNetwork: true`, `NET_ADMIN` (SO_MARK / fwmark), ConfigMap `outline-ss-config` + Secret `outline-ss-secrets` |
| `outline-ws-rust.deployment.yaml` | `Deployment` | `hostNetwork: true`, `nodeSelector` на `k3s-1`, `NET_ADMIN`, `/dev/net/tun` через `hostPath`, ConfigMap `outline-ws-config` + Secret `outline-ws-secrets` |

Образ (`<REGISTRY>/…:<TAG>`) и конфиг в ConfigMap — заглушки, поэтому `deploy.sh`
оба файла пропускает. После выбора варианта лишний файл удалить.

## Требования к подам

- `securityContext.capabilities.add: [NET_ADMIN]` — обоим (fwmark-роутинг; у `ws-rust`
  ещё и TUN ingress);
- `/dev/net/tun` через `hostPath` или device-plugin — для TUN-пути `ws-rust`;
- `hostNetwork: true`, если нужен доступ к физическому uplink/fwmark-роутингу;
- конфиг — ConfigMap, секреты (PSK/UUID/токены) — Secret вне git.

Не логировать PSK/UUID/токены (инвариант репо), metrics labels — low-cardinality.
