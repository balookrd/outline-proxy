# Instances & Uplinks dashboard (как на макете)

Файл дашборда:

- `dashboard/outline-ws-uplinks.json`

Этот вариант сделан под UI как на скрине: большие summary-карточки сверху, раскрывающиеся instance/group блоки и карточки uplink, где неактивный uplink кликабелен для `POST /control/activate`.

## Рекомендуемый стек плагинов

### 1) Обязательно для «богатого» UI

- **Business Text / Dynamic Text panel** от Volkov Labs (`volkovlabs-dynamictext-panel`)

Именно этот плагин рендерит кастомный HTML/CSS/JS внутри панели и позволяет:

- сделать layout как на скрине,
- дергать `GET /control/summary` и `GET /control/topology`,
- кликать по inactive-карточке и отправлять `POST /control/activate`.

### 2) Для fallback-таблицы

- **Infinity datasource** (`yesoreyeram-infinity-datasource`)

В дашборде есть свернутая секция fallback-таблицы, работающая через Infinity.

---

## Настройка переменных дашборда

В дашборде используются переменные:

- `control_url` — base URL control plane (например `http://127.0.0.1:9091`)
- `instance_name` — подпись инстанса в UI
- `activate_transport` — `tcp | udp | both`
- `control_token` — bearer token (скрытая переменная)

Все вызовы идут с header:

```http
Authorization: Bearer <token>
```

---

## Как работает рендер

Главная панель (`volkovlabs-dynamictext-panel`) внутри JS:

1. Делает `GET /control/summary`.
2. Делает `GET /control/topology`.
3. Рисует:
   - top cards (Instances / Uplink Groups / Uplinks / Active / Inactive)
   - collapsible instance block
   - nested group blocks
   - uplink cards
4. Красит карточки:
   - active = зеленая
   - inactive = красноватая
5. По клику на inactive-card отправляет:

```http
POST /control/activate
Content-Type: application/json
Authorization: Bearer <token>

{
  "group": "...",
  "uplink": "...",
  "transport": "tcp|udp|both"
}
```

После успеха панель перерисовывается.

---

## Ограничения и важные замечания

1. Это решение **зависит от Business Text/Dynamic Text plugin** (для JS-интерактива).
2. В некоторых инсталляциях Grafana может быть ограничено выполнение JS в текстовых панелях политиками безопасности — тогда используйте fallback-таблицу и/или отдельный action plugin.
3. Если нужен полностью «нативный» Grafana без JS-плагинов — получится только упрощённый UX (таблицы/stat, без красивой вложенной карточной иерархии и inline POST-click).

---

## Minimal fallback

Если rich-plugin недоступен:

- используйте свернутую секцию `Fallback (no Business Text plugin)`;
- она показывает flatten topology table из `/control/topology` через Infinity;
- активацию делайте через curl/API-клиент/внешний runbook.

---

## Безопасность

- `/control` не должен быть публичным.
- Доступ только из management-сети/VPN/loopback.
- Токен хранить как секрет (лучше secure settings datasource или secret manager).
- Держать `/metrics` и `/control` строго раздельно (как уже сделано в backend).
