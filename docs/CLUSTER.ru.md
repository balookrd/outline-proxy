# Mesh-кластер серверов (anycast-вход + shard-relay на home)

*English version: [CLUSTER.md](CLUSTER.md)*

Как несколько серверов `outline-ss-rust` работают единым кластером: клиент
`outline-ws-rust` может входить через **любой** сервер, но сессия всегда
закреплена за своим **home**-сервером. Не-home сервер (**edge**), на который
клиент попал, форвардит ещё зашифрованные application-байты на home-сервер по
QUIC-каналу **mesh**, маршрутизируя по shard-id, зашитому в session_id. Если
home недоступен или mesh слишком медленный — система деградирует к новой
сессии, ровно как сегодня, когда серверы ничего не знают друг о друге.

Документ покрывает только carrier'ы VLESS и combined-SS; раздельный SS вне
области кластера.

## Почему «миграция сессии на другой сервер» — не буквальная

Припаркованное на сервере состояние — это *живое* upstream-соединение:
установленный TCP-сокет к target с его sequence numbers, source-адресом и
состоянием в ядре (`ParkedTcp`), либо привязанный `UdpSocket`
(`ParkedVlessUdpSingle`). Ничего из этого нельзя сериализовать и поднять на
другой машине. Поэтому сессия никуда не переезжает. Она **остаётся на
home-сервере**, а anycast'ом становится carrier (клиентский транспорт
WebSocket / HTTP3 / QUIC): он может приземлиться на любой edge, который
релеит байты обратно на home. С точки зрения клиента это выглядит как «park на
сервере A, unpark на сервере B»; физически состояние всё время жило на home.

## Роли

- **home** — сервер, владеющий сессией: upstream-соединение к target,
  SS/VLESS crypto-state и парковка resumption (`OrphanRegistry`). Выбирается
  один раз, при первом подключении, и закреплён на всю жизнь сессии.
- **edge** — сервер, терминировавший клиентский carrier. Может *быть* home
  (всё локально) или быть другим сервером (тогда релеит на home).
- **mesh** — аутентифицированный QUIC-канал edge → home, переносящий ещё
  зашифрованные application-байты.
- **shard-id** — 4-битный идентификатор home, зашитый в session_id.

## Shard-id в session_id

Resumption-`SessionId` — 16 байт, генерируется home при первом handshake и
возвращается в `X-Outline-Session` (HTTP/WS) или VLESS-addon `0x10`. Сегодня
это чистый CSPRNG без структуры. Кластер зашивает в него идентичность home:

```
SessionId = obfuscate_k( shard_id (4 бита) || nonce (124 бита) )
            └─ keyed PRF/CTR под общим cluster_routing_key,
               чтобы id на проводе оставался полностью случайным
```

- **4 бита → до 16 серверов.** Остаётся 124 бита nonce — с огромным запасом
  против перебора resume-id.
- **обфускация** превращает структурированное значение в wire-случайное. Shard
  — это *routing-hint, не secret*, но его структура не должна быть видна
  DPI/fingerprint-наблюдателю, поэтому он шифруется общим для кластера
  `cluster_routing_key`. Любой член кластера де-обфусцирует и читает shard за
  O(1); общей routing-таблицы для id нет.
- Encode/decode живут в `outline-wire` (новый модуль `cluster`), чтобы
  серверный бинарь и mesh-путь использовали одну реализацию.

Бит `SsPathKind` combined-SS (TCP vs UDP) сидит в XHTTP-URL / WS-сегменте
`/{token}`, **не** в 16-байтном resume-id, и за эти биты не конкурирует.

## Решение маршрутизации на edge

Edge обязан узнать shard **до** любого SS/VLESS-payload. Shard доступен в
метаданных carrier'а, приходящих раньше тела:

| Carrier | Где shard | Когда виден |
| --- | --- | --- |
| WS / H3 / XHTTP resume | заголовок `X-Outline-Resume: <hex>` | при апгрейде, до тела |
| VLESS raw QUIC resume | addon `0x11 RESUME_ID` (16 байт) | в первом VLESS-кадре |
| Первое подключение (нет resume) | — | edge *и есть* home: обрабатывает локально, генерит session_id с `shard = self` |

```
            client (ws-rust)
          resume? X-Outline-Resume / addon 0x11
                      │ carrier (WS/H3/QUIC)
                      ▼
                  ┌────────┐
                  │  EDGE  │  decode_shard(session_id)
                  └───┬────┘
        shard==self   │   shard!=self
        ┌─────────────┘└──────────────┐
        ▼                              ▼
  LOCAL (как сейчас)          MESH RELAY на home[shard]
  accept→crypto→park          терминирует carrier, льёт
  →upstream→target            app-байты по mesh QUIC
                                       │
                                       ▼
                              HOME[shard]
                              accept / crypto / park / unpark
                              upstream → target  (state живёт только тут)
```

**Первое подключение выбирает home.** Клиент без resume-id попадает на
какой-то edge, тот обрабатывает локально и возвращает session_id со своим
shard. Все последующие resume этого клиента — через любой edge — указывают на
этот home. То есть home выбирается там, где клиент впервые поднял сессию,
обычно ближайший рабочий сервер.

## Mesh-транспорт (граница релея = сырые application-байты)

Edge терминирует **только carrier** (WS-фреймы / H3-stream / QUIC),
извлекает application-байты (ещё зашифрованный SS/VLESS-поток как есть) и
туннелирует их на home. **Crypto и upstream-соединение живут только на home.**
Edge никогда не держит ключей и не видит plaintext.

- **Канал:** длинноживущие **QUIC**-соединения между членами кластера,
  аутентифицированные mTLS (aws-lc-rs — единственный crypto-provider в графе;
  quinn уже в зависимостях). Одно QUIC-соединение на пару пиров, мультиплекс
  множества сессий.
- **Один QUIC-стрим на сессию.** Это и есть главная причина выбора QUIC вместо
  самописного фрейминга поверх mTLS-TCP: per-stream flow-control даёт честный
  backpressure бесплатно и убирает head-of-line blocking между сессиями —
  ровно тот класс отказов, что кусал TUN-pump. Никакого слепого коалесинга.

Control-сообщения mesh-стрима:

```
OPEN  { session_id, carrier_kind, client_meta (resume-заголовки / addons), peer_addr_hint }
DATA  { dir: up | down, bytes }          // application-байты, оба направления
CLOSE { reason: fin | abort | budget }   // graceful FIN / RST / превышен health-budget
```

Для VLESS mux весь мультиплекс паркуется атомарно, поэтому релей несёт весь
мультиплекс по одному mesh-стриму и никогда не дробит sub-connections по
стримам.

### Health-budget («медленный сосед → рвём»)

Поскольку члены кластера в разных странах, хоп edge → home всегда длинный.
Поэтому mesh — best-effort, а не надёжный бэкбон:

- Edge меряет *прогресс* per-session: `no_progress_ms` (есть in-flight байты,
  но от home не приходит DATA) и handshake-RTT mesh.
- Превышение `mesh_relay_budget_ms` заставляет edge закрыть клиентский carrier
  обычным resume-miss/close, и клиент стартует **новую сессию локально на
  edge** (edge становится новым home; осиротевший park на медленном home
  истечёт по TTL).
- Бюджет про *прогресс*, а не про абсолютный RTT — высокий RTT между странами
  ожидаем и допустим; зависший релей — нет.

## Home: park/unpark без изменений

Поскольку граница релея — ещё зашифрованный байтовый поток, релеенная сессия
для home **неотличима** от прямого клиентского carrier. `OrphanRegistry`,
варианты `Parked` и resume wire-protocol работают **без правок**. Разница лишь
в том, что «клиентский транспорт» — это mesh-стрим от edge, а не сокет
клиента.

«Park на A, unpark на B» при этом получается даром: клиент уходит с edge A
(или edge A умирает), home паркует, как при любом обрыве carrier; клиент
приходит на edge B с тем же session_id, edge B открывает свежий mesh-стрим к
home, и home делает unpark в этот стрим.

## Семантика отказов

| Отказ | Поведение | Сессия |
| --- | --- | --- |
| edge умер | клиент failover на другой edge (существующая uplink-логика); тот же session_id → тот же home → unpark | **жива** |
| mesh слишком медленный | edge рвёт по health-budget → новая сессия на edge | теряется (приемлемо) |
| home умер | shard указывает на мёртвый сервер; edge не дозвонился по mesh → resume-miss → новая сессия | теряется (= как сейчас) |
| shard неизвестен (сервер выведен) | edge трактует как home-down → новая сессия | теряется |

## Безопасность

- **mesh auth:** mTLS между членами кластера (общий CA / pinned-сертификаты);
  чужой не вклинит relay-стрим.
- **Топология не раскрывается:** при home-down или чужом owner edge отвечает
  обычным resume-miss (как существующий owner-mismatch путь остаётся тихим).
  Наблюдатель не отличит «нет такого шарда» от «home лежит».
- **Shard обфусцирован** ключом кластера, поэтому session_id для DPI остаётся
  wire-случайным.
- **Edge не видит plaintext** (граница = зашифрованные application-байты),
  поэтому компрометация edge не вскрывает трафик чужих сессий — только
  метаданные (session_id; target внутри SS/VLESS-потока, который edge не
  парсит).

## Конфигурация

Сервер (`outline-ss-rust`):

```toml
[cluster]
enabled = true
shard_id = 7                       # 0..15, уникален в кластере
cluster_routing_key = "<base64>"   # общий ключ обфускации shard в session_id
mesh_listen = "[::]:9443"          # mTLS QUIC-listener для входящего relay
mesh_ca = "..."; mesh_cert = "..."; mesh_key = "..."
mesh_relay_budget_ms = 4000        # бюджет прогресса: стоит дольше → рвём
peers = [
  { shard = 1, addr = "..." },
  { shard = 7, addr = "self" },
  # ...
]
```

Клиент (`outline-ws-rust`): **в идеале без изменений.** Кластер прозрачен для
клиента — он и так резюмит на тот же uplink с тем же session_id, и путь
failover между edge уже есть. Anycast-вход и релей для него невидимы.

## Bounded resources

По инварианту workspace «bounded resources» у каждого долгоживущего mesh-объекта
есть явный лимит:

- mesh-стримы: cap на активные релеи per-peer и глобально, с LRU-eviction.
- релеенная сессия наследует TTL home-парковки; у edge также собственный
  idle-timeout.
- health-budget — верхняя граница висящего релея.

## Открытые риски

1. **Mesh data-plane не покрыт юнит-тестами** (как TUN-pump) — нужен e2e плюс
   sha256-сверка больших передач на боевом трафике; держать `git revert`
   наготове.
2. **Двойной хоп через страны** повышает RTT для долгих bulk-передач;
   health-budget защищает от зависаний, но не от медленности. Возможный
   follow-up: дать клиенту дозваниваться до home напрямую, когда тот достижим,
   минуя edge-relay — но это client-side routing поверх mesh, отдельная фаза.
3. **VLESS mux** паркуется атомарно; релей обязан нести весь мультиплекс по
   одному mesh-стриму, не дробя его, иначе partial-resume сломается.
