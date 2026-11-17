# Серверный HTTP/3: transport parameters и CID как у Caddy (этап 1)

План для публичного H3-листенера `outline-ss-rust` (`bins/outline-ss-rust/src/server/h3/`).
Цель — убрать отличия серверных QUIC transport parameters (TP) и длины CID от Caddy
(quic-go), которые закрываются опциями уже имеющегося патча vendored `quinn-proto`
и нашим кодом. Новых патчей vendored-кода нет.

Эталон сверен по исходникам quic-go `master` (скачаны 2026-11-17: `connection.go`,
`internal/wire/transport_parameters.go`, `internal/protocol/params.go`,
`internal/wire/datagram_frame.go`) и по памяти аудита 2026-11-10.

## Что не трогаем

- Mesh-кластер: свой `Endpoint::server` и свой `TransportConfig`
  (`server/cluster/mesh/endpoint.rs`, `server/cluster/mesh/tls.rs`). Правки только в
  `build_h3_server` / `build_h3_transport_config`, mesh их не вызывает.
- Клиент: `crates/outline-transport` строит свой `TransportConfig` по профилям
  (`quic/tp_profile.rs`). Серверный код он не использует, его отпечатки не меняются.
- Этап 2: id GREASE-параметра, Version Negotiation, H3 SETTINGS (GREASE, нули
  WebTransport, `MAX_FIELD_SECTION_SIZE`), окна, число потоков, idle.
- `server/bootstrap/tls.rs` и `axum.rs` (на них работает ветка `tcp-caddy-emulation`).

## Было / станет / Caddy

| Что | Сейчас (quinn по умолчанию) | Станет | Caddy (quic-go) |
|---|---|---|---|
| Длина серверного CID (long header SCID, `0x0f`, NEW_CONNECTION_ID) | 8 | 4 | 4 (`DefaultConnectionIDLength`) |
| Порядок TP | случайный (перемешивание quinn) | `GREASE,05,06,07,04,08,09,01,03,[0b],[0a],[0c],02,00,[0e],0f,[10],[20]` | тот же |
| GREASE-параметр | есть, id `31·N+27` с N до 2^62, длина 0–15 | без изменений (этап 2) | есть, N — один байт, длина 0–15 |
| `min_ack_delay` (`0xff04de1b`) | шлётся | не шлётся | не шлётся |
| `grease_quic_bit` (`0x2ab2`) | шлётся | не шлётся | не шлётся |
| `max_ack_delay` (`0x0b`) | 25, не пишется | 26 | 26 (25 + гранулярность 1 мс) |
| `active_connection_id_limit` (`0x0e`) | 5 | 4 | 4 (`MaxActiveConnectionIDs`) |
| `max_datagram_frame_size` (`0x20`) | 65535, всегда | 16383 при `udp_datagrams = true`, иначе нет | 16383 при `EnableDatagrams`, иначе нет |
| `H3_DATAGRAM` (`0x33`) в SETTINGS | 1, всегда | 1 при `udp_datagrams = true`, иначе нет | при `EnableDatagrams` |
| `max_udp_payload_size` (`0x03`) | 1452 | без изменений | 1452 (`MaxPacketBufferSize`) |
| `stateless_reset_token`, `original_destination_connection_id`, `initial_source_connection_id` | шлются | без изменений | шлются |
| `disable_active_migration` (`0x0c`) | не шлётся (миграция включена) | без изменений | сервер не шлёт |

`ack_delay_exponent` (`0x0a`) = 3 не пишут ни quinn, ни quic-go. `retry_source_connection_id`
(`0x10`) не появляется: Retry у нас выключен.

## Механика

1. Серверный гейт `bins/outline-ss-rust/src/server/h3/vendored.rs` получает одну функцию
   `apply_caddy_transport_parameters(transport, udp_datagrams)`. Она вызывает патч-API:
   - `transport_parameter_order(Fixed([0x1b, 0x05, 0x06, 0x07, 0x04, 0x08, 0x09, 0x01, 0x03, 0x0b, 0x0a, 0x0c, 0x02, 0x00, 0x0e, 0x0f, 0x10, 0x20]))`.
     `0x1b` — место GREASE-параметра (`TransportParameterId::ReservedTransportParameter`
     в патче). Остальные известные quinn id (`0x0d`, `0x2ab2`, `0xff04de1b`) идут после
     списка, но не пишутся;
   - `advertise_min_ack_delay(false)`;
   - `max_ack_delay_ms(26)`. Этот же параметр задаёт локальный таймер отложенного ACK
     сервера: 26 мс вместо 25;
   - `advertised_active_connection_id_limit(Some(4))`;
   - при `udp_datagrams`: `advertised_max_datagram_frame_size(Some(16383))`, буферы
     датаграмм 1 МиБ как сейчас; без `udp_datagrams`: `datagram_receive_buffer_size(None)`,
     `0x20` не шлётся, клиент не может слать датаграммы.

   Список в CI-проверке «vendored quinn-proto API only behind gate modules» уже
   пропускает серверный гейт; меняется только комментарий в `.github/workflows/ci.yml`
   и абзац в `AGENTS.md` о том, что серверу через гейт доступны и TP-опции.
2. `build_h3_server` (`server/h3/mod.rs`), upstream-API без гейта:
   - `endpoint_config.grease_quic_bit(false)`. quinn ставит случайный «фиксированный бит»
     в своих пакетах, только если его объявил пир (`packet_builder.rs:127`), а наши
     клиенты `0x2ab2` не шлют, так что наблюдаемая разница — только в TP;
   - `endpoint_config.cid_generator(|| Box::new(RandomConnectionIdGenerator::new(4)))`.
3. `build_h3_transport_config` и `build_h3_quinn_server_config` получают `udp_datagrams`
   (`config.h3_udp_datagrams`), в том числе из перезагрузчика сертификатов
   `spawn_h3_cert_reloader`. `h3_server_builder(udp_datagrams)` вызывает
   `enable_datagram(udp_datagrams)`; вызов из `server/h3/http.rs` передаёт
   `ctx.udp_datagrams`.

## Оценки

### CID 4 байта

- Маршрутизации по CID у нас нет: один процесс, один сокет, без `SO_REUSEPORT` и eBPF
  (поиск по `cid_generator`, `ConnectionIdGenerator`, `reuse_port` в `bins/`, `crates/`,
  `android/rust` пуст). quinn разбирает short header по длине CID своего генератора.
- Коллизии: `RandomConnectionIdGenerator` генерирует 2^32 значений, endpoint перегенерирует
  CID, если он уже занят. При ~10^3 соединений по 4 CID на каждое вероятность совпадения
  на одну генерацию ~10^-6, и совпадение всё равно отбрасывается.
- Stateless reset: токен выводится из CID ключом `reset_key`; длина CID на это не влияет.
- Рестарт сервера: пакеты старых соединений и до правки не находили соединения (состояние
  терялось вместе с процессом), так что 8-байтовые DCID от старых соединений ничего не
  ломают.
- Старые клиенты: длину CID сервера клиент берёт из long header и в TP не проверяет её
  длину; quinn, quic-go и браузеры принимают 0–20 байт. Совместимость не меняется.

### MTU и датаграммы

Short header клиент→сервер несёт DCID сервера, он станет на 4 байта короче. Клиент
считает место под датаграмму через `quinn::Connection::max_datagram_size()`
(`crates/outline-transport/src/h3/datagram.rs:112`), который вычитает фактическую длину
DCID, — места на uplink станет на 4 байта больше (запас был ~10 байт, см. замер
2026-10-31). Константы с зашитой длиной CID в нашем коде нет (`pmtu_cache.rs` хранит
размер UDP-нагрузки, `H3_MAX_UDP_PAYLOAD_SIZE` = 1452 тоже). Потолок туннеля 1440 —
предел UDP-нагрузки, на CID не завязан. Downlink не меняется: там DCID клиента.

`max_datagram_frame_size` 65535 → 16383: датаграмма у нас не больше ~1440 байт, лимит
16383 её не ограничивает. С `udp_datagrams = false` `max_datagram_size()` у клиента
станет `None`, и клиент перестанет предлагать `x-outline-udp-datagram` — раньше он
предлагал, а сервер отказывал. UDP по-прежнему идёт в потоке.

### Прочее

- `min_ack_delay` нужен только для расширения ACK frequency; ни сервер, ни клиент
  `ack_frequency_config` не включают.
- `active_connection_id_limit` 5 → 4: клиент выдаёт серверу не больше 4 своих CID.
  Профили Chrome и Safari используют пустой SCID и NEW_CONNECTION_ID не шлют.

## Решение владельца: по умолчанию или опцией

Рекомендация — новое поведение по умолчанию, без ключа конфигурации:
- все изменения меняют только то, что видит пир после рукопожатия, и длину CID; рабочие
  параметры туннеля (окна, потоки, idle, MTU) не трогаются;
- ключ означал бы второй путь в тестах и в документации, а значения «как у quinn» нам
  не нужны: это и есть отпечаток, от которого уходим;
- откат — сборка предыдущего бинаря, конфиг не меняется.

Вариант с ключом: `[server.h3] quic_profile = "caddy" | "quinn"`, по умолчанию `"caddy"`.
Конфиг с ключом не запустится на старом бинаре (`deny_unknown_fields`), как с
`mtu_first_probe`.

## Тесты

Тесты покрывают `server/h3/mod.rs`, поэтому лежат в новом
`bins/outline-ss-rust/src/server/h3/tests/mod.rs` и подключаются из `mod.rs` строкой
`#[cfg(test)] mod tests;`. Рядом уже есть `tests/http.rs` для `http.rs`, его не трогаем.

Способ захвата TP сервера: клиент quinn на loopback с обёрткой над
`quinn::crypto::rustls::QuicClientConfig`, которая реализует `crypto::ClientConfig` /
`crypto::Session` делегированием и копирует байты, приходящие в `read_handshake`
(CRYPTO-поток Initial и Handshake). Из них тест достаёт сообщение EncryptedExtensions
(тип 8), расширение `0x39` и разбирает пары `(id, value)`. При необходимости
`quinn-proto` добавляется в `[dev-dependencies]` (тип `TransportParameters` в сигнатуре
`Session::transport_parameters`).

1. `server_transport_parameters_follow_quic_go_order` — id после GREASE идут в порядке
   quic-go; первый id имеет вид `31·N+27`.
2. `server_omits_min_ack_delay_and_grease_quic_bit` — нет `0xff04de1b` и `0x2ab2`.
3. `server_advertises_quic_go_ack_delay_and_cid_limit` — `0x0b` = 26, `0x0e` = 4.
4. `server_connection_id_is_four_bytes` — длина `0x0f` (= SCID long header, quinn сверяет
   их по RFC 9000 §7.3) равна 4.
5. `datagrams_follow_udp_datagrams` — при `true`: `0x20` = 16383 и `H3_DATAGRAM = 1` в
   SETTINGS; при `false`: ни того, ни другого. SETTINGS читаются сырым QUIC-клиентом:
   первый uni-поток сервера, тип `0x00`, кадр SETTINGS.

Существующие тесты `server/tests/h3.rs`, `cross_repo_ss_h3_datagram.rs` и e2e проверяют,
что ws_h3/xhttp_h3 и датаграммы продолжают работать с клиентом.

## Документация

- `bins/outline-ss-rust/README.md` / `README.ru.md`: раздел про HTTP/3 — что сервер
  объявляет и что `udp_datagrams = false` теперь убирает `0x20` и `H3_DATAGRAM`.
- `bins/outline-ss-rust/CHANGELOG.md` / `CHANGELOG.ru.md`, раздел Unreleased / Changed.
- `AGENTS.md`: абзац о гейтах `quinn-proto`; комментарий CI-проверки.
- `PATCHES*.md` не меняются: vendored-код не правится.

## Гейт перед коммитом

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
cargo check -p outline-ss-rust --no-default-features
cargo check -p outline-ws-rust --no-default-features
cargo check -p outline-ui --no-default-features
cargo test --workspace --exclude sockudo-ws
RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls --test 'e2e_*' -- --test-threads=1
(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
```

Коммиты — только по команде владельца, `git commit -- <paths>`, без выкатки на узлы.
Выкатка (позже, отдельным решением): только серверы, по одному узлу; клиенты не
пересобираются.
