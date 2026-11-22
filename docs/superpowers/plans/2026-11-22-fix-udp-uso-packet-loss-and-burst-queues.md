# План исправления потерь UDP-пакетов в USO-батчере и burst-дропов H3-датаграмм

## Цель
Устранить постоянную потерю **1.5–4.2%** UDP-пакетов на SS2022 при включённом `TUN_F_USO` (`udp_gso = true`) и подавить стартовые burst-переполнения `queue_full` / `outbound_queue_full` на ARM64-шлюзах (`gw-1` / `gw-2`), из-за которых тормозит YouTube 4K на ТВ.

## Архитектурные решения
1. **Разделение TX и RX состояния SS2022 без `tokio::sync::Mutex`** — убираем блокировку downlink-дешифрования исходящими ACK (`send_packet`) и делаем `decrypt_udp_bytes` полностью синхронным (без `.await`).
2. **Явный cancel-safe `try_read_packet` вместо `.read_packet().now_or_never()`** — полностью исключаем класс багов, когда отмена async-future после `recv_datagram().await` теряет уже извлечённую датаграмму.
3. **Разгрузка горячего пути `spawn_flow_reader` и расширение burst-очередей** — убираем лишние `flows.read().await` + `flow.lock().await` с каждого batch'а и даём достаточно запаса под стартовый BBR-всплеск 4K без увеличения connection-level лимита памяти (`CONNECTION_QUEUE_BYTES = 4 MiB` остаётся прежним).

---

## Порядок работ

### Шаг 1. Разделить TX/RX состояние SS2022 и убрать `tokio::sync::Mutex` (`outline-transport`)
**Файлы:**
- `crates/outline-transport/src/udp_transport.rs`
- `crates/outline-transport/src/tests/udp_transport.rs`

**Изменения:**
- Заменить `ss2022: Option<tokio::sync::Mutex<Ss2022UdpState>>` на структуру с `client_session_id: u64`, `next_client_packet_id: AtomicU64` и `rx: parking_lot::Mutex<Ss2022UdpRxState>`.
- В `send_packet`: брать `packet_id = state.next_client_packet_id.fetch_add(1, Ordering::Relaxed)` без блокировок.
- Сделать `decrypt_udp_bytes` синхронной: расшифровка до лока, `rx.lock()` только на проверку `server_session_id` и `replay_filter`.
- Вынести общую декодирующую логику `decode_channel_datagram`.
- Обновить доступ к `client_session_id` в тестах `udp_transport.rs`.

### Шаг 2. Добавить cancel-safe синхронный `try_read_packet` и заменить `.now_or_never()` (`outline-transport` + `outline-tun`)
**Файлы:**
- `crates/outline-transport/src/frame_io.rs`
- `crates/outline-transport/src/frame_io_ws.rs`
- `crates/outline-transport/src/h3/datagram.rs`
- `crates/outline-transport/src/udp_transport.rs`
- `crates/outline-transport/src/vless/udp_mux_core.rs`
- `crates/outline-transport/src/vless/udp_mux.rs`
- `crates/outline-tun/src/udp/lifecycle.rs`

**Изменения:**
- Добавить `DatagramChannel::try_recv_datagram(&self) -> Result<Option<Bytes>>` (реализовать для `WsDatagramChannel` и `H3DatagramChannel`).
- Добавить `UdpWsTransport::try_read_packet`, `UdpSessionTransport::try_read_packet`, `VlessUdpMuxCore::try_read_packet`, `VlessUdpSessionMux::try_read_packet`.
- В `spawn_flow_reader` заменить `transport.read_packet().now_or_never()` на `transport.try_read_packet()?` и удалить `futures_util::FutureExt as _`.

### Шаг 3. Оптимизация горячего пути `spawn_flow_reader` и расширение burst-очередей
**Файлы:**
- `crates/outline-tun/src/udp/lifecycle.rs`
- `crates/outline-tun/src/udp/types.rs`
- `crates/outline-wire/src/h3_datagram.rs`
- `crates/outline-transport/src/vless/udp_mux_core.rs`

**Изменения:**
- Передавать `uplink_name: Arc<str>` в `spawn_flow_reader`, кэшировать `udp_flow_counters` до цикла, убрать ежепакетные `flows.read().await` + `h.lock().await`.
- Квантовать `bump_last_seen_if_current` по локальному таймеру `(idle_timeout / 4).min(Duration::from_secs(1))` в reader и uplink-задаче.
- Увеличить `REGISTRATION_QUEUE_BYTES` с `512 * 1024` до `1024 * 1024`.
- Увеличить буфер `downlink_tx` в `VlessUdpMuxCore` с `256` до `1024`.
- Увеличить `UDP_OUTBOUND_QUEUE_CAP` с `64` до `256`.

### Шаг 4. Тесты (TDD / регрессия)
- `crates/outline-transport/src/tests/udp_transport.rs`: `MockChannel::try_recv_datagram`, тесты `try_read_packet_drains_ss2022_burst_without_dropping_under_concurrent_sends` и `try_read_packet_skips_padding_cover_frames_and_returns_none_when_empty`.
- `crates/outline-transport/src/h3/tests/datagram.rs`: тест `try_recv_datagram_drains_demux_and_stream_fallback_without_blocking`.
- `crates/outline-tun/src/udp/tests/lifecycle.rs`: проверить возможность теста USO-коалесцинга с `try_read_packet`.

### Шаг 5. Проверка документации
- Проверить упоминания `512 KiB` / `64` / `256` в `README*.md` и `docs/*.md`, при необходимости обновить обе языковые версии синхронно.

### Шаг 6. Верификация и CI-гейт
- Точечные тесты (`outline-wire`, `outline-transport`, `outline-tun`).
- `cargo fmt --all` + откат `vendor/` при необходимости + `cargo fmt --check`.
- `cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings`.
- `cargo test --workspace --exclude sockudo-ws --exclude outline-windows`.
- Feature-matrix (`--no-default-features`).
- `RUN_E2E_FAILOVER=1 cargo test -p outline-client --features test-tls --test 'e2e_*' -- --test-threads=1`.
- `(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)`.
- Linux-кросс-сборка `cargo client-release-musl-aarch64`.
- Очистка `target/debug/` и `android/rust/target/`.
