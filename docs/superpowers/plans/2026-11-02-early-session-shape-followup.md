# Форма начала сессии — доработки после повторного замера (план)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Цель:** закрыть побочные эффекты, найденные повторным замером на `dfd8b876` (отчёт scratchpad `early-shape/REPORT2.md`):
нарезка начала сессии на всех h1/h2-путях (cover-кадры — только с паддингом), без нарезки от клиента на xhttp
packet-up, проверка частоты cover-кадров, разбор 9-байтных хвостов записей у сервера на h2.

**Архитектура:** планировщик `outline-wire::early_shape` получает признак «cover разрешены»; клиент и сервер создают
формирователь для h1/h2 независимо от паддинга, а куски на пути без паддинга уходят обычными сообщениями `Binary` без
обёртки. Клиент не режет c→s, если xhttp работает в режиме packet-up.

## Global Constraints

- Решения владельца (2026-11-02): нарезка — на всех TCP-сессиях h1/h2 (с паддингом и без); cover-кадры — только при
  включённом паддинге; на xhttp packet-up клиент не режет начало (s→c режется как прежде); h3 и UDP не трогаются.
- Провод не меняется: на пути без паддинга нарезка = больше обычных сообщений `Binary`; получатели читают TCP как поток
  (наш сервер, старые серверы, Xray).
- Размеры и окно — как в `docs/superpowers/specs/2026-11-02-early-session-shape-design.md` (c→s > 900 → 300..=850;
  s→c > 1500 → 600..=2800; окно 6..=10 сообщений / 16..=24 КиБ; cover 1..=2 по 40..=100 с вероятностью 1/2 на сессию).
- Комментарии — по-английски; документация — парами EN/RU; тесты — в `tests/` рядом с модулем.
- `cargo fmt` только `-p` по пакетам CI; `vendor/` и `macos/` не трогать; коммит — только по команде владельца,
  `git commit -- <пути>`; параллельно в main работает другой агент.
- Гейт как в CI + Linux в docker; после коммита — повтор замера на стенде.

---

### Task A: Нарезка на путях без паддинга (клиент и сервер)

**Files:** `crates/outline-wire/src/early_shape.rs` (+ tests), `crates/outline-transport/src/carrier_padding.rs`
(`shaped_messages`), `crates/outline-transport/src/tcp_transport/writer/transport.rs`, `crates/outline-transport/src/frame_io_ws.rs`,
`bins/outline-ss-rust/src/server/transport/carrier_padding.rs` (`shape_eligible`, `shaped_messages`),
`bins/outline-ss-rust/src/server/transport/tcp.rs`, `bins/outline-ss-rust/src/server/transport/vless/tcp.rs`, docs
`docs/PADDING{,.ru}.md`, CHANGELOG обоих бинарей EN/RU.

**Interfaces:**
- `EarlyShaper::new(direction, covers_allowed: bool, draw)` — при `covers_allowed == false` план никогда не содержит covers.
- `shaped_messages(scheme, shaper, frame, rng)` при выключенной схеме возвращает куски как есть (без обёртки паддинга)
  и без cover-кадров.
- Сервер: `shape_eligible(protocol) -> bool` (только протокол: Http1/Http2/XhttpH1/XhttpH2), формирователь создаётся
  для всех таких сессий; `covers_allowed` для сервера всегда `false` (как сейчас).
- Клиент: формирователь создаётся при `shape` (h1/h2), `covers_allowed = padding.scheme.is_enabled()`.

- [ ] Тесты (сначала падают): планировщик с `covers_allowed=false` не выдаёт covers ни в одной из 400 сессий;
  `shaped_messages` с выключенной схемой: сумма кусков = кадр, ни одного кадра паддинга (байты кусков — срезы исходника);
  сервер `shape_eligible(Http1)` = true и без паддинга; e2e на пути без паддинга (`ws_h1`, SS и VLESS) с первой записью
  6000 B — эхо совпадает.
- [ ] Реализация по интерфейсам выше; обновить вызовы `EarlyShaper::new`.
- [ ] Документация: в `PADDING.md`/`.ru.md` раздел «Early-session shaping» — нарезка на всех h1/h2, cover только с
  паддингом; CHANGELOG `Unreleased`/`Changed` EN/RU обоих бинарей.

### Task B: Без нарезки от клиента на xhttp packet-up

**Files:** call-sites, где вычисляется `shape` (`bins/outline-ws-rust/src/proxy/tcp/failover.rs`, `crates/outline-tun/src/tcp/engine/connect.rs`,
`crates/outline-uplink/src/probe/transport.rs`, `crates/outline-transport/src/frame_io_ws.rs::from_ws_frames`),
`crates/outline-transport/src/ws_stream.rs` (если нужен хелпер), тесты.

**Interfaces:** `TransportStream::shapes_client_start(&self) -> bool` = `!self.is_h3()` и не xhttp в режиме packet-up
(через существующий `xhttp_active_submode()`); все call-sites используют его вместо `!is_h3()`.

- [ ] Тест хелпера: Http1/H2 → true; H3 → false; Xhttp packet-up → false; Xhttp stream-one на h1/h2 → true.
- [ ] Реализация и замена на call-sites.

### Task C: Частота cover-кадров (проверка тестом)

**Files:** тесты `crates/outline-transport/src/frame_io_ws.rs` / `tcp_transport/writer` (существующие файлы тестов).

- [ ] Тест: 200 сессий `WsFrameSink` (VLESS) с включённым паддингом и h1, первая запись 1964 B; посчитать сессии, где
  перед первым куском есть pad-only кадры (декодировать через `PaddingDecoder`, cover = кадр с `real_len = 0`).
  Ожидание: 70..=130 из 200. То же для SS через `WsWriteTransport` с учётом склейки удержанного заголовка: первое
  сообщение = заголовок + cover (проверить, что cover в нём есть примерно в половине сессий).
- [ ] Если частота заметно ниже — найти причину и исправить (отдельный шаг с ревью); если в норме — записать, что
  в замере это артефакт сопоставления.

### Task D: Хвосты 9 байт после записей 16384 у сервера на h2 (разбор, без правки кода)

Факт: сервер на h2 при больших загрузках шлёт пары записей 16401 + 26 (кадр DATA 16384 + заголовок 9 > записи TLS
16384). Эталон браузера: у реальных серверов из 382 полных записей только 4 продолжаются записью 26 B.

- [ ] Найти, кто задаёт размер кусков, которые сервер отдаёт в h2 (WS-сообщения downlink, буфер relay, hyper/h2
  `max_frame_size` пира), и где их можно ограничить без правки `vendor/` (например, резать downlink-сообщения на h2 до
  ~16 KiB − 9 − накладные, или собирать кадры так, чтобы заголовок шёл в одной записи с данными).
- [ ] Оценить цену (пропускная способность, лишние кадры) и предложить вариант владельцу. Код не менять.

### Task E: Сообщения downlink на h2 влезают в одну TLS-запись (реализация варианта (a) из Task D)

Решение владельца (2026-11-02): делать до коммита доработок. Причина хвостов — кадр DATA 16384 + заголовок 9 > запись
TLS 16384. Сообщения на h2 больше 16375 байт h2 режет на кадры по 16384. Relay SS читает до `MAX_CHUNK_SIZE` (64 КиБ)
и шлёт весь шифротекст одним сообщением. VLESS шлёт до `GREEDY_DRAIN_TARGET` (16383) плюс заголовок WS и паддинг.

**Files:** `crates/outline-wire/src/padding.rs` (аксессор `max_pad`), `bins/outline-ss-rust/src/server/transport/carrier_padding.rs`
(`h2_plaintext_cap`), `bins/outline-ss-rust/src/server/relay.rs` (`UpstreamSink::plaintext_cap`, нарезка буфера),
`bins/outline-ss-rust/src/server/transport/tcp.rs` (`ChannelSink`), `bins/outline-ss-rust/src/server/transport/vless/tcp.rs`,
`bins/outline-ss-rust/src/server/transport/vless_mux/tcp_sub.rs` (если mux ходит по h2), тесты рядом, CHANGELOG сервера EN/RU,
`docs/PADDING{,.ru}.md` (раздел про маркеры).

**Interfaces:**
- `H2_DATA_PAYLOAD_MAX = 16384 - 9 = 16375`.
- `carrier_padding::h2_plaintext_cap(protocol, scheme, inner_overhead) -> Option<usize>`: `Some` только для `Http2`/`XhttpH2`.
  Это бюджет открытого текста, при котором сообщение целиком (заголовок WS 4 + обёртка паддинга 4 + max_pad + накладные
  протокола: SS chunk 34, VLESS 0, mux — заголовок mux) не больше 16375.
- `UpstreamSink::plaintext_cap(&self) -> Option<usize>` (по умолчанию `None`). Relay SS режет прочитанный буфер на куски
  `<= cap` и каждый шифрует и шлёт отдельно. На h1/h3/сокете поведение прежнее.
- VLESS: цель drain и размер одного сообщения `min(GREEDY_DRAIN_TARGET, cap)`; лишнее идёт следующими сообщениями.

- [ ] Тесты: `h2_plaintext_cap` (None на Http1/H3, бюджет + накладные <= 16375 с паддингом и без); relay с sink,
  у которого cap = N: на вход 64 КиБ — каждый шифротекст <= N + 34, расшифровка даёт исходник; VLESS — каждое
  сообщение <= бюджета.
- [ ] Реализация; окно нарезки начала сессии не ломается (куски там и так меньше).
- [ ] Проверка после выкатки — повтор замера: пары 16401 + 26 у сервера на h2 практически исчезают (эталон 4/382).
