# План: два хвоста серии «форма начала сессии»

Дата: 2026-11-04. Спека серии: `docs/superpowers/specs/2026-11-02-early-session-shape-design.md`
(п. 1.2 — заголовок ответа VLESS «перед первым ответным пакетом», в том числе для UDP).
Ревью 2026-11-04 нашло два незакрытых хвоста (оба LOW, не регрессии).

## Цели

1. **Сервер.** Заголовок ответа VLESS (`[VERSION, 0x00]`, 2 байта, после паддинга —
   фиксированный маркер около 21 байта) больше нигде не уходит отдельным сообщением
   (= отдельной TLS-записью). Сейчас так только на fresh-TCP пути.
2. **Клиент.** На h2-носителях uplink-сообщение больше 16375 байт после окна нарезки
   уходит несколькими сообщениями, каждое влезает в один h2 DATA одной TLS-записи.
   Зеркально серверному cap из `d9d071c6`.

Формат на проводе не меняется: обе стороны уже читают VLESS-ответ, ack-prefix/ORDR и
SS/VLESS-данные потоком, границы WS-сообщений смысла не несут. Новые серверы работают
со старыми клиентами и наоборот.

## Часть 1. Сервер: заголовок ответа VLESS вместе с первыми данными

Механизм fresh-TCP (`vless/tcp.rs::relay_vless_upstream_to_client`, аргумент
`response_header`): заголовок держится локально в релее, пишется перед первыми прочитанными
байтами апстрима **после** захвата в ring (в ring заголовок не попадает, при v2-replay
не переигрывается), на h2 лимит чтения уменьшается на длину заголовка, при закрытии без
данных заголовок уходит один перед Close.

### 1.1 VLESS-TCP resume (`vless/tcp.rs`, ветка `ResumeOutcome::Hit`)

- Без v1/v2 (клиент не просил ack-prefix): заголовок не шлём сразу, а передаём в релей
  `Some(header)` — ровно как на fresh-пути.
- С v1 и/или v2 клиент ждёт контрольные кадры (`consume_ack_prefix_with_timeout`) до
  отправки uplink-данных, поэтому держать их до первых данных апстрима нельзя (дедлок с
  протоколами «клиент говорит первым»). Вместо этого собираем одну преамбулу
  `header || ORSM(14) || ORDR(14 + replay)` и отправляем её через
  `capped_downlink_messages` (одно сообщение вне h2, на h2 — ровные куски ≤ cap). Клиент
  разбирает заголовок, ORSM и ORDR из одного буфера (`header_buf` / `pending_tail`).
- Ring восстанавливается как раньше; заголовок и кадры управления в него не пишутся.

### 1.2 VLESS mesh-relay на edge (`vless/tcp.rs::attach_mesh_upstream`)

- `Tcp` с ack-prefix: `header || ORSM` одним сообщением.
- `Tcp` без ack-prefix и `Mux`: заголовок уходит в релей (`Some(header)`), он склеит его с
  первыми байтами от home.

### 1.3 VLESS-mux fresh и resume (`vless/mod.rs::establish_vless_mux_upstream`)

У mux несколько писателей в один канал (по задаче-читателю на sub-conn плюс `send_end` из
обработчика кадров). Локальный `Option` не подходит. Вводим общий «одноразовый» заголовок
`HeldResponseHeader` (новый модуль `transport/held_header.rs`):

- `Arc` с `AtomicBool sent` и `tokio::sync::Mutex<Option<Bytes>>`;
- `send(tx, make_binary, padding, frame)`: быстрый путь, если `sent`; иначе под мьютексом
  клеит заголовок к кадру, шлёт, затем снимает заголовок и ставит `sent` (Release). Отправка
  под мьютексом сохраняет порядок: любой другой писатель увидит `sent` только после того,
  как сообщение с заголовком уже в канале. Заголовок снимается только после успешной
  отправки, поэтому отменённый `send` его не теряет (mpsc `send` cancel-safe);
- `pending_len()` — на h2 читатель sub-conn вычитает его из лимита чтения, чтобы первый
  кадр с заголовком не перерос cap.

`MuxState` получает поле `header: Option<Arc<HeldResponseHeader>>`; все места отправки
вниз (`run_tcp_reader`, `run_udp_reader` — данные и End, `send_end`) идут через него.
На home (relayed mux, `MuxAccounting::OnTheEdge`) поле `None`: заголовок шлёт edge.
Resume-ветка mux строит новый заголовок для нового носителя.

### 1.4 VLESS-UDP: fresh, resume и mesh (`vless_udp.rs`)

Один писатель (релей), поэтому — локальный `Option<Bytes>` в
`relay_vless_udp_upstream_to_client` и `relay_mesh_udp_to_client`:

- первый ответный record уходит как `header || len || payload` одним сообщением;
- пока заголовок не ушёл, record всегда идёт по потоку, мимо HTTP/3 datagram (страховка:
  клиент шлёт датаграммы только после чтения заголовка, а сервер вооружает маршрут только
  после первой uplink-датаграммы, так что датаграмма заголовок не обгонит и так);
- mesh-релей при штатном конце шлёт неотправленный заголовок одним сообщением перед Close
  (как TCP-релей).

Клиент (`vless/udp.rs::read_packet`) разбирает заголовок и record из одного буфера, uplink
заголовка не ждёт.

### Тесты сервера

- `vless/tests/tcp.rs`: релей с `Some(header)` и ring — первое сообщение = header + данные,
  ring содержит только данные; при EOF без данных заголовок уходит один перед Close;
  сборка resume-преамбулы (`header || ORSM`, `header || ORSM || ORDR`, h2-нарезка) — через
  выделенную чистую функцию `resume_preamble`.
- `tests/held_header.rs` (новый): заголовок приклеивается ровно к первому сообщению;
  конкурентные писатели — заголовок всегда в начале потока; `pending_len` после отправки 0;
  отменённая отправка не теряет заголовок.
- `vless_mux/tests/tcp_sub.rs`: первый кадр sub-conn несёт заголовок, на h2 влезает в cap.
- `tests/vless_udp.rs`: первый record склеен с заголовком и идёт по потоку даже при
  наличии datagram-цели; второй — без заголовка.
- Существующие e2e/кросс-тесты resume (`server/tests/resumption/*`) должны остаться
  зелёными без правок — это и есть проверка совместимости формата.

## Часть 2. Клиент: h2-uplink cap

- `crates/outline-transport/src/carrier_padding.rs`: константы `H2_DATA_PAYLOAD_MAX = 16375`,
  `H2_WS_CLIENT_HEADER_LEN = 8` (2 + 2 расширенной длины + 4 маски для 126..=65535),
  `MIN_H2_PLAINTEXT_CAP = 1024`; `h2_uplink_cap(scheme) -> Option<usize>` (вычитает заголовок
  WS и паддинг на максимальном паде); `even_piece_lens` как на сервере; общий
  `uplink_messages(scheme, shaper, cap, frame, rng)`: план шейпера (если активен), затем
  любой кусок больше cap режется ровно, каждый кусок паддится. Внутренний оверхед 0: режем
  уже зашифрованный поток, сервер читает SS и VLESS потоково.
- `TransportStream::caps_h2_uplink()`: `H2` → да; `Xhttp` → носитель h2 и submode
  stream-one; h1, h3 и XHTTP packet-up — нет (packet-up не трогаем: там POST на кусок,
  своя нарезка `shaped_post_pieces`). `XhttpStream` получает флаг `carrier_is_h2`
  (выставляет только `xhttp/h2.rs`).
- SS: `WsWriteTransport` получает `h2_cap: Option<usize>`, `write_frame` идёт через
  `uplink_messages`; `TcpShadowsocksWriter<WsWriteTransport>::with_h2_uplink_cap(bool)` —
  билдер, чтобы не менять сигнатуру `connect` у 8 вызовов. Продовые вызовы (`outline-tun`
  connect, `failover.rs`, probe) передают `ws_stream.caps_h2_uplink()`.
- VLESS: `from_ws_frames` сам берёт `caps_h2_uplink()` у потока, `WsFrameSink::send_frame`
  идёт через тот же `uplink_messages`.
- Удержанный SS2022-заголовок клеится к первому сообщению данных; на h2 первое сообщение
  всегда кусок окна нарезки (≤ 850 байт), так что cap не нарушается.

### Тесты клиента

- `tcp_transport/writer/tests/mod.rs`: на h2 запись 64 KiB после окна нарезки уходит
  ровными сообщениями ≤ cap, конкатенация = исходник (без паддинга и с паддингом через
  декодер); без h2 — одно сообщение как раньше.
- `tests/carrier_padding.rs`: `h2_uplink_cap` (h2/паддинг/порог), `uplink_messages` режет
  хвост за окном.
- `tests/ws_stream.rs`: решение `caps_h2_uplink` по носителю/submode.

## Документация

- `docs/PADDING.md` + `docs/PADDING.ru.md`: заголовок VLESS держится до первых данных на
  всех путях (resume/mesh/mux/UDP); клиентский h2-uplink режется по 16375.
- `bins/outline-ss-rust/CHANGELOG.md` + `.ru.md`, `bins/outline-ws-rust/CHANGELOG.md` + `.ru.md`.

## Верификация

CI-гейт из `AGENTS.md`: fmt по списку пакетов, clippy `--all-targets -D warnings`,
`cargo test --workspace --exclude sockudo-ws`, e2e
`RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls --test 'e2e_*' -- --test-threads=1`.
Linux-специфики правка не касается (docker не нужен).

## Выкатка

Не входит в задачу. Порядок любой (формат совместим): сервер и клиент можно выкатывать
независимо, по одному узлу через `ops/deploy/deploy-binary.sh`, только по команде владельца.
Ничего не коммитим, diff показываем владельцу.
