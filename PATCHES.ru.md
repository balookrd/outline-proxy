# Локальные патчи

Единый источник истины по локальным патчам на vendored-крейты.
*English version: [PATCHES.md](PATCHES.md).*

Монорепо vendor'ит и патчит четыре upstream-крейта, чтобы HTTP/3 WebSocket-путь
был практичен. Пропатченные копии лежат в `vendor/h3`, `vendor/sockudo-ws`,
`vendor/quinn-proto` и `vendor/rustls`, подключены через `[patch.crates-io]` в корневом `Cargo.toml`. Файлы `.patch` в
этом каталоге — review- и maintenance-артефакты; сами сборки используют
vendored-копии.

Регенерированы против:

- **h3** — crates.io `h3 0.0.8`.
- **sockudo-ws** — GitHub-тег `v1.7.5` (коммит `7819745`), в raw
  upstream-форматировании git (см. примечание ниже).
- **quinn-proto** — crates.io `quinn-proto 0.11.15`.
- **rustls** — crates.io `rustls 0.23.40`.

## Артефакты-патчи

| Файл | Что покрывает |
|------|---------------|
| [`h3-0.0.8.patch`](h3-0.0.8.patch) | все отличия `vendor/h3` от upstream `h3 0.0.8` |
| [`sockudo-ws-1.7.5.patch`](sockudo-ws-1.7.5.patch) | все отличия `vendor/sockudo-ws/src` (однострочное изменение `Cargo.toml` описано ниже, в патч не входит) |
| [`quinn-proto-0.11.15.patch`](quinn-proto-0.11.15.patch) | все отличия `vendor/quinn-proto` от upstream `quinn-proto 0.11.15` (`src/` и `Cargo.toml`) |
| [`rustls-0.23.40.patch`](rustls-0.23.40.patch) | все отличия `vendor/rustls` от upstream `rustls 0.23.40` (`src/` и `Cargo.toml`) |

## Модули-гейты

Весь production-код обращается к пропатченной поверхности API через четыре
модуля-гейта (клиентский h3, серверный h3, клиентский QUIC, клиентский rustls):

- [`crates/outline-transport/src/h3/vendored.rs`](crates/outline-transport/src/h3/vendored.rs) — клиент
  (`Protocol::WEBSOCKET` на Extended CONNECT, `Stream::from_h3_client` +
  `WebSocketStream::from_raw`).
- [`bins/outline-ss-rust/src/server/h3/vendored.rs`](bins/outline-ss-rust/src/server/h3/vendored.rs) — сервер
  (request-extension `h3::ext::Protocol`, `Stream::from_h3_server` +
  `WebSocketStream::from_raw`, восстановленный `WebSocketServer::into_parts`,
  плюс реэкспорты sockudo-ws-типов, используемых сервером).
- [`crates/outline-transport/src/quic/vendored.rs`](crates/outline-transport/src/quic/vendored.rs) — клиент, пропатченный
  `quinn-proto` (`TransportConfig::initial_stream_receive_window`).
- [`crates/outline-transport/src/tls_vendored.rs`](crates/outline-transport/src/tls_vendored.rs) — клиент, пропатченный
  `rustls` (`ClientConfig::client_hello_shape` с `ClientHelloShape` /
  `ExtensionOrder`, `kx_group::SECP521R1` и `apply_tls_hello_profile`, который
  превращает браузерный TLS-профиль hello — QUIC или TCP — в `ClientHelloShape`).

Ребейз vendored-крейтов на новый upstream начинай (и в идеале заканчивай) в
этих файлах-гейтах. CI следит, чтобы `sockudo_ws` упоминался только в
модулях-гейтах, а пропатченный API quinn-proto
(`initial_stream_receive_window`) — только в
`crates/outline-transport/src/quic/vendored.rs`, а пропатченный API rustls
(`client_hello_shape`, `ClientHelloShape`, `ExtensionOrder`,
`kx_group::SECP521R1`) — только в `crates/outline-transport/src/tls_vendored.rs`
(шаг «invariant — patched rustls API only behind the gate module» в
`.github/workflows/ci.yml`); тестовые модули — исключение: они намеренно изображают
клиентскую сторону.

## h3 (0.0.8)

Логические изменения в `h3-0.0.8.patch`:

1. **RFC 9220 WebSocket** (`src/ext.rs`, `src/lib.rs`) — добавляет
   `Protocol::WEBSOCKET` и парсит/сериализует `:protocol = websocket`.
   Upstream `h3 0.0.8` его не распознаёт, а Extended CONNECT WebSocket поверх
   HTTP/3 требует этого значения псевдо-заголовка.
2. **fix-h3-poll-write** (`src/connection.rs`, `src/client/stream.rs`,
   `src/server/stream.rs`) — добавляет `queue_send` / `poll_drain` /
   `queue_grease` / `poll_quic_finish`, чтобы `AsyncWrite::poll_write` и
   `poll_shutdown` не пересоздавали `send_data`-future на каждый poll. Старый
   код делал двойную запись при заполненном QUIC send-буфере; h3-quinn
   репортит это как `H3_INTERNAL_ERROR`, что закрывает всё QUIC-соединение и
   рвёт все мультиплексированные сессии на нём.
3. **Vendoring-trim** (`Cargo.toml`) — убраны dev-dependencies, чтобы
   workspace их не тянул.

## sockudo-ws (1.7.5)

> **Примечание — crate yanked.** `sockudo-ws 1.7.5` снят (yanked) с crates.io
> (скачивание возвращает `403 AccessDenied`), поэтому baseline — GitHub-тег
> `v1.7.5`. Vendored `src/` хранится в **upstream-форматировании git** (не в
> переформатировании crates.io-publish), поэтому `sockudo-ws-1.7.5.patch`
> применяется напрямую к чистому `git clone` этого тега — без шага rustfmt.
> Library-`Cargo.toml` по-прежнему отбрасывает upstream `[[bin]]` /
> bench-таргеты, как и опубликованный library-крейт (поэтому `src/bin/` здесь
> нет и в патч он не входит).
>
> **От дрейфа форматирования ничто не защищает автоматически.** Ключ `ignore`
> у rustfmt — nightly-only, поэтому строка `ignore = ["vendor"]` в
> `rustfmt.toml` на стабильном тулчейне, под которым идёт гейт, не работает:
> голый `cargo fmt --all` ПЕРЕФОРМАТИРУЕТ `vendor/` под проектный стиль и молча
> рассинхронизирует дерево с этим патчем (ровно так между 2026-07-11 и
> 2026-08-08 уехал 21 файл). Гонять `cargo fmt` только по явному списку пакетов
> из `AGENTS.md`, а format-only diff в `vendor/` откатывать. Проверка
> соответствия: склонировать тег, `git apply sockudo-ws-1.7.5.patch` и сравнить
> `diff -r` два дерева `src/` — они обязаны совпасть побайтово, кроме `src/bin/`.

Логические изменения в `sockudo-ws-1.7.5.patch`:

1. **h3-noerror** (`src/server.rs`) — трактует `ApplicationClose: H3_NO_ERROR`
   как нормальное закрытие и подавляет ложные `eprintln!` `HTTP/3 accept
   error` / `HTTP/3 connection error` при чистом shutdown. Также
   восстанавливает `WebSocketServer::into_parts`, нужный серверному
   accept-циклу `outline-ss-rust`.
2. **fix-h3-poll-write** (`src/stream/transport_stream.rs`) — sockudo-половина
   poll-write-фикса, применённая к ЖИВОМУ H3 WebSocket-стриму `Stream<Http3>`
   (`Http3StreamInner::{Server,Client}` — тип, получаемый через `from_h3_client`
   / `from_h3_server`): машины состояний `write_queued` / `shutdown_started`,
   дёргающие h3-методы `queue_send` / `poll_drain` / `queue_grease` /
   `poll_quic_finish` ровно один раз на логическую запись / shutdown.
   Дополнительно `poll_shutdown` дренирует незавершённую запись `poll_write`
   (`write_queued.is_some()`) до конца ПЕРЕД вызовом `queue_grease`: иначе
   shutdown, гонящийся с недренированной downlink-записью (teardown релея под
   всплеском открытий/закрытий стримов), вызвал бы `send_data`, когда у
   send-стрима h3-quinn ещё `writing = Some(..)`, а h3-quinn эскалирует это в
   connection-level `H3_INTERNAL_ERROR`, который роняет ВСЕ мультиплексированные
   сессии на общей QUIC-несущей. Третий флаг состояния, `send_poisoned`,
   закрывает оставшуюся дыру: `poll_ready` у h3-quinn очищает свой слот
   `writing` **только на успешном пути**, поэтому упавший дренаж оставляет
   send-сторону занятой, тогда как наш `write_queued` уже сброшен — и следующий
   `queue_grease()` бьёт ровно в тот misuse-guard, ради обхода которого дренаж и
   делался. Теперь любой отказ send-стороны «отравляет» стрим, а
   `h3_shutdown_phase` (покрыт unit-тестами) уводит отравленный стрим сразу к
   QUIC-FIN, который через `send_data` не проходит. `poll_write` отказывает
   отравленному стриму сразу — по той же причине и на том же слоте: WebSocket-слой
   продолжает писать и после упавшей записи (Close-фрейм, который он шлёт на
   разрыве, — ровно такая запись), а этот `queue_send` и есть второй `send_data`
   в занятый слот. Прикрытым был только shutdown-путь, и именно эта дыра
   продолжала ронять носители на проде уже после того, как флаг `send_poisoned`
   появился. (Примечание: неиспользуемые
   обёртки `Http3ServerStream` / `Http3ClientStream` в `src/http3/stream.rs`
   оставлены в upstream-vanilla — data plane их не инстанцирует, поэтому фикс
   живёт только в одном живом типе стрима.)
3. **valid-close-codes-1012-1014** (`src/error.rs`) — `Error::is_valid_code`
   принимал только `1000..=1003 | 1007..=1011 | 3000..=4999`, отвергая
   зарегистрированные IANA коды 1012 (Service Restart), 1013 (Try Again Later)
   и 1014 (Bad Gateway). Сервер шлёт штатный `Close 1013` («try again later»)
   на каждый недоступный upstream-таргет; на HTTP/3-пути это отвержение
   превращало безобидный per-target close в фатальную read-ошибку несущей
   (`Invalid close code: 1013`), дёргая `ws_h3 -> ws_h2` и рвя потоки на wire.
   Диапазон расширен до `1007..=1014` (1015 не входит — TLS, на wire не
   передаётся).
4. **h3-read-buf-capacity** (`src/stream/transport_stream.rs`) — начальная
   ёмкость `read_buf` у живых H3 WebSocket-стримов снижена с 64 KiB до 32 KiB в
   `from_h3_client` и `from_h3_server` (`Http3StreamInner::{Client,Server}` — те
   же два конструктора, что правит `fix-h3-poll-write`). Буфер аллоцируется
   упреждающе (eagerly) на КАЖДЫЙ стрим, а каждый туннельный флоу несёт свой носитель, так
   что резерв платился по разу на флоу; на `.104` под cgroup-лимитом 700 MiB это
   часть той памяти, из-за которой процесс убивал OOM. `BytesMut::with_capacity`
   задаёт начальную ёмкость, а не потолок, поэтому крупное сообщение по-прежнему
   растит буфер сам — меняется только объём упреждающего резерва. `from_h2`
   (`Http2StreamInner::recv_buf`) и `from_quic` (`Http3StreamInner::Raw`)
   намеренно оставлены upstream-vanilla: data plane их не инстанцирует — тот же
   принцип, по которому `fix-h3-poll-write` живёт только в двух живых типах
   стрима.

**`Cargo.toml`** (в патч не входит): зависимости rustls-стека запинены с
`default-features = false` и provider-фичей `aws_lc_rs`
(`tokio-rustls = { features = ["aws_lc_rs", "tls12"] }`, `quinn` на
`rustls-aws-lc-rs`, `rustls` на `aws_lc_rs`), чтобы vendored-крейт оставался
на том же крипто-провайдере, что и остальной workspace, и в графе был ровно
один `CryptoProvider` (см. инвариант о единственном провайдере в корневом
`AGENTS.md`).

## quinn-proto (0.11.15)

Baseline — crates.io `quinn-proto 0.11.15`. Логические изменения в
`quinn-proto-0.11.15.patch`:

1. **advertised-stream-window** (`src/config/transport.rs`,
   `src/transport_parameters.rs`, `src/connection/mod.rs`,
   `src/connection/streams/{state,mod,recv}.rs`) — новое
   `TransportConfig::initial_stream_receive_window(Option<VarInt>)`. Это значение
   уходит в `initial_max_stream_data_*` transport parameters и служит начальным
   кредитом каждого потока на приём (включая принимающую половину локально
   открытых bidi-потоков); `stream_receive_window` остаётся окном, до которого
   поток расширяется, когда приложение впервые опрашивает его на чтение
   (`MAX_STREAM_DATA` ставится в очередь, даже если байты ещё не прочитаны). Нужно, чтобы
   H3-клиент объявлял в Initial окно браузера (видно пассивному DPI), а работал с
   большим (последующие `MAX_STREAM_DATA` зашифрованы). `None` (дефолт) — поведение
   upstream; сервер патч не использует. `max_stream_data` считает разницу через
   `saturating_sub`, чтобы рабочее окно меньше объявленного не паниковало.
2. **browser-shaped-transport-parameters** (`src/config/transport.rs`,
   `src/transport_parameters.rs`) — опции `TransportConfig`, нужные H3-клиенту,
   чтобы transport parameters в Initial совпадали с браузером:
   `advertise_min_ack_delay`, `send_grease_transport_parameter`,
   `advertise_max_idle_timeout` (локальный idle продолжает действовать),
   `advertise_max_udp_payload_size`, `advertised_max_datagram_frame_size`,
   `version_information` (RFC 9368: выбранная версия v1, `other_versions` из
   фиксированных версий и GREASE-слотов на соединение, при необходимости
   переставленных) и `extra_transport_parameters` (сырые `(id, value)`, вплетаются в
   случайные позиции общего перемешанного порядка). Лимиты:
   `extra_transport_parameters` принимает не более 2 параметров (3-й из 3 слотов
   занят под `version_information`) со значениями не длиннее 16 байт; иначе сеттер
   паникует. Сеттер также проверяет, что id extra не совпадает ни с одним id, который
   пишет сам quinn (`TransportParameterId::SUPPORTED`), ни с `version_information`
   (0x11). `advertised_max_datagram_frame_size` не должен превышать
   `datagram_receive_buffer_size`. `version_information` — только для клиента
   (выбранная версия всегда QUIC v1). Дефолты повторяют upstream, и с дефолтами rng
   расходуется в том же порядке, что и в upstream (extras и `version_information`
   обращаются к нему только когда заданы), поэтому сервер, не использующий эти
   опции, не затронут.
3. **browser-order-and-firefox** (`src/config/transport.rs`,
   `src/transport_parameters.rs`, `src/cid_queue.rs`, `src/connection/mod.rs`,
   `src/connection/streams/{state,mod,recv}.rs`, `src/lib.rs`) — опции для
   Safari- и Firefox-профилей:
   `transport_parameter_order` (`Shuffled` / `Fixed` / `Rotated`; в `Rotated`
   сдвигаются только штатные параметры), `initial_stream_receive_windows`
   (начальный кредит по направлениям, по классу потока; пулы освобождённых `Recv`
   тоже поделены по классам), `advertised_active_connection_id_limit` (кольцевой
   буфер remote CID на 8 записей; проверка идёт по объявленному лимиту с потолком 8,
   дефолт 5; больше 8 активных CID от пира завершает соединение
   `CONNECTION_ID_LIMIT_ERROR`) и `max_ack_delay_ms` (объявляется и задаёт
   локальный ACK-таймер). Все дефолты — upstream, rng в дефолтном режиме
   расходуется как в upstream, сервер опции не использует.
4. **Vendoring-trim** (`Cargo.toml`) — убраны dev-dependencies (upstream `rcgen` с
   дефолтным `ring` нарушил бы инвариант aws-lc-rs).

Проверка соответствия: применить патч к чистой копии crates.io 0.11.15 и сравнить
`diff -r src/` — совпадение побайтово.

## Стратегия сопровождения (sockudo-ws)

`sockudo-ws` снят (yanked) с crates.io (скачивание возвращает `403`), а
`v1.7.5` — последняя версия, на которую можно запиниться, поэтому
vendored-копия трактуется как **де-факто наш собственный форк**, а не
временный pin в ожидании upstream-фикса. Практические следствия:

- **Фиксы вносим здесь.** Баги и проблемы безопасности правим прямо в
  `vendor/sockudo-ws/src`; то же изменение обновляет `sockudo-ws-1.7.5.patch`
  и обе `PATCHES*.md`. Не блокируем фикс в ожидании гипотетического
  upstream-релиза.
- **Provenance пиним на коммит, не только на тег.** Baseline — GitHub-тег
  `v1.7.5` на коммите `7819745`; фиксируй хэш коммита, чтобы vendored-дерево
  можно было перепроверить, даже если тег сдвинут или репозиторий пропал —
  этот тег теперь единственный публичный baseline, раз crates.io отдаёт
  `403`.
- **Радиус поражения уже мал.** Production обращается к крейту только через
  модули-гейты выше, и CI это стережёт, поэтому при ребейзе или аудите
  достаточно понимать пропатченные файлы плюс модули-гейты — не весь крейт.
- **Держим diff минимальным; неиспользуемые модули пока НЕ вырезаем.** Крейт
  несёт код, который HTTP/3 WebSocket-путь никогда не задействует (`io_uring`,
  `compression` / `deflate`, `simd`, `multiplex`, большую часть `pubsub`).
  Удаление сократило бы аудит-поверхность, но раздуло бы diff против тега
  `v1.7.5` и усложнило каждую перепроверку, поэтому дерево держим побайтово
  выровненным с upstream. Вырезание станет опцией только если решим полностью
  перестать отслеживать upstream (жёсткий форк + переименование); зафиксируй
  это решение здесь, если оно будет принято.

**Триггеры пересмотра / ухода** — пересматривай зависимость по событию, не по
расписанию:

- upstream `h3` обретает нативную поддержку RFC 9220 WebSocket-over-HTTP/3 —
  это выведет из игры WebSocket-stream-слой и часть патч-набора;
- появляется поддерживаемая альтернатива WebSocket-over-HTTP/3;
- в неиспользуемом нами модуле всплывает неустранимая проблема безопасности,
  где вырезать дешевле, чем тащить.

## rustls (0.23.40)

Baseline — crates.io `rustls 0.23.40`. Изменения в `rustls-0.23.40.patch`:

1. **client-hello-shape** (`src/client/client_conn.rs`, `src/client/builder.rs`,
   `src/client/hs.rs`, `src/client/common.rs`, `src/client/tls13.rs`,
   `src/client/ech.rs`, `src/msgs/handshake.rs`, `src/lib.rs`) — новое поле
   `ClientConfig::client_hello_shape: Option<Arc<ClientHelloShape>>` (по умолчанию
   `None`, выставляется в `builder.rs`; `ClientHelloShape` и `ExtensionOrder`
   реэкспортируются из `rustls::client`). H3-клиент с его помощью делает ClientHello
   в QUIC Initial таким же, как у браузера (вплоть до JA4); им же пользуются
   TCP-носители, проверка сертификата и HTTPS-проба для TCP ClientHello. Поля:
   - `omit_extended_master_secret`, `omit_ec_point_formats`,
     `omit_status_request` — не отправлять расширения 23 / 11 / 5;
   - `extra_extensions: Vec<(u16, Vec<u8>)>` — расширения, записываемые как есть и
     упорядочиваемые наравне со штатными; запись со штатным типом заменяет
     кодирование rustls, записи `pre_shared_key` игнорируются, типы учитываются как
     отправленные (эхо сервера не считается непрошеным расширением). Типы не
     дедуплицируются и не должны совпадать со значениями GREASE; при настоящем (не
     GREASE) ECH тип, который внутренний hello сжимает, был бы записан дважды — ни
     один наш профиль так не делает;
   - `grease` — GREASE по RFC 8701 в стиле BoringSSL: случайные значения `0x?A?A`,
     вытягиваемые раз на соединение (после всей случайности upstream и
     сохраняемые через HelloRetryRequest), первыми в `cipher_suites`,
     `supported_groups` и `supported_versions`, первая запись `key_share` с
     однобайтным ключом `00` (пропадает после HRR, называющего группу), и два
     различных GREASE-расширения: первое пустое, последнее с `00` (за ним идёт
     только `pre_shared_key`);
   - `extension_order: ExtensionOrder` — `Upstream` (перемешивание rustls, затем
     ECH, затем `pre_shared_key`), `ShuffledWithEch` (ECH перемешивается со
     всеми, `pre_shared_key` последним) или `Fixed(Vec<u16>)` (сначала
     перечисленные типы, неотправляемые пропускаются, остальные — в порядке
     upstream; поэтому неперечисленный ECH идёт после всех прочих расширений, и за
     ним следуют только замыкающее GREASE-расширение, если включено, и
     `pre_shared_key`; GREASE-расширения первые и последние независимо от списка).
     Порядок сохраняется в ClientHello после HRR;
   - `extra_key_share_groups: Vec<NamedGroup>` — дополнительные записи `key_share`
     после штатных (группы без поддержки TLS 1.3 или уже предложенные
     пропускаются). Клиент хранит их закрытые ключи и, если ServerHello выбрал
     одну из этих групп, завершает обмен с ней, а не падает (`tls13.rs`); HRR с
     запросом уже предложенной так группы отвергается как недопустимый. После HRR
     без группы они отправляются снова, после HRR с группой — отбрасываются;
   - `ech_grease_payload_lengths: Vec<u16>` — длина поля `payload` (с тегом AEAD)
     у GREASE `encrypted_client_hello` (`ech.rs`): пустой список — размер по
     правилам rustls, одно значение — ровно оно, несколько — равновероятный выбор
     на соединение (rejection sampling на `SecureRandom` конфига, после генерации
     HPKE-пары и до заполнения случайного payload). Настоящий ECH не затрагивается;
   - `wire_cipher_suites: Vec<CipherSuite>` — ровно тот `cipher_suites`, что уходит
     на провод, после GREASE-набора при `grease` и без renegotiation SCSV. Пусто
     (по умолчанию) — список rustls. Меняется только объявляемый список: наборы,
     которые rustls умеет согласовать, остаются провайдерскими, поэтому ServerHello
     с выбором набора, которого у провайдера нет (CBC, RSA-обмен, 3DES), завершает
     рукопожатие ошибкой. Список обязан содержать все наборы провайдера, которые
     конфиг должен уметь согласовать, — это проверяет `outline-transport`, не патч;
   - `advertise_tls12: bool` — добавить `0303` после `0304` в
     `supported_versions` на проводе даже для конфига только с TLS 1.3. Меняется
     лишь расширение: фильтрация наборов, SCSV, `extended_master_secret`, тикеты и
     проверка версии в ServerHello по-прежнему идут по реальным версиям конфига,
     так что сервер, ответивший TLS 1.2, проваливает рукопожатие. Для QUIC не
     нейтрально: поле игнорирует запрет TLS 1.2 в QUIC и положило бы `0303` в
     QUIC-hello, поэтому QUIC-профили держат его `false`. По умолчанию `false`;
   - `grease_signature_algorithms: bool` — при `grease` отдельное GREASE-значение
     (`0x?A?A`, свой случайный байт, сохраняется при HRR) идёт первым в
     `signature_algorithms`. Без `grease` игнорируется; принимаемые от сервера
     схемы по-прежнему определяет верификатор. По умолчанию `false`;
   - `alps: Vec<(Vec<u8>, Vec<u8>)>` — клиентская сторона ALPS
     (`application_settings`, новый кодпойнт 17613) в виде пар
     `(ALPN-протокол, настройки клиента)`. Непустое: hello несёт 17613 со списком
     объявленных ALPN-протоколов, у которых есть запись, в порядке ALPN (ни одного —
     расширения нет); кодируется как сырое расширение, поэтому так же участвует в
     `extension_order`, и hello побайтово равен тому, что давала прежняя сырая запись
     17613. В отправленные не записывается: 17613 в ServerHello остаётся
     незапрошенным, а в EncryptedExtensions (`tls13.rs`) принимается, только если
     согласованный ALPN-протокол есть в списке, — иначе, как и без ALPN, рукопожатие
     падает (`unsupported_extension`, `UnsolicitedEncryptedExtension`). Принятый
     ответ ставит настройки протокола в очередь (`ClientConnectionData`), и клиент
     шлёт их перед своими Certificate / Finished в handshake-сообщении
     `EncryptedExtensions` (тип 8) с единственным расширением
     `application_settings`; оно входит в транскрипт, поэтому его покрывают client
     Finished и секрет резюмпции, но не секреты application traffic (транскрипт до
     server Finished). Не шлётся, если early data принята (как в BoringSSL). QUIC
     ничего особого не требует: сообщение идёт в CRYPTO-данных Handshake-эпохи
     вместе с остальным полётом. Настройки сервера не сохраняются. Запись типа 17613
     в `extra_extensions` перекрывает поле (пишется как есть, считается
     отправленной, настройки клиента не шлются, а на ответ сервера ALPS клиент не
     отвечает, так что ждущий их сервер обрывает рукопожатие — абортом фронтов Google).
     Каждое значение настроек должно помещаться в u16-поля длины (не более 65531
     байт; `outline-transport` это проверяет assert'ом). Chrome кладёт свои HTTP/2
     SETTINGS в клиентские данные ALPS; у нас они пусты, поэтому зашифрованная
     запись второго полёта на несколько байт короче, чем у Chrome. По умолчанию пусто.

   Четыре новых поля по умолчанию пусты / `false`, и с такими значениями ClientHello
   и рукопожатие при `Some(shape)` структурно совпадают с прежними (QUIC-профили на
   проводе не меняются; при `grease` поток RNG получает один лишний байт под GREASE-значение
   signature algorithms, и случайные байты, взятые после него, сдвигаются). При `None` ClientHello, обработка ServerHello / HelloRetryRequest /
   EncryptedExtensions и порядок расхода случайности побайтово как в upstream; сервер
   (`outline-ss-rust`) и mesh кластера опцию не выставляют; её выставляет каждый клиентский
   TLS-дозвон (TCP- и QUIC-носители, проверка сертификата, HTTPS-проба через туннель).
2. **secp521r1** (`src/crypto/aws_lc_rs/mod.rs`, `src/crypto/ring/kx.rs`) — новая
   группа `rustls::crypto::aws_lc_rs::kx_group::SECP521R1` (ECDH P-521 через
   aws-lc-rs, её предлагают Safari и Firefox). Она живёт в маленьком модуле в
   `aws_lc_rs/mod.rs`, потому что `ring/kx.rs` общий с провайдером *ring*, у
   которого P-521 нет; в этом файле только `KxGroup`, его поля и
   `uncompressed_point` стали `pub(crate)`. Группы нет ни в `DEFAULT_KX_GROUPS`, ни
   в `ALL_KX_GROUPS` — дефолты не меняются.
3. **Vendoring trim** (`Cargo.toml`) — убраны dev-dependencies вместе с
   целями `[[example]]` и `[[bench]]` (их исходники, `Cargo.lock`, README и
   `.clippy.toml` не vendor'ятся), так же как у `quinn-proto`. `build.rs` —
   побайтово upstream.

Фичи rustls `brotli` / `zlib` остаются выключенными: с ними сервер, который делит
vendored-крейт с клиентом, получил бы компрессоры и начал бы сжимать свой
сертификат. Декомпрессоры сертификата у клиента — в `outline-transport`
(`brotli-decompressor`, `flate2`, `ruzstd`), теперь они собираются всегда: их
используют и TCP-дозвоны.

Проверка соответствия: применить патч к чистой копии crates.io 0.23.40 (в объёме
vendored-файлов) и сравнить `diff -r` — пусто.

## Регенерация

Чтобы пересобрать артефакты-патчи после правки vendored-исходников:

- **h3** — сравнить vendored-копию с чистым upstream-checkout'ом: взять
  свежий `h3 0.0.8` с crates.io (например через одноразовый git-baseline) и
  сделать `git diff vendor/h3` по изменённым файлам.
- **sockudo-ws** — сделать diff `vendor/sockudo-ws/src` против `src/` чистого
  GitHub-checkout'а `v1.7.5` (оба уже в raw upstream-форматировании).
- **quinn-proto / rustls** — распаковать чистый крейт с crates.io в новый
  одноразовый git-репозиторий (оставив только vendored-набор файлов),
  закоммитить, скопировать поверх vendored-файлы и взять `git diff` как патч;
  проверка — применить его `patch -p1` к другой чистой копии и сравнить `diff -r`
  (пусто).

Не поднимай upstream-версии и не убирай `[patch.crates-io]` без явной
причины: HTTP/3 WebSocket-путь зависит от этих патчей.
