# Локальные патчи

Единый источник истины по локальным патчам на vendored-крейты.
*English version: [PATCHES.md](PATCHES.md).*

Монорепо vendor'ит и патчит два upstream-крейта, чтобы HTTP/3 WebSocket-путь
был практичен. Пропатченные копии лежат в `vendor/h3` и `vendor/sockudo-ws`,
подключены через `[patch.crates-io]` в корневом `Cargo.toml`. Файлы `.patch` в
этом каталоге — review- и maintenance-артефакты; сами сборки используют
vendored-копии.

Регенерированы против:

- **h3** — crates.io `h3 0.0.8`.
- **sockudo-ws** — GitHub-тег `v1.7.5` (коммит `7819745`), в raw
  upstream-форматировании git (см. примечание ниже).

## Артефакты-патчи

| Файл | Что покрывает |
|------|---------------|
| [`h3-0.0.8.patch`](h3-0.0.8.patch) | все отличия `vendor/h3` от upstream `h3 0.0.8` |
| [`sockudo-ws-1.7.5.patch`](sockudo-ws-1.7.5.patch) | все отличия `vendor/sockudo-ws/src` (однострочное изменение `Cargo.toml` описано ниже, в патч не входит) |

## Модули-врата

Весь production-код обращается к пропатченной поверхности API через два
модуля-врата, по одному на сторону:

- [`crates/outline-transport/src/h3/vendored.rs`](crates/outline-transport/src/h3/vendored.rs) — клиент
  (`Protocol::WEBSOCKET` на Extended CONNECT, `Stream::from_h3_client` +
  `WebSocketStream::from_raw`).
- [`bins/outline-ss-rust/src/server/h3/vendored.rs`](bins/outline-ss-rust/src/server/h3/vendored.rs) — сервер
  (request-extension `h3::ext::Protocol`, `Stream::from_h3_server` +
  `WebSocketStream::from_raw`, восстановленный `WebSocketServer::into_parts`,
  плюс реэкспорты sockudo-ws-типов, используемых сервером).

Ребейз vendored-крейтов на новый upstream начинай (и в идеале заканчивай) в
этих двух файлах. CI следит, чтобы `sockudo_ws` упоминался только в
модулях-вратах; тестовые модули — исключение: они намеренно изображают
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
> bench-таргеты, как и опубликованный library-крейт; в `rustfmt.toml` стоит
> `ignore = ["vendor"]`, так что дерево больше не дрейфует к проектному формату.

Логические изменения в `sockudo-ws-1.7.5.patch`:

1. **h3-noerror** (`src/server.rs`) — трактует `ApplicationClose: H3_NO_ERROR`
   как нормальное закрытие и подавляет ложные `eprintln!` `HTTP/3 accept
   error` / `HTTP/3 connection error` при чистом shutdown. Также
   восстанавливает `WebSocketServer::into_parts`, нужный серверному
   accept-циклу `outline-ss-rust`.
2. **fix-h3-poll-write** (`src/http3/stream.rs`,
   `src/stream/transport_stream.rs`) — sockudo-половина poll-write-фикса:
   машины состояний `write_queued` / `shutdown_started`, дёргающие h3-методы
   `queue_send` / `poll_drain` / `queue_grease` / `poll_quic_finish` ровно
   один раз на логическую запись / shutdown.
3. **valid-close-codes-1012-1014** (`src/error.rs`) — `Error::is_valid_code`
   принимал только `1000..=1003 | 1007..=1011 | 3000..=4999`, отвергая
   зарегистрированные IANA коды 1012 (Service Restart), 1013 (Try Again Later)
   и 1014 (Bad Gateway). Сервер шлёт штатный `Close 1013` («try again later»)
   на каждый недоступный upstream-таргет; на HTTP/3-пути это отвержение
   превращало безобидный per-target close в фатальную read-ошибку несущей
   (`Invalid close code: 1013`), дёргая `ws_h3 -> ws_h2` и рвя потоки на wire.
   Диапазон расширен до `1007..=1014` (1015 не входит — TLS, на wire не
   передаётся).

**`Cargo.toml`** (в патч не входит): зависимости rustls-стека запинены с
`default-features = false` и provider-фичей `aws_lc_rs`
(`tokio-rustls = { features = ["aws_lc_rs", "tls12"] }`, `quinn` на
`rustls-aws-lc-rs`, `rustls` на `aws_lc_rs`), чтобы vendored-крейт оставался
на том же крипто-провайдере, что и остальной workspace, и в графе был ровно
один `CryptoProvider` (см. инвариант о единственном провайдере в корневом
`AGENTS.md`).

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
  два модуля-врата выше, и CI это стережёт, поэтому при ребейзе или аудите
  достаточно понимать пропатченные файлы плюс модули-врата — не весь крейт.
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

## Регенерация

Чтобы пересобрать артефакты-патчи после правки vendored-исходников:

- **h3** — сравнить vendored-копию с чистым upstream-checkout'ом: взять
  свежий `h3 0.0.8` с crates.io (например через одноразовый git-baseline) и
  сделать `git diff vendor/h3` по изменённым файлам.
- **sockudo-ws** — сделать diff `vendor/sockudo-ws/src` против `src/` чистого
  GitHub-checkout'а `v1.7.5` (оба уже в raw upstream-форматировании).

Не поднимай upstream-версии и не убирай `[patch.crates-io]` без явной
причины: HTTP/3 WebSocket-путь зависит от этих патчей.
