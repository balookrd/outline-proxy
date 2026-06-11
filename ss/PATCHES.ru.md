# Локальные патчи

В этом репозитории вендорятся и патчатся два апстримных крейта, чтобы сделать HTTP/3 WebSocket путь работоспособным.

*English version: [PATCHES.md](PATCHES.md)*

## h3

Файл патча: [h3-rfc9220-websocket.patch](h3-rfc9220-websocket.patch)

Зачем нужен:
- апстримный `h3 0.0.8` не распознаёт `:protocol = websocket`
- RFC 9220 WebSocket over HTTP/3 требует это значение псевдозаголовка для Extended CONNECT

Что меняет:
- добавляет `Protocol::WEBSOCKET`
- учит `h3` разбирать и сериализовать `websocket` в `:protocol`
- подавляет шумные предупреждения в вендорной копии

Путь вендорного крейта:
- [vendor/h3](vendor/h3)

Переопределение в Cargo:
- `[patch.crates-io] h3 = { path = "vendor/h3" }`

## sockudo-ws

Файл патча: [sockudo-ws-h3-noerror.patch](sockudo-ws-h3-noerror.patch)

Зачем нужен:
- апстримный `sockudo-ws 1.7.4` выводит `HTTP/3 accept error` / `HTTP/3 connection error` при штатном завершении с `H3_NO_ERROR`
- это создаёт ложный шум в stderr даже когда RFC 9220 релей работает корректно

Что меняет:
- обрабатывает `ApplicationClose: H3_NO_ERROR` как нормальное закрытие
- подавляет эти ложноположительные сообщения `eprintln!`

Путь вендорного крейта:
- [vendor/sockudo-ws](vendor/sockudo-ws)

Переопределение в Cargo:
- `[patch.crates-io] sockudo-ws = { path = "vendor/sockudo-ws" }`

## fix-h3-poll-write (h3 + sockudo-ws)

Файл патча: [fix-h3-poll-write.patch](fix-h3-poll-write.patch)

Зачем нужен:
- `AsyncWrite::poll_write` в `sockudo-ws` создавал новый future `send_data` при
  **каждом** вызове, включая повторные попытки после `Poll::Pending`
- когда QUIC send-буфер был временно заполнен, h3-quinn выставлял внутреннее
  `writing = Some(data)` при первом вызове, но future дропался до того, как
  `poll_ready` успевал его слить; следующий `poll_write` снова вызывал `send_data`
  пока `writing` был занят
- h3-quinn обнаруживает двойную запись и возвращает
  `InternalError("internal error in the http stack")`, которую слой h3
  транслирует в `ApplicationClose: H3_INTERNAL_ERROR`, закрывая всё QUIC-соединение
  и убивая все мультиплексированные сессии на нём
- та же проблема drop-and-recreate присутствовала в `poll_shutdown`: async-функция
  `finish()` пересоздавала future при каждом вызове; если QUIC send-буфер был
  заполнен во время отправки GREASE-фрейма, `send_data` снова видел `writing.is_some()`
  и генерировал `H3_INTERNAL_ERROR`

Что меняет:

**`vendor/h3`** (`src/connection.rs`, `src/server/stream.rs`, `src/client/stream.rs`):
- добавляет `queue_send(&mut self, buf: B) -> Result<(), StreamError>` — синхронно
  помещает данные в write-буфер h3-quinn (первая половина `send_data`)
- добавляет `poll_drain(&mut self, cx) -> Poll<Result<(), StreamError>>` — опрашивает
  до полного сброса write-буфера (вторая половина), безопасен для повторных вызовов
  без риска двойной записи
- добавляет `queue_grease(&mut self) -> Result<(), StreamError>` — синхронно ставит
  в очередь GREASE-фрейм (если `send_grease` включён) и сбрасывает флаг; no-op если
  отключён
- добавляет `poll_quic_finish(&mut self, cx) -> Poll<Result<(), StreamError>>` —
  опрашивает до доставки QUIC FIN на стороне отправки; вызывать только после того,
  как `poll_drain` вернул Ready

**`vendor/sockudo-ws`** (`src/stream/transport_stream.rs`, `src/http3/stream.rs`):
- добавляет `write_queued: Option<usize>` в `Http3StreamInner::Server` и `::Client`
  (а также в `Http3ServerStream` / `Http3ClientStream`)
- переписывает `poll_write` как двухфазный автомат состояний: `queue_send` вызывается
  ровно один раз на логическую запись (когда `write_queued.is_none()`); последующие
  опросы после `Pending` идут прямо в `poll_drain`, не касаясь write-буфера h3-quinn
  повторно
- добавляет `shutdown_started: bool` в те же типы
- переписывает `poll_shutdown` как трёхфазный автомат состояний: `queue_grease`
  (один раз), `poll_drain` (сброс GREASE-фрейма или no-op), `poll_quic_finish`
  (отправка FIN)

Пути вендорных крейтов:
- [vendor/h3](vendor/h3)
- [vendor/sockudo-ws](vendor/sockudo-ws)

## Примечания

- Файлы патчей в корне репозитория — документация и артефакты для ревью.
- В реальных сборках используются вендорные копии из `vendor/` через `[patch.crates-io]`.
