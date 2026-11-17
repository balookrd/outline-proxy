# Серверный TCP/TLS/H2: эмуляция Caddy (Go) на порту 443 (этап 2)

План для публичного TCP-листенера `outline-ss-rust` (`bins/outline-ss-rust/src/server/bootstrap/axum.rs`, `tls.rs`, `server/h3/http.rs`).
Цель — привести сетевой отпечаток сервера на TCP-443 (TLS 1.3/1.2, HTTP/2 SETTINGS и HTTP-ответы) в соответствие с эталоном Caddy (Go 1.26 `crypto/tls` + `net/http` + `golang.org/x/net/http2`), устранив противоречия между поведением сервера на UDP (HTTP/3, этап 1) и TCP.

Эталон сверен по исходникам Go 1.26 (`crypto/tls`, `net/http`), `golang.org/x/net/http2` v0.62.0 и Caddy master.

---

## 1. Контекст и архитектурные решения

На боевом парке сервер слушает порт 443 одновременно по UDP (HTTP/3) и TCP (TLS / HTTP/2 / HTTP/1.1).
Пассивный наблюдатель (DPI) или активный сетевой сканер сравнивает отпечатки обоих протоколов. После этапа 1 UDP-листенер ведёт себя в точности как Caddy (quic-go). Этап 2 устраняет расхождения стека TCP.

### Что не трогаем
- Клиентский бинарник (`outline-ws-rust`): клиент строит свои исходящие профили браузеров (`Chrome`, `Firefox`, `Safari`) независимо в `crates/outline-transport`.
- Mesh-кластер: межсерверное взаимодействие работает по изолированному протоколу QUIC mesh.
- Протоколы туннелей (Shadowsocks AEAD, SS2022, VLESS): wire-формат внутри туннельных соединений не меняется.

---

## 2. Сравнение было / станет / Caddy

| Область | Сейчас (rustls + hyper) | Станет | Эталон Caddy (Go 1.26) |
|---|---|---|---|
| **Заголовок `Server`** | Не выставляется | `Server: Caddy` | `Server: Caddy` (`modules_caddyhttp_server.go:594`) |
| **Заголовок `Alt-Svc`** | Выставляется только при явной настройке | `h3=":443"; ma=2592000` на всех h1/h2 ответах | `h3=":443"; ma=2592000` (`http3_server.go:399`) |
| **Fallback при отсутствии маршрута** | `404 Not Found` (или fallback прокси) | Пустой `200 OK` с `Content-Length: 0` (если fallback не задан) | Пустой `200 OK` (`emptyHandler` в Caddy) |
| **HTTP-запрос на TLS-порт** | Сброс соединения / TLS alert | `HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n` | В точности те же байты (`net_http_server.go:1930`) |
| **Запрос HTTP/1.1 без `Host`** | Hyper 400 Bad Request | `400 Bad Request\r\n\r\nmissing required Host header` | В точности те же байты (`net_http_server.go:950`) |
| **H2 `MAX_CONCURRENT_STREAMS`** | Дефолт hyper (unlimited / 200) | `250` | `250` (`x/net/http2` default) |
| **H2 `MAX_FRAME_SIZE`** | 16384 | `1048576` (1 MiB) | `1048576` (`x/net/http2` Caddy config) |
| **H2 Окно соединения** | 65535 (или tuning) | `1048576` (1 MiB) через `WINDOW_UPDATE 983041` | `1048576` (`x/net/http2`) |
| **H2 Серверные PING** | Нет | Нет (без изменений) | Нет (`ReadIdleTimeout` = 0) |
| **H2 Extended CONNECT** | `ENABLE_CONNECT_PROTOCOL=1` | `ENABLE_CONNECT_PROTOCOL=1` (см. обоснование ниже) | В штатном Go выключен, включается `GODEBUG=http2xconnect=1` |
| **TLS 1.3 Порядок ServerHello** | `key_share, [psk], supported_versions` | `supported_versions, key_share, [psk]` | `supported_versions, key_share, [psk]` |
| **TLS 1.3 NewSessionTicket** | 2 тикета на 24 часа, nonce 32 байта | 1 тикет на 7 дней (604800 с), nonce пустой | 1 тикет на 7 дней, nonce пустой |
| **TLS Динамический размер записи** | 16384 всегда | Рост от MSS (~1208) до 16384 на первых 128 КиБ | Плавный рост до 128 КиБ потока |

### Обоснование по `ENABLE_CONNECT_PROTOCOL` на HTTP/2
В Go `net/http` поддержка Extended CONNECT (RFC 8441) на HTTP/2 по умолчанию выключена (`disableExtendedConnectProtocol = true`) и активируется только флагом `http2xconnect=1`.
Однако в нашем стеке носитель `ws_h2` использует RFC 8441 для рукопожатия WebSocket поверх одного H2-соединения.
- Отключение Extended CONNECT сломает клиентов на `ws_h2`.
- Поэтому на сервере параметр сохраняется (эмулируя Caddy с поддержкой xconnect/WebTransport).
- Клиентам в рекомендациях и профилях рекомендуется приоритет `xhttp_h2` (где CONNECT не требуется вовсе — чистые GET/POST) либо `ws_h3`.

---

## 3. Детали реализации

### Фаза 2.1: HTTP-слой и fallback-ответы (`outline-ss-rust`)
Файл: `bins/outline-ss-rust/src/server/bootstrap/axum.rs` и `bins/outline-ss-rust/src/server/bootstrap/tls.rs`.
1. **Глобальные заголовки ответов**:
   - Добавить middleware / заголовочный слой:
     - `Server: Caddy`
     - Если H3-листенер активен на порту `P`: `Alt-Svc: h3=":P"; ma=2592000`
2. **Обработка неизвестных маршрутов (`fallback`)**:
   - Если секция `[http_fallback]` отсутствует, вместо `StatusCode::NOT_FOUND` отдавать:
     - Статус: `200 OK`
     - Заголовки: `Server: Caddy`, `Content-Length: 0`, `Date: <RFC7231>`
     - Тело: пустое
3. **Обработка открытого HTTP на HTTPS порту**:
   - На TLS-акцепторе перехватывать первые 4 байта (`GET `, `POST`, `HEAD`). Если первый байт соответствует ASCII методу HTTP, сразу отдавать в сокет сырой ответ Go:
     `b"HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n"`
     и закрывать сокет.

### Фаза 2.2: Настройка HTTP/2 в hyper
Файл: `bins/outline-ss-rust/src/server/bootstrap/axum.rs`.
1. Инициализация `hyper::server::conn::http2::Builder`:
   - `max_concurrent_streams(250)`
   - `max_frame_size(1048576)`
   - `initial_connection_window_size(1048576)`
   - `initial_stream_window_size(1048576)`
   - Отключение keep-alive ping со стороны сервера (дефолт Go).

### Фаза 2.3: Настройка параметров TLS 1.3 / ServerHello (`vendor/rustls`)
Файлы: `vendor/rustls/src/server/hs.rs`, `vendor/rustls/src/server/tls13.rs`.
1. **Порядок расширений ServerHello**:
   - Выстроить запись расширений ServerHello:
     `0x002b (supported_versions)` -> `0x0033 (key_share)` -> `0x0029 (pre_shared_key)`.
2. **Session Tickets**:
   - В `emit_ticket`: выставлять `lifetime = 604800` (7 суток).
   - Число тикетов: 1 (вместо 2).
   - Длина `ticket_nonce`: 0 (пустой слайс).
3. **Динамический размер записи**:
   - Ограничение размера первых записей до достижения порога 128 КиБ (`recordSizeBoostThreshold`).

---

## 4. План тестирования

Файл тестов: `bins/outline-ss-rust/src/server/tests/tcp_caddy_emulation.rs`.
1. `test_plaintext_http_on_tls_port_matches_go`:
   - Подключение сырым TCP сокетом к порту 443, отправка `GET / HTTP/1.1\r\nHost: test\r\n\r\n`.
   - Проверка побайтового совпадения с `"HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n"`.
2. `test_caddy_empty_fallback_response`:
   - TLS-запрос на неизвестный путь без настроенного fallback.
   - Проверка статуса `200 OK`, пустого тела, заголовков `Server: Caddy` и `Alt-Svc`.
3. `test_h2_settings_and_windows`:
   - Подключение H2 клиентом.
   - Захват кадра SETTINGS: проверка значений `MAX_CONCURRENT_STREAMS = 250`, `MAX_FRAME_SIZE = 1048576`, окон.
4. `test_tls13_server_hello_and_ticket`:
   - Захват ServerHello и NewSessionTicket: проверка порядка расширений, времени жизни 604800с и пустого nonce.

---

## 5. Порядок реализации и гейт
1. Реализация Фазы 2.1 и 2.2 (HTTP-ответы и настройки H2 в `outline-ss-rust`).
2. Прогон тестов HTTP-маскировки.
3. Реализация Фазы 2.3 (TLS-отпечаток в `vendor/rustls`).
4. Прогон полного локального CI-гейта (`fmt`, `clippy`, `test`, `e2e`, checks).
5. Все коммиты строго в текущей ветке `caddy-masking`.
