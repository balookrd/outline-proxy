# Заголовки Safari, таблицы h3 и регистр xhttp по h1 — план

> **Для агентов-исполнителей:** обязательный под-скилл — superpowers:subagent-driven-development. Шаги отмечаются чекбоксами (`- [ ]`).

**Цель:** закрыть четыре оставшихся отличия заголовков носителей от браузеров:
1. Safari не замерен — его таблицы и часть значений профиля исторические.
2. h3 берёт таблицу h2 без замера.
3. `Content-Type` у POST — не проверен замером.
4. `sec-ch-ua*` на `xhttp_h1` уходят с заглавных (hyper умеет только Title-Case целиком).

**Архитектура:** таблицы и значения — в `crates/outline-transport/src/request_headers.rs`; для h3 появляются свои таблицы (`HttpVersion::H3` перестаёт сводиться к h2). Регистр на `xhttp_h1` — через `preserve_header_case` hyper: тип `HeaderCaseMap` у hyper 1.10.1 `pub(crate)`, поэтому hyper вендорится (как rustls / quinn-proto / h3) с патчем «только видимость», доступ к патченому API — через gate-модуль.

**Стек:** Rust, hyper 1.10.1, h2, h3/quinn, vendored rustls.

## Глобальные ограничения

- Все замеры — 2026-10-31, macOS: Chrome 156 (headless), Firefox 159, Safari 27.0.1; same-origin; тело POST — `Uint8Array` (как у xhttp: бинарное).
- Значения переносятся из раздела «Замеры» дословно.
- `Accept-Language` профилей не меняем (`en-US,en;q=0.9`): в замерах он локальный (`ru…`).
- Без профиля (`Strategy::None`) провод не меняется.
- Окна h2/QUIC, псевдозаголовки, SETTINGS — вне задачи.
- Тесты — в `tests/` рядом с модулем (правило репозитория), `cargo fmt` по нашим крейтам и `cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings` (как в CI), плюс android-воркспейс.
- Документация EN/RU обновляется парой.
- Linux-специфики нет, но перед коммитом — прогон в docker (правило памяти).

---

## Замеры (2026-10-31)

Стенды: scratchpad `hdr31/` (h1, `rawsink.py` — пишет заголовки как есть, с регистром), `h2fp/h2-sink.py` (h2, ENABLE_CONNECT_PROTOCOL=1), `h3sink/` (docker, aioquic 1.2.0; Chrome — `--origin-to-force-quic-on` + `--ignore-certificate-errors-spki-list`; Firefox — `Alt-Svc` + тестовый CA в базе временного профиля + `network.http.http3.disable_when_third_party_roots_found=false`).

### Content-Type

Все три браузера, h1/h2/h3: POST с бинарным телом — **без `Content-Type`**; со строковым — `text/plain;charset=UTF-8`. Наш xhttp его не шлёт — совпадает. Меняется только формулировка в документации.

### Safari 27.0.1 (h1 по TLS = h1 по http, порядок стабилен)

UA: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0.1 Safari/605.1.15`.
`Accept-Encoding` по HTTPS: `gzip, deflate, br, zstd` (по http — `gzip, deflate`).
Регистр h1 — канонический у всех имён (`Sec-Fetch-Dest`, `Sec-WebSocket-Version`).
`Priority: u=3, i`; `Accept: */*` в fetch и WebSocket; `Sec-WebSocket-Extensions: permessage-deflate`; `Sec-Fetch-Dest: websocket` у WebSocket.

fetch GET, h1: `Host, Sec-Fetch-Dest, User-Agent, Accept, Referer, Sec-Fetch-Site, Sec-Fetch-Mode, Accept-Language, Priority, Accept-Encoding, Connection`
fetch POST, h1: `Host, Accept, Origin, Sec-Fetch-Site, Sec-Fetch-Mode, User-Agent, Referer, Sec-Fetch-Dest, Content-Length, Accept-Language, Priority, Accept-Encoding, Connection`
WebSocket, h1: `Host, Origin, Pragma, Sec-Fetch-Site, Sec-WebSocket-Version, Sec-Fetch-Mode, User-Agent, Sec-WebSocket-Extensions, Cache-Control, Sec-Fetch-Dest, Accept, Accept-Language, Priority, Accept-Encoding, Sec-WebSocket-Key, Connection, Upgrade`
fetch GET, h2: `sec-fetch-dest, user-agent, accept, referer, sec-fetch-site, sec-fetch-mode, accept-language, priority, accept-encoding`
fetch POST, h2: `accept, origin, sec-fetch-site, sec-fetch-mode, user-agent, referer, sec-fetch-dest, content-length, accept-language, priority, accept-encoding`
WebSocket, h2 (**Safari 27 делает RFC 8441 extended CONNECT**): `origin, pragma, sec-fetch-site, sec-websocket-version, sec-fetch-mode, user-agent, sec-websocket-extensions, cache-control, sec-fetch-dest, accept, accept-language, priority, accept-encoding`

Порядок GET и POST у Safari разный — таблицы fetch для Safari раздельные по виду запроса.

### h3

- **Chrome 156:** fetch GET и POST — порядок ровно как `CHROMIUM_FETCH_H2`, значения те же (`priority: u=1, i`). WebSocket по h3 Chrome не делает (как и по h2).
- **Firefox 159:** fetch — как `FIREFOX_FETCH_H2`, но **без `te: trailers`** и с **`alt-used: <authority>`** непосредственно перед `sec-fetch-dest`. WebSocket по h3 не наблюдался (ушёл по TCP).
- **Safari:** не замерен (нужен доверенный сертификат и Alt-Svc) — берёт свою таблицу h2, это допущение.

`alt-used` замерен на нестандартном порту (`localtest.me:8629`); для 443 пишем authority без порта, как `:authority` (допущение, отметить в документации).

---

## Файлы

- Изменить: `crates/outline-transport/src/request_headers.rs` — таблицы Safari, h3, новые поля `AltUsed`; значения Safari; `h1_browser_case`/`h1_wire_name` — Safari канонический регистр; модульная документация.
- Изменить: `crates/outline-transport/src/fingerprint_profile.rs` — профиль `safari-27-macos`: UA `Version/27.0.1`, `accept_encoding` с `zstd` (комментарий «Safari не шлёт zstd» — убрать).
- Изменить: `crates/outline-transport/src/tests/request_headers.rs`, `crates/outline-transport/src/tests/fingerprint_profile.rs`, `crates/outline-transport/src/xhttp/tests/post_headers.rs`, `crates/outline-transport/src/tests/ws_h1.rs`.
- Создать: `vendor/hyper/` (копия crates.io `hyper 1.10.1`), `hyper-1.10.1.patch`, gate `crates/outline-transport/src/hyper_vendored.rs`.
- Изменить: корневой `Cargo.toml` и `android/rust/Cargo.toml` (`[patch.crates-io] hyper`), `PATCHES.md`/`PATCHES.ru.md`, `.github/workflows/ci.yml` (инвариант gate-модуля).
- Изменить: `crates/outline-transport/src/xhttp/h1.rs` — `preserve_header_case(true)` + карта регистра вместо `title_case_headers`.
- Изменить: `bins/outline-ws-rust/CHANGELOG.md`/`.ru.md`, `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md`/`.ru.md`.

---

### Task 1: Safari по замеру (таблицы, значения, профиль, регистр h1)

**Interfaces:** `table(family, kind, version)` начинает различать `FetchGet`/`FetchPost` для Safari; `h1_browser_case` возвращает `true` и для Safari; `h1_wire_name` для Safari — `canonical_case`.

- [ ] Тесты (сначала, падают): таблицы Safari для fetch GET / POST / WebSocket на h1 и h2 дословно из «Замеров» (имена и порядок); значения Safari: `accept: */*`, `priority: u=3, i`, `sec-websocket-extensions: permessage-deflate`, `sec-fetch-dest: websocket` у WS, `empty` у fetch; профиль: UA с `Version/27.0.1`, `accept_encoding = "gzip, deflate, br, zstd"`; `ws_h1` Safari пишет имена в каноническом регистре (`Sec-Fetch-Dest`, `Sec-WebSocket-Key`), `Sec-WebSocket-Key`, `Connection`, `Upgrade` — в конце, как в замере.
- [ ] Реализация: заменить `SAFARI_*` таблицы на измеренные (раздельные GET/POST), снять ветки «Safari not aligned» в `field_value` (`Accept`, `Priority`, `Sec-WebSocket-Extensions`), обновить профиль.
- [ ] `cargo test -p outline-transport --all-features` зелёный.

### Task 2: свои таблицы h3

**Interfaces:** новый `Field::AltUsed` (значение — authority запроса без порта по умолчанию, то есть `origin` без схемы); `table()` для `HttpVersion::H3`: Chromium → `CHROMIUM_*_H2`; Firefox fetch → `FIREFOX_FETCH_H3` (= h2 без `Te`, с `AltUsed` перед `SecFetchDest`); Firefox WS → `FIREFOX_WS_H2`; Safari → свои h2-таблицы.

- [ ] Тесты (падают): h3 Chromium = h2 Chromium; h3 Firefox fetch GET/POST — порядок и `alt-used: host[:port]` (порт по умолчанию опущен), без `te`; h2 Firefox по-прежнему с `te: trailers`.
- [ ] Реализация; снять `cfg_attr(... dead_code)` с `H3`, если он теперь используется везде; обновить doc-комментарий `HttpVersion::H3`.
- [ ] Проверить, что `xhttp/h3.rs` и `h3/shared.rs` передают `HttpVersion::H3` (а не H2).
- [ ] Тесты `outline-transport --all-features` зелёные.

### Task 3: регистр xhttp_h1 через vendored hyper

**Interfaces:** gate `hyper_vendored::header_case_map(headers: &HeaderMap, profile: Option<&Profile>) -> HeaderCaseMap` (имена через `request_headers::h1_wire_name`) и функция, кладущая карту в `request.extensions_mut()`. Патченый API hyper упоминается только в gate-модуле (инвариант CI).

- [ ] Вендорить `hyper 1.10.1` в `vendor/hyper` (копия из `~/.cargo/registry/src/*/hyper-1.10.1`, без изменений), подключить в оба `[patch.crates-io]`; убедиться, что сборка без патча кода зелёная.
- [ ] Патч (только видимость/конструктор): `ext::HeaderCaseMap` — `pub`, публичные `new()`/`append(&HeaderName, Bytes)` (или `insert`), реэкспорт из `hyper::ext`. Поведение hyper не меняется. Сгенерировать `hyper-1.10.1.patch`, описать в `PATCHES.md`/`PATCHES.ru.md` (раздел, список в шапке, gate-модуль, «Regenerating»).
- [ ] CI: шаг-инвариант «patched hyper API only behind the gate module» по образцу rustls.
- [ ] Тест (падает): `xhttp/tests/post_headers.rs` — проводной захват h1 GET и POST: Chromium `sec-ch-ua*` строчными, остальные канонически; Firefox и Safari — канонически; без профиля — как раньше (Title-Case hyper не включается). Обновить/убрать `hyper_title_case` хелпер.
- [ ] Реализация в `xhttp/h1.rs`: `http1::Builder::preserve_header_case(true)` (вместо `title_case_headers`), на каждый запрос — карта регистра из gate-модуля.
- [ ] Тесты `outline-transport --all-features`, clippy как в CI, android `cargo clippy --no-deps -- -D warnings`.

### Task 4: документация и замер провода

- [ ] Модульная документация `request_headers.rs`: Safari выровнен по замеру; h3 — Chromium/Firefox замерены, Safari h3 = h2 (допущение); `Content-Type` — замерено; регистр h1 — браузерный везде; `alt-used` для 443 — допущение.
- [ ] CHANGELOG EN/RU (раздел Unreleased) и `UPLINK-CONFIGURATIONS` EN/RU — убрать снятые оговорки, описать новое.
- [ ] Проверка провода: наш клиент (`--features test-tls`) через `rawsink.py`/`h2-sink.py` — xhttp_h1, xhttp_h2, ws_h1, ws_h2 с профилями Chrome/Firefox/Safari совпадают с замером (кроме собственных `x-outline-*`).
- [ ] Linux docker: тесты workspace.

## Порядок выкатки

Только клиент (`outline-ws-rust`, Android). Сервер не меняется: hyper патчится лишь по видимости, поведение ss-rust прежнее. Раскатка вместе с предыдущими неразвёрнутыми коммитами (`1b64d765`, `cc6407a6`, `74b970d6`), по одному узлу.
