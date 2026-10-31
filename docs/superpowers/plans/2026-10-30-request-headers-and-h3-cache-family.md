# Заголовки fetch/WebSocket как у браузера и ключ H3-кэша по семейству — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** (1) Заголовки запросов носителей повторяют браузер профиля для того типа запроса, который носитель реально делает (xhttp — `fetch` GET/POST, ws — WebSocket), отдельно для h1 и h2 (h3 — по таблице h2), а не порядок и значения навигации. (2) Общие H3-соединения (`H3ConnectionKey`, `XhttpH3Key`) кэшируются с учётом TLS-семейства браузера, как уже сделано для h2 (`cc6407a6`).

**Architecture:** Вместо `SecFetchPreset` + одного порядка на семейство — таблица шаблонов «семейство × тип запроса × версия HTTP» в `h2_profile.rs` (или новом `request_headers.rs`): упорядоченный список заголовков с источником значения (профиль, константа, `authority`, служебный). `fingerprint_profile::apply`/`apply_h2` заменяются одной функцией построения, вызываемой из всех точек сборки запроса. Ключ H3-кэша получает поле семейства (как h2-ключ), пул слотов и реапер группируют по нему.

**Tech Stack:** Rust 2024, hyper 1.x, tokio-tungstenite, h3/quinn, tshark 4.6.

**Предыстория:** память проекта `request-headers-fetch-ws-vs-browsers` (замер), `h2-fingerprint-vs-browsers`; сырые дампы — scratchpad `h2fp/request-headers-2026-10-30.txt`; стенд — `h2fp/h2-sink.py` (`SINK_PAGE`, `SINK_ALPN`), `h2fp/hdrs-all.py`, CA `h2fp/ca.der`/`chain.pem`/`leaf.key`. Предыдущая серия: `cc6407a6` (профиль на дозвон закреплён `with_dial_profile`; h2-кэш по семейству).

## Global Constraints

- Комментарии в коде, commit-сообщения и PR — на английском; план и чат — на русском. Термины: «носитель», «гейт».
- Никогда не добавлять трейлер `Co-Authored-By: Claude` и футер «Generated with Claude Code».
- Коммит и push — только по явной команде владельца. Работать в `main`. Исполнители НЕ коммитят: одобренное складывается в индекс, следующая задача ревьюится по незастейдженному diff.
- Тесты — в `tests/` рядом с модулем по конвенции крейта; inline `mod tests {}` запрещены.
- Гейт:
  ```bash
  cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
    -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
    -p outline-tun -p outline-uplink -p outline-wire \
    -p shadowsocks-crypto -p socks5-proto
  cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
  cargo test --workspace --exclude sockudo-ws
  RUN_E2E_FAILOVER=1 cargo test -p outline-ws-rust --features test-tls --test 'e2e_*' -- --test-threads=1
  (cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
  ```
  плюс `cargo check -p outline-ws-rust --no-default-features`, `cargo check -p outline-ss-rust --no-default-features`. Известные флейки: `outline-tun health_recovery::tun_downlink_traffic_restores_uplink_health_without_probe`, `outline-uplink loss::tests::a_vanished_carrier_contributes_no_window` (linux).
- **Никогда `cargo fmt --all`**; `vendor/` не трогать. Сервер (`outline-ss-rust`) не менять, кроме случая из решения 4 (только с вопросом владельцу).
- Без профиля (`Strategy::None`) браузерные заголовки не добавляются — как сейчас.
- Двуязычные доки парой (CHANGELOG EN/RU).

## Замеры (2026-10-30, Chrome 156 и Firefox 159 на macOS; страница отдана тем же сервером, запросы same-origin)

Полные дампы — `h2fp/request-headers-2026-10-30.txt`. Сводка порядка (в скобках — что меняется для POST / только в h1 / только в h2):

**Chrome, fetch (`mode: cors`)**
- h2: `[content-length — POST, первым]`, sec-ch-ua-platform, user-agent, sec-ch-ua, `[content-type — POST]`, sec-ch-ua-mobile, accept `*/*`, `[origin — POST]`, sec-fetch-site `same-origin`, sec-fetch-mode `cors`, sec-fetch-dest `empty`, referer, accept-encoding, accept-language, priority `u=1, i`.
- h1: Host, `Connection: keep-alive`, `[Content-Length — POST]`, далее тот же порядок, **без** priority; имена sec-ch-ua* строчными, остальные — с заглавных букв.

**Chrome, WebSocket**
- h1: Host, `Connection: Upgrade`, `Pragma: no-cache`, `Cache-Control: no-cache`, User-Agent, `Upgrade: websocket`, Origin, `Sec-WebSocket-Version: 13`, Accept-Encoding, Accept-Language, Sec-WebSocket-Key, `Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits`.
- h2 (extended CONNECT; Chrome его делает, когда сервер объявил ENABLE_CONNECT_PROTOCOL): pragma, cache-control, user-agent, origin, sec-websocket-version, accept-encoding, accept-language, sec-websocket-extensions.
- **Нет** sec-ch-ua*, sec-fetch-*, accept.

**Firefox, fetch** — порядок навигации, другие значения:
- h2: user-agent, accept `*/*`, accept-language, accept-encoding, referer, `[content-type, content-length, origin — POST]`, sec-fetch-dest `empty`, sec-fetch-mode `cors`, sec-fetch-site `same-origin`, priority `u=4`, te `trailers`.
- h1: Host первым, … `Connection: keep-alive` перед Sec-Fetch-*, Priority `u=4`, **без** te.

**Firefox, WebSocket**
- h2: user-agent, accept `*/*`, accept-language, accept-encoding, sec-websocket-version, origin, sec-websocket-extensions `permessage-deflate`, sec-fetch-dest **`empty`**, sec-fetch-mode `websocket`, sec-fetch-site `same-origin`, pragma, cache-control.
- h1: Host, User-Agent, Accept, Accept-Language, Accept-Encoding, Sec-WebSocket-Version, Origin, Sec-WebSocket-Extensions, `Connection: Upgrade`, Sec-Fetch-Dest `empty`, Sec-Fetch-Mode `websocket`, Sec-Fetch-Site, Pragma, Cache-Control, `Upgrade: websocket` последним.

Content-Type у браузерного POST из JS со строкой — `text/plain;charset=UTF-8` (наш xhttp ставит свой — см. решение 3).

Наш клиент сейчас: для WS шлёт sec-ch-ua* и `sec-fetch-dest: websocket` (ни один браузер так не делает), порядок — навигационный (h2) или исторический (h1/h3); нет origin/referer/priority/pragma/cache-control.

## Решения

1. **Типы запросов:** xhttp GET → «fetch GET», xhttp POST → «fetch POST», ws (h1 upgrade, h2/h3 extended CONNECT) → «WebSocket». Таблицы для Chromium (Chrome и Edge) и Firefox — из «Замеров», h1 и h2 отдельно. **h3 использует таблицу h2** (не замерено; у Chromium и Gecko порядок заголовков h3 формирует тот же код, что для h2 — записать как допущение в rustdoc и CHANGELOG). **Safari** не замерен (URLSession ≠ Safari) — оставить его текущие значения и порядок, записать как не выровненное.
2. **Значения:** `accept: */*` для fetch (если носитель не задаёт свой Accept), `origin: https://<authority>` для POST и WS, `referer: https://<authority>/` для fetch (у Chrome и Firefox; для WS — не слать), `priority` (Chrome h2 `u=1, i`, h1 нет; Firefox `u=4` h1 и h2), `te: trailers` (Firefox h2), `pragma`/`cache-control: no-cache` для WS, `Connection: keep-alive` на h1 fetch — только если стек (hyper) позволяет управлять им без вреда для keep-alive; sec-fetch-site `same-origin`. Chrome WS — без sec-ch-ua*, sec-fetch-*, accept; Firefox WS — `sec-fetch-dest: empty`.
3. **Служебные и носительные заголовки** (`x-outline-*`, `content-type`/`content-length`, которые ставит xhttp, `sec-websocket-key`, `upgrade`, `connection`) — на позиции браузера, если у браузера есть такой заголовок (content-type/content-length/sec-websocket-*), иначе — после браузерных. Значение `content-type` xhttp не меняется (сервер может на него опираться) — отличие записать.
4. **`Sec-WebSocket-Extensions`:** наш клиент `permessage-deflate` не умеет. Слать браузерное значение можно, только если `outline-ss-rust` гарантированно никогда не принимает сжатие (проверить код сервера и его WS-библиотеки `sockudo-ws` с фичей `permessage-deflate`; закрепить тестом «клиент с этим заголовком против нашего сервера → в ответе нет `Sec-WebSocket-Extensions`, данные ходят»). Если сервер может согласовать сжатие — **STOP и вопрос владельцу** (варианты: не слать заголовок или запретить сжатие на сервере).
5. **Регистр имён в h1:** если hyper/tungstenite позволяют задать регистр (Chrome: sec-ch-ua* строчными, остальные Title-Case; Firefox: Title-Case) без вендоринга — сделать; если нет — записать как не выровненное. Порядок, который диктует сам стек (tungstenite ставит Host/Connection/Upgrade/Sec-WebSocket-* сам), — выровнять насколько позволяет публичное API; остальное — записать.
6. **H3-кэш:** в `H3ConnectionKey` и `XhttpH3Key` — семейство TLS (`Option<TlsFingerprint>` нормализованное `None`→Chromium, как в h2). Пул слотов, реапер, счётчики/метрики, которые группируют по базовому ключу, должны продолжать работать корректно (при `process_stable`/`per_host_stable`/`none` — ровно одно семейство на host:port, т.е. поведение не меняется).

## File Structure

| Файл | Действие | Ответственность |
|---|---|---|
| `crates/outline-transport/src/request_headers.rs` (или расширение `h2_profile.rs`) | создать/изменить | таблицы «семейство × тип × версия» и функция построения |
| `crates/outline-transport/src/fingerprint_profile.rs` | изменить | `apply`/`apply_h2`/`SecFetchPreset` → новая функция (или тонкие обёртки) |
| `crates/outline-transport/src/dial_plan.rs` (ws_h1, ~575), `h2/shared.rs` (~364), `h3/shared.rs` (~338), `xhttp/h1.rs` (~277, ~460), `xhttp/h2.rs` (~286, ~696), `xhttp/h3.rs` (~314, ~496) | изменить | вызов новой функции с типом запроса и версией |
| `crates/outline-transport/src/h3/shared.rs` (`H3ConnectionKey`), `crates/outline-transport/src/xhttp/h3_pool.rs` (`XhttpH3Key`) | изменить | ключ по семейству |
| тесты рядом с модулями | создать/изменить | порядок и значения по реально закодированным запросам; ключи H3 |
| `bins/outline-ws-rust/CHANGELOG.md` / `.ru.md` | изменить | что выровнено/нет |

---

### Task 1: Заголовки по типу запроса и версии HTTP

**Interfaces:** Produces: `pub(crate) enum RequestKind { FetchGet, FetchPost, WebSocket }`, `pub(crate) enum HttpVersion { H1, H2, H3 }`, `pub(crate) fn browser_headers(profile: &Profile, kind: RequestKind, version: HttpVersion, authority: &str, headers: &mut HeaderMap)` (или эквивалент, если носителю нужно вставлять свои заголовки в середину — тогда функция, возвращающая упорядоченный план со слотами для носительных заголовков). Consumes: `Profile`, `TlsFingerprint`, закреплённый профиль дозвона (`with_dial_profile`).

- [ ] **Step 1: Проверить решение 4** (сжатие на нашем сервере) — по коду `outline-ss-rust` и `vendor/sockudo-ws`; результат и ссылки на строки — в отчёт. Если сервер может согласовать `permessage-deflate` — STOP (NEEDS_CONTEXT) с фактами.
- [ ] **Step 2: Тесты (падают).** Для Chromium и Firefox × {fetch GET, fetch POST, WebSocket} × {h1, h2} — снять реально закодированный запрос (h2/h3: in-test `h2::server`/hyper-сервер, как в `tests/h2_profile.rs`; h1: сырые байты запроса с in-memory сокета — для xhttp h1 через hyper, для ws_h1 через tokio-tungstenite) и сравнить порядок имён и значения с «Замерами»; допуски — только то, что решения 3/5 разрешают (служебные заголовки, регистр/порядок, который стек не даёт задать), и каждое отличие явно перечислено в тесте. Safari — текущее поведение не меняется (снапшот-тест). `Strategy::None` — браузерных заголовков нет.
- [ ] **Step 3: Реализация** таблиц и функции; перевести все 9 точек вызова; удалить `SecFetchPreset` и `LEGACY_HEADER_ORDER`, если больше не нужны (h3 и h1 теперь по таблицам).
- [ ] **Step 4: Провод.** Собрать `cargo build -p outline-ws-rust --features test-tls`, снять заголовки наших ws_h1, ws_h2, xhttp_h1, xhttp_h2 стендом `h2fp/h2-sink.py` (+ `SINK_ALPN=http/1.1` для h1; `OUTLINE_WS_TEST_TLS_CA_DER=h2fp/ca.der`; `fingerprint_profile = "random"`) и `h2fp/hdrs-all.py`; сравнить с дампами браузеров. Таблица «носитель × семейство → совпало / отличия» — в отчёт.
- [ ] **Step 5:** Гейт целиком; CHANGELOG EN/RU (что выровнено; h3 по таблице h2 — допущение; Safari не выровнен; отличия решений 3/5).

### Task 2: Ключ H3-кэша по семейству

**Files:** `crates/outline-transport/src/h3/shared.rs` (`H3ConnectionKey`, ~74), `crates/outline-transport/src/xhttp/h3_pool.rs` (`XhttpH3Key`, ~93), места, где ключ строится, пул слотов и реапер; тесты рядом.

- [ ] **Step 1: Тесты (падают).** (1) Два дозвона одного host:port под разными закреплёнными семействами получают разные H3-соединения (ws_h3 и xhttp_h3); (2) под одним семейством — общее, как сейчас; (3) `None` и Chromium — один ключ; (4) реапер/пул слотов: соединения разных семейств не вытесняют и не считают друг друга (по фактическому API пула — описать в отчёте, что именно проверено).
- [ ] **Step 2: Реализация** по образцу h2-ключа из `cc6407a6` (семейство читается внутри скоупа дозвона один раз, `None`→Chromium).
- [ ] **Step 3:** Гейт целиком (e2e ходят по h3); CHANGELOG EN/RU — убрать «H3 shared connections are not yet keyed by browser family» из известных ограничений.

## После выполнения

- Финальное ревью серии (opus); Linux docker-прогон `outline-transport` и `outline-uplink`.
- Память: `request-headers-fetch-ws-vs-browsers`, `h2-fingerprint-vs-browsers` — отметить результат.
- Коммит/push/выкатка — по командам владельца.
