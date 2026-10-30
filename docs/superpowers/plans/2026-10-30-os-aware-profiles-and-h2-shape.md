# Профиль браузера под реальную ОС и дешёвая подгонка HTTP/2 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** (1) Браузерный профиль клиента выбирается из пула, совместимого с ОС, на которой он реально работает (на Linux/Android не бывает Safari, UA называет ту же ОС, что видна по TCP), с актуальными версиями (Chrome 156, Firefox 159, Safari 27). (2) HTTP/2-носители (ws_h2, xhttp_h2) без вендоринга `h2` становятся ближе к браузеру: значения SETTINGS и окна соединения по профилю, браузерный порядок обычных заголовков, без заголовка `host`.

**Architecture:** В `fingerprint_profile::Profile` добавляется поле `os`; `PROFILES` — общий каталог, а выбор (`select_with_strategy`, `process_index`, `host_index`, `Random`) идёт по под-пулу текущей ОС (`cfg!(target_os)`), с внутренней функцией, принимающей ОС явно, для тестов. HTTP/2: новый модуль `h2_profile.rs` в `outline-transport` отдаёт настройки hyper `http2::Builder` для профиля (`TlsFingerprint`) и порядок заголовков; `h2/shared.rs` и `xhttp/h2.rs` берут их вместо нынешних значений, когда профиль активен; без профиля — Chromium, как у TLS.

**Tech Stack:** Rust 2024, hyper 1.x (`hyper::client::conn::http2::Builder`), крейт `h2` 0.4 (не вендорится), tshark 4.6.

**Предыстория:** TLS ClientHello TCP и QUIC уже как у браузеров (`1b64d765`). Замер HTTP/2 — память проекта `h2-fingerprint-vs-browsers`; инструменты в scratchpad `h2fp/` (`h2-sink.py`, `fp.py`, `hdrs.py`, CA `ca.pem`/`ca.der`, захваты `chrome.pcap`/`ff.pcap`/`apple.pcap`/`ours-*.pcap`). TCP-hello — память `tcp-tls-clienthello-vs-browsers`. Чеклист обновления пула профилей — память `fingerprint-refresh-checklist` (имена профилей продублированы литералами в нескольких крейтах — все места перечислены в Task 1).

## Global Constraints

- Комментарии в коде, commit-сообщения и PR — на английском; план и чат — на русском. Термины: «носитель», «гейт».
- Никогда не добавлять трейлер `Co-Authored-By: Claude` и футер «Generated with Claude Code».
- Коммит и push — только по явной команде владельца. Работать в `main`. Исполнители задач НЕ коммитят: одобренное складывается в индекс, следующая задача ревьюится по незастейдженному diff.
- Тесты — в `tests/` рядом с модулем (как принято в крейте: `#[path = "tests/<name>.rs"] mod tests;` или регистрация в `src/tests/mod.rs`); inline `mod tests {}` запрещены.
- Гейт (ровно эти команды):
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
  плюс `cargo check -p outline-ws-rust --no-default-features`, `cargo check -p outline-ss-rust --no-default-features`. Известные флейки: `outline-tun health_recovery::tun_downlink_traffic_restores_uplink_health_without_probe`, `outline-uplink loss::tests::a_vanished_carrier_contributes_no_window` (linux) — при единственном падении перезапустить и указать оба прогона.
- **Никогда `cargo fmt --all`**; `vendor/` не трогать.
- Двуязычные доки парой (`*.md`/`*.ru.md`, CHANGELOG EN/RU).
- Сервер (`outline-ss-rust`) не меняется. Поведение без профиля (`Strategy::None`) по HTTP-заголовкам не меняется (заголовки не добавляются); для TLS/h2 `None` = Chromium.
- Значения заголовков и версии — только из таблицы «Замеры» ниже или из официальных источников (Chrome VersionHistory, Mozilla product-details, Edge release notes) — не из головы.
- Выкатка — только по команде владельца, по одному узлу.

## Замеры (2026-10-30)

HTTP/2 (Akamai: SETTINGS | connection WINDOW_UPDATE | PRIORITY | псевдо):

| | SETTINGS (порядок как на проводе) | conn WU | приоритет | псевдо |
|---|---|---|---|---|
| Chrome 156 | 1:65536, 2:0, 4:6291456, 6:262144 | 15663105 (окно 15728640) | флаг в HEADERS | m,a,s,p |
| Firefox 159 | 1:65536, 2:0, 4:131072, 5:16384 | 12517377 (окно 12582912) | флаг в HEADERS, первый поток 3 | m,p,a,s |
| Apple URLSession (macOS 27) | 2:0, 4:4194304, 3:100, 9:1 | 10485760 (окно 10551295) | нет | m,s,p,a |
| наш ws_h2 | 2:0, 4:8388608, 5:16384, 6:16384 | 33488897 | нет | m,s,a,p(+:protocol) |
| наш xhttp_h2 | 2:0, 4:2097152, 5:16384, 6:16384 | 5177345 | нет | m,s,a,p + `host` |

Крейт `h2` пишет SETTINGS в порядке 1,2,3,4,5,6,8 и только заданные; 9 не поддерживает; псевдозаголовки — всегда m,s,a,p; флаг приоритета в HEADERS не ставит. Это не меняем (решение владельца: без вендоринга).

Заголовки запроса (навигация; первые HEADERS):
- Chrome 156 (macOS): `sec-ch-ua: "Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156"`, `sec-ch-ua-mobile: ?0`, `sec-ch-ua-platform: "macOS"`, `upgrade-insecure-requests: 1`, `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36` (в захвате `HeadlessChrome/` — headless-артефакт, в профиль идёт `Chrome/`), `accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`, `sec-fetch-site: none`, `sec-fetch-mode: navigate`, `sec-fetch-user: ?1`, `sec-fetch-dest: document`, `accept-encoding: gzip, deflate, br, zstd`, `accept-language: …`, `priority: u=0, i`. Порядок именно такой.
- Firefox 159 (macOS): `user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:159.0) Gecko/20100101 Firefox/159.0`, `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`, `accept-language: en-US,en;q=0.9`, `accept-encoding: gzip, deflate, br, zstd`, `upgrade-insecure-requests: 1`, `sec-fetch-dest: document`, `sec-fetch-mode: navigate`, `sec-fetch-site: none`, `priority: u=0, i`, `te: trailers`. Порядок именно такой.
- Safari: установлен Safari 27.0.1 (macOS 27.0.1) → UA `… Version/27.0 Safari/605.1.15` (версия major.minor, как сейчас в пуле `Version/26.0`). Порядок/значения заголовков Safari не сняты (URLSession — не Safari); оставить текущие значения профиля.

Наш клиент сейчас: пул из 6 профилей (chrome-151-windows, chrome-151-macos, firefox-152-windows, firefox-152-macos, safari-26-macos, edge-150-windows) на ЛЮБОЙ ОС; клиенты парка работают на Linux, Android-приложение — на Android. TCP SYN (TTL 64, опции Linux) виден DPI рядом с ClientHello: hello Safari (или Edge/Windows) из Linux-стека — несовместимая пара.

## Решения (владелец, 2026-10-30)

1. **Профиль по ОС.** Под-пулы:
   - macOS (`target_os = "macos"`): `chrome-156-macos`, `firefox-159-macos`, `safari-27-macos`;
   - Linux (`target_os = "linux"`, не Android): `chrome-156-linux`, `firefox-159-linux`;
   - Android (`target_os = "android"`): `chrome-156-android`;
   - Windows (`target_os = "windows"`): `chrome-156-windows`, `firefox-159-windows`, `edge-<актуальная>-windows`;
   - любая другая ОС: пул Linux.
   Профили других ОС остаются в каталоге `PROFILES` (тесты, снапшоты), но не выбираются. Стратегии (`per_host_stable`, `process_stable`, `random`) работают по под-пулу.
2. **Новые профили:** Linux Chrome — UA `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36`, `sec-ch-ua-platform: "Linux"`; Linux Firefox — `Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0`; Android Chrome — `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36` (замороженный вид UA Reduction), `sec-ch-ua-mobile: ?1`, `sec-ch-ua-platform: "Android"`. Остальные поля Chrome/Firefox — из «Замеров». Edge — версия из официальных release notes на дату выполнения; если не удаётся проверить — STOP и вопрос.
3. **TLS-семейство** профиля не меняется по ОС (Chrome Android → Chromium hello, как desktop). Отдельный замер hello Chrome Android не делался — записать как известное допущение. **Обновление 2026-10-30:** подтверждено замером — Chrome Android 156.0.8078.73 на Android 17 шлёт тот же ClientHello, что и десктопный Chrome 156, байт в байт, включая trust anchors (Samsung Internet 30 = Chrome 140: без trust anchors и без сигнатурных алгоритмов ML-DSA/GREASE); допущения больше нет.
4. **0-RTT отложен** (решение владельца): записать как известное отличие.
5. **HTTP/2, дешёвая часть:** по `TlsFingerprint` профиля (None → Chromium):
   - SETTINGS через `http2::Builder`: Chromium — `header_table_size(65536)`, `initial_stream_window_size(6291456)`, `max_header_list_size(262144)`, окно соединения 15728640, `max_frame_size` НЕ задавать (Chrome его не шлёт); Firefox — `header_table_size(65536)`, `initial_stream_window_size(131072)`, `max_frame_size(16384)`, `max_header_list_size` не задавать, окно соединения 12582912; Safari — `initial_stream_window_size(4194304)`, `max_concurrent_streams(100)` если hyper-клиент даёт его выставить в SETTINGS (если нет — пропустить), окно соединения 10551295; `ENABLE_PUSH=0` hyper шлёт сам.
   - **Обновление 2026-10-30 (решение владельца после замера):** окна (stream / connection) НЕ браузерные — у всех семейств прежние значения носителя: ws_h2 8 МиБ / 32 МиБ, xhttp_h2 2 МиБ / 5 МиБ. Причина: окна видит только TLS-терминатор, а браузерные (15 МиБ соединение) вдвое режут мультиплекс ws_h2 при RTT 300 мс (~38 против ~72 МБ/с на 4 потоках). Значения окон ниже в этом пункте устарели.
   - **Окно потока Firefox (128 KiB) — проверить на пропускную способность**: настоящий Firefox сразу после HEADERS шлёт WINDOW_UPDATE потока на 12451840; hyper так не умеет. Если 128 KiB даёт заметную деградацию (e2e/локальный замер скачивания через ws_h2 с RTT ≥ 50 мс), использовать для Firefox окно потока Chromium и задокументировать отличие. Решение исполнитель фиксирует замером в отчёте.
   - Конфиг `[h2]` (окна, заданные оператором) по-прежнему имеет приоритет над профилем; это отличие документируется.
   - Убрать заголовок `host` из h2-запросов xhttp (в h2 его роль играет `:authority`; браузеры его не шлют). h1 не трогать.
   - Порядок обычных заголовков на h2 — как у браузера профиля (Chrome/Firefox из «Замеров»; Safari — текущий). Служебные `x-outline-resume-*` и `sec-websocket-*` — после браузерных. Порядок задаётся порядком вставки в `HeaderMap` (hyper/h2 кодируют в порядке итерации) — проверить тестом по реально закодированным HEADERS.
   - Псевдозаголовки, флаг приоритета, первый поток Firefox (=3), SETTINGS 9 и порядок 3/4 у Safari — не подгоняются (нужен вендоринг h2).

## File Structure

| Файл | Действие | Ответственность |
|---|---|---|
| `crates/outline-transport/src/fingerprint_profile.rs` | изменить | поле `os`, новые/обновлённые профили, под-пулы по ОС, `PROFILES_REFRESHED_AT_UNIX` |
| `crates/outline-transport/src/tests/fingerprint_profile.rs` | изменить | тесты под-пулов и значений |
| места с литералами имён профилей (см. Task 1) | изменить | новые имена |
| `crates/outline-transport/src/h2_profile.rs` | создать | настройки `http2::Builder` и порядок заголовков по `TlsFingerprint` |
| `crates/outline-transport/src/tests/h2_profile.rs` | создать | тесты значений и закодированного порядка |
| `crates/outline-transport/src/h2/shared.rs`, `crates/outline-transport/src/xhttp/h2.rs` | изменить | применение `h2_profile`, без `host` |
| `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md` / `.ru.md`, `bins/outline-ws-rust/CHANGELOG.md` / `.ru.md` | изменить | доки |

---

### Task 1: Пул профилей по ОС и обновление версий

**Files:** `crates/outline-transport/src/fingerprint_profile.rs`, `crates/outline-transport/src/tests/fingerprint_profile.rs`, и все места с литералами имён профилей: `crates/outline-uplink/src/tests/mod.rs` (`snapshot_reports_fingerprint_profile_name_per_strategy`, список `pool`), `crates/outline-metrics/src/snapshot_types.rs` (doc-примеры), `bins/outline-ws-rust/src/http/control/topology.rs` (doc), `bins/outline-ws-rust/src/http/control/tests/mod.rs` (мок + assert), `bins/outline-ws-rust/src/http/dashboard/dashboard.html` (JS-комментарии, если файл ещё существует), `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md` + `.ru.md`, CHANGELOG EN/RU. Перед правкой: `grep -rn "chrome-15\|firefox-15\|safari-26\|edge-15" --include=*.rs --include=*.md --include=*.html .` (исключая `target/`, `vendor/`, `docs/superpowers/`).

**Interfaces:**
- Produces: `pub enum ProfileOs { Windows, MacOs, Linux, Android }`; `Profile::os: ProfileOs`; `pub fn host_os() -> ProfileOs` (по `cfg!(target_os)`, прочие → Linux); `pub(crate) fn pool_for(os: ProfileOs) -> impl Iterator<Item=&'static Profile>` или срез индексов; `select_with_strategy` выбирает из `pool_for(host_os())`; тестируемый вариант `select_with_strategy_for_os(url, strategy, os)`.

- [ ] **Step 1: Тесты (падают).** (1) `pool_for(MacOs)` = {chrome-156-macos, firefox-159-macos, safari-27-macos}; `Linux` = {chrome-156-linux, firefox-159-linux}; `Android` = {chrome-156-android}; `Windows` = {chrome-156-windows, firefox-159-windows, edge-…-windows}. (2) Ни один профиль под-пула Linux/Android не имеет `tls == Safari`. (3) Для каждой ОС и каждой стратегии `select_with_strategy_for_os` возвращает профиль этой ОС (PerHostStable — на 50 разных url; Random — 200 раз). (4) Значения Chrome 156 / Firefox 159 / Safari 27 (UA, accept, accept-language, accept-encoding, sec-ch-ua*) побайтово как в «Замерах»/«Решениях». (5) UA каждого профиля согласован с его `os` (Windows → `Windows NT`, macOS → `Macintosh`, Linux → `X11; Linux`, Android → `Linux; Android`) и `sec_ch_ua_platform` (для Chromium). (6) Имена профилей уникальны.
- [ ] **Step 2: Реализация** + bump `PROFILES_REFRESHED_AT_UNIX` (`date +%s` на момент выполнения) + все литералы имён из списка выше. `process_index`/`host_index` — индекс в под-пуле. Обновить rustdoc таблицы (доли браузеров по ОС).
- [ ] **Step 3:** `cargo test --workspace --exclude sockudo-ws` (литералы падают в других крейтах) и `grep` из списка — пусто для старых имён. Android: `(cd android/rust && cargo clippy --no-deps -- -D warnings)` и проверка, что `cfg!(target_os = "android")` реально выбирает Android-пул (тест с `#[cfg(target_os = "android")]` не запустить на маке — достаточно юнит-теста `pool_for(Android)` + review кода `host_os`).
- [ ] **Step 4:** Гейт целиком. Доки: UPLINK-CONFIGURATIONS EN/RU (список профилей и правило ОС), CHANGELOG EN/RU (Unreleased, Changed): профиль выбирается под ОС клиента, версии, Safari только на macOS, 0-RTT не выровнен (решение 4), Chrome Android hello = desktop (решение 3).

### Task 2: HTTP/2-носители — SETTINGS, окна, порядок заголовков, без `host`

**Files:** создать `crates/outline-transport/src/h2_profile.rs` + `src/tests/h2_profile.rs`; изменить `crates/outline-transport/src/h2/shared.rs` (билдер ~строка 541, сборка запроса), `crates/outline-transport/src/xhttp/h2.rs` (билдер ~512, сборка запроса и `host`), места вставки браузерных заголовков (`fingerprint_profile.rs` ~576 `apply`-функция) — порядок вставки; `lib.rs` (модуль).

**Interfaces:**
- Consumes: `fingerprint_profile::current_dial_fingerprint()` (как TLS-билдеры), `Profile` (Task 1).
- Produces: `pub(crate) struct H2Shape { header_table_size: Option<u32>, initial_stream_window: u32, initial_connection_window: u32, max_frame_size: Option<u32>, max_header_list_size: Option<u32>, max_concurrent_streams: Option<u32> }`, `pub(crate) fn h2_shape(fp: Option<TlsFingerprint>) -> H2Shape` (значения из решения 5), `pub(crate) fn apply_h2_shape(builder: &mut http2::Builder<…>, shape: &H2Shape, operator: Option<(u32,u32)>)` — окна оператора из `[h2]` побеждают; функция/таблица порядка браузерных заголовков, которую использует вставка заголовков профиля.

- [ ] **Step 1: Тесты (падают).** (1) `h2_shape` для None/Chromium/Firefox/Safari = значения решения 5. (2) Захват реального клиентского префикса: поднять в тесте TCP-слушатель без TLS (или in-memory duplex) и выполнить `http2::Builder::handshake` с `apply_h2_shape` + один запрос как в xhttp/ws_h2 — разобрать SETTINGS (порядок id и значения) и conn WINDOW_UPDATE из байтов; для Chromium ожидается `1:65536, 2:0, 4:6291456, 6:262144` и инкремент 15663105; для Firefox `1:65536, 2:0, 4:131072 (или окно по итогам замера), 5:16384` и 12517377. (3) Декодировать HEADERS этого запроса (HPACK — крейт `hpack`/`h2`-внутренности недоступны; допустимо подключить dev-dependency `hpack` или проверить порядок через сервер `h2::server` в том же тесте, получив `http::Request` и сравнив порядок `headers().keys()`) — порядок обычных заголовков = браузерному для профиля, нет `host`, служебные — после браузерных. (4) Оператор задал `[h2]` окна → они в SETTINGS вместо профильных.
- [ ] **Step 2: Реализация** в `h2_profile.rs`; применить в обоих билдерах; убрать `host` из h2-запроса xhttp; привести порядок вставки заголовков профиля к браузерному (только h2-путь; если общий код вставки используется и h1 — порядок для h1 не ухудшать, Host в h1 остаётся первым).
- [ ] **Step 3: Окно потока Firefox.** Локальный замер пропускной способности ws_h2 с окном 131072 против 6291456 (in-process сервер `outline-ss-rust` из e2e-харнесса или любой локальный h2-сервер, RTT эмулировать задержкой в тестовом прокси ≥ 50 мс — или, если эмуляция задержки дорога, оценка расчётом окно/RTT с цифрами) → выбрать по решению 5, записать цифры в отчёт и в rustdoc `h2_shape`.
- [ ] **Step 4:** Гейт целиком (e2e: `e2e_tls_carriers`, `e2e_wire_failover` ходят по h2). Провод: собрать `cargo build -p outline-ws-rust --features test-tls`, для ws_h2 и xhttp_h2 снять кадры `h2fp/h2-sink.py` (CA `h2fp/ca.der` через `OUTLINE_WS_TEST_TLS_CA_DER`, `fingerprint_profile = "random"`, разбор `h2fp/fp.py`) — SETTINGS/WU как у браузера выбранного профиля (кроме невыравниваемого), `host` нет. Доки: CHANGELOG EN/RU (что выровнено и что нет — пункт 5 «не подгоняются»), rustdoc `fingerprint_profile.rs` «does NOT do» (SETTINGS частично теперь да).

## После выполнения

- Финальное ревью серии (opus).
- Память: `h2-fingerprint-vs-browsers` и `fingerprint-refresh-checklist` — отметить результат (новые имена профилей, пул по ОС).
- Коммит/push/выкатка — по командам владельца.
