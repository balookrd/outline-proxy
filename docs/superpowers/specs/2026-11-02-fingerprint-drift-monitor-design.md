# Монитор дрейфа браузерных отпечатков — дизайн

Дата: 2026-11-02. Статус: реализовано, не закоммичено; amd64-прогон в GitHub не проверен.

## Зачем

Клиент `outline-ws-rust` выдаёт себя за браузер на всех слоях, которые видит или
может увидеть DPI: TCP TLS ClientHello (h1/h2), QUIC Initial (ClientHello и
transport parameters), h2-преамбула (SETTINGS, WINDOW_UPDATE, порядок
псевдозаголовков), заголовки fetch и WebSocket, User-Agent и `sec-ch-ua`.
Профили подогнаны под замеры 2026-10-29…31: Chrome 156, Firefox 159, Apple
(Safari 27 / URLSession).

Регрессии нашего кода уже ловит `cargo test`: hello сверяются с записанными
браузерными хендшейками (`crates/outline-transport/src/tests/fixtures/`), QUIC
Initial расшифровывается и его TP сравниваются с браузерными, h2 и заголовки
проверяются по байтам. Не ловится другое: **браузеры обновляются, а эталоны —
нет.** Chrome выпускает мажор раз в 4 недели; версия зашита в UA и `sec-ch-ua`
(`fingerprint_profile.rs`), а за её возрастом следит только тест, который
падает через 180 дней после `PROFILES_REFRESHED_AT_UNIX`. Изменения самих
hello (так между Chrome 140 и 156 появились trust anchors 51764 и ML-DSA с
GREASE в sig_algs) не замечает никто, пока их не переснимут вручную.

Идея взята у aivpn (`make mask-gate`: настоящий трафик → pcap → TShark/nDPI),
но направлена на дрейф эталона, а не на наш вывод.

## Решение

Еженедельный GitHub Actions-джоб снимает отпечаток свежих Chrome stable и
Firefox release, нормализует его и сравнивает с закоммиченным эталонным
снимком браузера. При расхождении открывается (или обновляется) issue с
диффом.

Сравнивается **браузер с эталоном браузера**, а не с нашим клиентом: проверка не
зависит от Rust-кода, детерминирована и не требует списка намеренных различий
(окна h2, Initial 1200, дробление CRYPTO). Сравнение с нашим клиентом — отдельная
следующая спека.

### Вне рамок

- Apple (Safari, URLSession): образ macOS-раннера отстаёт от релизов, дрейф
  виден с задержкой в месяцы. Переснимается вручную после крупного релиза
  macOS/iOS.
- Сравнение браузера с выводом `outline-ws-rust` и независимая сверка нашего
  парсера через tshark (подход B).
- nDPI-классификация.
- Автоматическое обновление профилей: монитор только сообщает.

## Компоненты

Всё лежит в `scripts/fingerprint-drift/`, Python 3 только на stdlib,
тесты — `unittest`. Разбор протоколов делает tshark.

| Файл | Назначение | Вход → выход |
|---|---|---|
| `tls_sink.py` | TCP-приёмник. Пишет первый ClientHello каждого соединения, затем терминирует TLS эфемерным CA, отвечает на h2 и h1 (страница `page.html`, 200 на fetch, 101 на WebSocket), пишет расшифрованное как h2c/h1 в pcap. На h2 шлёт `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`, на ответ по TCP — `Alt-Svc: h3=":<quic-port>"`. TLS session tickets не выдаёт (`num_tickets = 0`), чтобы последующие соединения браузера не возобновлялись (у возобновлённого hello появляется `pre_shared_key`) | порт, ALPN-режим → `<prefix>-hello.pcap`, `<prefix>-plain.pcap` |
| `scripts/quic-initial-sink.py` | UDP-приёмник Initial-датаграмм — **существующий, не переносится**: на этот путь ссылаются планы 2026-10-29. `capture.sh` вызывает его как есть | порт → `quic.pcap` |
| `page.html` | fetch GET, fetch POST, `new WebSocket` на тот же origin | — |
| `ca.sh` | Генерация эфемерного CA и leaf для `localtest.me` на каждый прогон через openssl CLI (в stdlib нет генерации сертификатов; ключи в репозиторий не кладутся) | → `ca.pem`, `leaf.pem`, `leaf.key`, SPKI-хеш |
| `capture.sh` | Ставит браузеры, поднимает приёмники, гоняет сценарии, пишет `versions.json` | → каталог захвата |
| `normalize.py` | pcap → нормализованный JSON | каталог захвата → `snapshot/{chrome,firefox}.json` |
| `compare.py` | Сравнение эталона со снимком | два JSON → markdown-отчёт, код выхода |
| `baseline/{chrome,firefox}.json` | Эталон | — |
| `tests/` | `unittest` (stdlib) на `normalize` и `compare` | маленькие pcap с localhost |
| `README.md`, `README.ru.md` | Как запустить локально, как обновить эталон | — |

Хост во всех сценариях — `localtest.me` (публично резолвится в 127.0.0.1),
чтобы ушёл SNI.

### `capture.sh`

1. Ставит Chrome stable из apt-репозитория Google и Firefox release из
   apt-репозитория Mozilla (не snap, не ESR). Пишет `versions.json`
   (`google-chrome --version`, `firefox --version`).
2. Генерирует CA (`ca.sh`). Для Firefox создаёт временный профиль, кладёт CA в
   `cert9.db` (`certutil -A -t "C,,"`) и `user.js` с отключённой телеметрией и
   обновлениями. Для Chrome — временный `--user-data-dir`.
3. Запускает браузеры под `xvfb-run`, **не в headless**: headless даёт
   `HeadlessChrome` в UA, а legacy headless не поднимает QUIC.
4. Сценарии для каждого браузера, каждый с таймаутом:
   - **page h2**: открыть `https://localtest.me:<tcp>/` (ALPN `h2,http/1.1`) →
     hello страницы, h2-преамбула, заголовки навигации, fetch GET/POST,
     WebSocket по h2 (RFC 8441).
   - **ws h1**: тот же сценарий с приёмником в режиме только `http/1.1` →
     hello WebSocket-соединения (у Chrome отдельный, `t13d1516h1`), заголовки
     WebSocket по h1.
   - **quic**: Chrome — `--origin-to-force-quic-on=localtest.me:<udp>` и
     `--ignore-certificate-errors-spki-list=<spki>`; Firefox — настоящий
     `Alt-Svc` в ответе по TCP и CA в `cert9.db` (`alt-svc-mapping-for-testing`
     не работает). Нужен только Initial, сервер QUIC не нужен.
5. Chrome TCP получает `--ignore-certificate-errors-spki-list` тем же SPKI.

### `normalize.py`

Читает pcap через `tshark -T json` (или `-T fields`). Берёт **первый**
ClientHello соединения: Firefox при отказе повторяет без 27, повторы не
считаются. Выдаёт JSON вида:

```json
{
  "browser": "chrome",
  "major": 157,
  "tcp_h2": { "ja4": "...", "ciphers": [...], "extensions": {...}, ... },
  "tcp_h1": { ... },
  "quic":   { "ja4": "...", "tls": {...}, "transport_parameters": [...] },
  "h2":     { "settings": [...], "window_update": 0, "headers": { "<вид>": [...] },
              "priority": { "<вид>": {...} } },
  "h1":     { "<вид>": [...] }
}
```

Правила нормализации — единственное место, где решается, что считать шумом:

- **GREASE** (TLS-значения `0x?a?a`, QUIC TP `31·N+27`) заменяется одним
  маркером; позиция маркера сохраняется там, где порядок фиксирован.
- **Порядок расширений**: Chrome перемешивает — сравнивается отсортированное
  множество; Firefox — порядок как есть. Режим задаётся по браузеру, а не
  угадывается.
- **JA4**: сравнивается `ja4_ab` — a- и b-части значения tshark
  (`tls.handshake.ja4`) без c-части (она хеширует sig_algs с GREASE и меняется
  от hello к hello). TShark < 4.4 пишет префикс QUIC как `u` вместо `q`;
  `pcapread.client_hellos` приводит его к `q`.
- **Позиция зарезервированной (GREASE) версии** внутри QUIC TP `version_information` (0x11): у Chrome выбранная версия идёт первой, остальные сравниваются как множество; у Firefox порядок фиксирован и сравнивается как есть.
- **Session tickets**: приёмник их не выдаёт, возобновлённых hello нет.
- **Длины** (длина hello, длина ECH GREASE, padding) не сравниваются: меняются
  от SNI и случайно.
- **Сохраняются**: шифры, группы, key_share-группы, sig_algs, ALPN, ALPS
  (кодпоинт и протоколы), compress_cert, supported_versions, наличие ECH,
  trust anchors (51764) как сырой hex.
- **QUIC TP**: id и значения; порядок — только для Firefox (фиксированный);
  длина SCID как число; `version_information` и `google_connection_options`
  как значения.
- **h2**: SETTINGS (id и значения по порядку), инкремент первого
  WINDOW_UPDATE, PRIORITY-кадры, порядок псевдозаголовков.
- **Заголовки**: список имён по порядку и значения. Вырезаются изменчивые
  (`host`/`:authority`, `origin`, `referer`, `sec-websocket-key`,
  `accept-language`). Платформа нормализуется: в UA токен платформы в скобках
  заменяется на `<platform>`, `sec-ch-ua-platform` → `<platform>`. Версия
  остаётся: её изменение — главный ожидаемый дрейф.
- **`major`**: из `versions.json`. Сверка с версией в UA не реализована.

Платформа нормализуется, потому что эталон снят на macOS, а CI — на Linux.
Hello Chrome одинаков на desktop и Android (замер 2026-10-30), Firefox — тоже
кроссплатформенный по hello.

### `compare.py`

`compare.py baseline/chrome.json snapshot/chrome.json` — рекурсивный дифф по
полям, вывод markdown: слой, поле, было → стало. Коды выхода: 0 — совпадает,
1 — дрейф, 2 — снимок неполный (слой отсутствует или пуст). Отдельной строкой
верхнего уровня — смена мажора («Chrome 156 → 157: обновить UA и `sec-ch-ua`
в `fingerprint_profile.rs`»).

### Эталон

`baseline/chrome.json` и `baseline/firefox.json` строятся `normalize.py` из
pcap замеров 2026-10-29…31 (они сохранились в scratchpad прошлой сессии:
`tcpch/` — TCP hello, `chello.bcEH/s*` — QUIC с SNI, `h2fp/` — h2 и
заголовки). Если для какого-то слоя исходного pcap нет или он не
нормализуется, эталон этого слоя берётся из первого CI-прогона после ручной
сверки с таблицами в `request_headers.rs` / `h2_profile.rs` /
`quic/tp_profile.rs`.

Маленькие pcap из этого набора кладутся в `scripts/fingerprint-drift/tests/data/`
как фикстуры `unittest` (localhost, без секретов; сертификаты сценариев
эфемерные).

**Связь с Rust-таблицами.** Новый тест в
`crates/outline-transport/src/tests/fingerprint_profile.rs` читает
`baseline/*.json` (`include_str!`) и проверяет, что `major` эталона равен
мажору в UA соответствующих записей `PROFILES`. Обновить профиль и забыть
эталон (или наоборот) нельзя — `cargo test` упадёт. Тест на возраст таблицы
(`REFRESH_PERIOD_SECS`) остаётся.

## Workflow `.github/workflows/fingerprint-drift.yml`

- Триггеры: `schedule` (понедельник, 06:00 UTC), `workflow_dispatch`,
  `pull_request` с `paths: scripts/fingerprint-drift/**` — на PR только `unittest`
  и прогон захвата без работы с issue.
- Раннер `ubuntu-24.04` (tshark из apt; поле `tls.handshake.ja4` есть с
  Wireshark 4.2, но QUIC-префикс там `u`). `permissions: contents: read, issues: write`.
- Шаги: unittest → `capture.sh` → `normalize.py` → `compare.py` для каждого
  браузера → `upload-artifact` (pcap, снимки, отчёт, `versions.json`) → отчёт
  в `$GITHUB_STEP_SUMMARY`.
- **Issue** (только `schedule`/`workflow_dispatch`): одна открытая issue с
  меткой `fingerprint-drift`, ищется через `gh issue list --label`.
  - дрейф и issue нет → `gh issue create` с отчётом и ссылкой на прогон;
  - дрейф и issue есть → `gh issue edit --body` (тело заменяется актуальным
    отчётом, без потока комментариев);
  - дрейфа нет и issue есть → комментарий «снова совпадает» и
    `gh issue close`.
  Метка создаётся при первом использовании (`gh label create … || true`).
- Репозиторий публичный: отчёт и issue пишутся на английском.
- У Firefox выключен DoH, `localtest.me` пинится в `/etc/hosts`.
- **Сбой захвата ≠ дрейф.** Код 2 из `compare.py`, падение `capture.sh` или
  таймаут сценария делают джоб красным, issue не трогается: это
  инфраструктурная ошибка, а не сигнал об изменении браузера.

## Обработка ошибок

- Каждый сценарий браузера под таймаутом (на Linux есть `timeout`); браузер
  убивается после записи нужного.
- Приёмник, не получивший ни одного hello за время сценария, — ошибка
  захвата с именем сценария в логе.
- `normalize.py` падает с понятным сообщением, если в pcap нет нужного кадра
  (а не выдаёт пустой слой молча); `compare.py` дополнительно ловит пустые
  слои кодом 2.
- Apt-ошибки установки браузера — инфраструктурный сбой (красный джоб).

## Тесты

- `unittest`, `scripts/fingerprint-drift/tests/`:
  - `normalize` на фикстурах даёт ожидаемый JSON (GREASE замаскирован,
    множество расширений у Chrome, порядок у Firefox, первый hello при
    повторе, вырезанные изменчивые заголовки, нормализованная платформа);
  - `compare`: идентичные снимки → 0; изменённое поле → 1 и строка в отчёте;
    смена мажора → отдельная строка; пустой слой → 2;
  - перестановка расширений Chrome не даёт дрейфа, перестановка у Firefox —
    даёт.
- cargo: тест согласованности `major` эталона и `PROFILES`.
- Ручной прогон `workflow_dispatch` после мержа; ожидаемо Chrome уже 157+ →
  первая issue — проверка всей цепочки.

## Документация

- `scripts/fingerprint-drift/README.md` и `README.ru.md`: локальный запуск
  (Linux или docker), обновление эталона после пересъёма профилей, что
  считается шумом.
- `AGENTS.md`: строка про монитор и про правило «обновил `PROFILES` → обнови
  `baseline/*.json`» рядом с описанием CI-гейта.
- Комментарий к `PROFILES_REFRESHED_AT_UNIX` в `fingerprint_profile.rs`:
  процедура обновления дополняется эталоном.

## Порядок выкатки

Изменение только в CI и тестах, на боевой парк не выкатывается. Порядок:
нормализатор и эталон с `unittest` → cargo-тест согласованности → приёмники и
`capture.sh` (проверка локально в docker на маке) → workflow → ручной
`workflow_dispatch`.

## Правки после финального ревью

- Отсутствующий вид запроса в `h2.headers`, `h2.priority` или `h1` — ошибка
  захвата (INCOMPLETE, код 2), а не дрейф.
- Таймауты `capture.sh`: приёмники 30 с, браузер 25 с. После сценария с QUIC
  pcap из одного 24-байтного заголовка (ни одной датаграммы) — ошибка захвата
  с именем файла.
- Пакет с фрагментом hello без полного сообщения пропускается; ошибка только
  если ни один пакет не дал hello.
