# Монитор дрейфа браузерных отпечатков

English version: [README.md](README.md).

`outline-ws-rust` выдаёт себя за браузер на всех слоях, которые видит DPI:
ClientHello по TCP и QUIC, transport parameters QUIC, преамбула HTTP/2 и
заголовки запросов. Профили (`crates/outline-transport/src/fingerprint_profile.rs`
и таблицы рядом) подогнаны под Chrome 157 и Firefox 159
(`tests/data/versions.json`). `cargo test` ловит регрессии нашего кода
относительно этих захватов, но не замечает, что браузеры ушли вперёд. Это
делает монитор: `.github/workflows/fingerprint-drift.yml` (по понедельникам в
06:00 UTC и вручную) снимает свежие Chrome stable и Firefox release, сравнивает
их с `baseline/*.json` и держит открытой одну issue `fingerprint-drift`, пока
они расходятся.

Сравниваются только браузеры, наш клиент не участвует: эталон — это то, что
браузер отправлял, когда подгоняли профили.

## Файлы

| Файл | Назначение |
|---|---|
| `capture.sh` | Ставит браузеры (`--install`), гоняет сценарии, пишет `versions.json` и сжатый net-log Chrome на каждый сценарий |
| `tls_sink.py` | Записывает каждый ClientHello, терминирует TLS, отвечает по h2/h1, записывает запросы |
| `../quic-initial-sink.py` | Записывает QUIC Initial-датаграммы |
| `ca.sh`, `page.html` | Эфемерный CA для `localtest.me`; страница с fetch GET/POST и WebSocket |
| `pcapwrite.py` | Пишет полученные приёмниками байты в pcap синтетическими IPv4/TCP-пакетами |
| `pcapread.py` | Читает pcap через tshark (расшифровка QUIC Initial, сборка CRYPTO/TCP, JA4, HPACK) |
| `hello.py` | Разбирает ClientHello на сравнимые поля |
| `normalize.py` | pcap → JSON-снимок; единственное место, где решается, что считать шумом. Падает, если мажор из UA не совпадает с `versions.json` |
| `compare.py` | Снимок против эталона → markdown-отчёт; код 0 — совпадает, 1 — дрейф, 2 — снимок неполный, 3 — дрейф рядом с неполным снимком. У списков показывает, что добавилось и что пропало |
| `issue.sh` | Открывает, обновляет или закрывает issue `fingerprint-drift` |
| `baseline/` | Эталонные снимки (генерируются из `tests/data/`, руками не правятся) |

Сценарии, все на `localtest.me`: страница по h2 (порт 8443), страница только по
http/1.1 (8444; здесь Chrome открывает WebSocket-соединение с hello, где в ALPN
один `http/1.1`), QUIC Initial (8445; Chrome принуждается
`--origin-to-force-quic-on`, Firefox идёт по `Alt-Svc` страницы). Браузеры
работают под Xvfb, не в headless.

## Что считается шумом

GREASE-значения, порядок расширений (случайный везде, кроме Firefox по TCP),
порядок transport parameters (случайный у Chrome), значение source connection
ID, зарезервированные версии QUIC, c-часть JA4 (её исходные поля сравниваются
по отдельности), длины, значения `host`/`:authority`, `origin`, `referer`,
`sec-websocket-key`, `accept-language` (сам заголовок — имя и позиция —
сравнивается). Платформа в `user-agent` и `sec-ch-ua-platform` маскируется:
эталон снят на macOS, CI работает на Linux. Приёмник не выдаёт TLS session
tickets (`num_tickets = 0` в `tls_sink.py`), поэтому последующие соединения не
возобновляются: у возобновлённого hello появляется `pre_shared_key`.

## Локальный запуск

Linux (или Docker) с браузерами:

```bash
scripts/fingerprint-drift/capture.sh --install /tmp/cap      # без --install, если браузеры уже стоят
python3 scripts/fingerprint-drift/normalize.py /tmp/cap /tmp/snap
python3 scripts/fingerprint-drift/compare.py scripts/fingerprint-drift/baseline /tmp/snap /tmp/report.md
```

`CHROME=` и `FIREFOX=` задают другие бинари (по умолчанию `google-chrome` и
`firefox`), например `CHROME=chromium` на arm64: у Google Chrome нет сборки под
linux/arm64, а под QEMU-эмуляцией Docker на Apple silicon Chrome падает.

Юнит-тесты:

```bash
python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests
```

## Когда прогон упал

Неполный снимок («Snapshot lacks layers») — это частичный захват, а не дрейф:
джоб падает, а issue обновляется, только если дрейфанул второй браузер. Захват,
сорвавшийся целиком (ни одного ClientHello), роняет джоб ещё в `capture.sh` /
`normalize.py`, до сравнения.

Прежде чем винить браузер, посмотрите net-log Chrome в артефакте прогона
(`*.netlog.json.gz`; JSON в нём не закрыт, потому что Chrome убивается по
таймауту). Свежий Google Chrome в первые мгновения пересоздаёт верификатор
сертификатов и рвёт все соединения, поэтому `page.html` ждёт 2 с перед первым
запросом.

## Когда открылась issue

1. Прочитайте отчёт. Новый мажор — значит, новые строки UA и `sec-ch-ua`.
   Изменение hello, преамбулы или заголовков — значит, то же изменение нужно в
   таблицах профилей.
2. Перезамерьте и обновите `PROFILES` и таблицы. Чеклист — в комментарии к
   `PROFILES_REFRESHED_AT_UNIX` (`crates/outline-transport/src/fingerprint_profile.rs`).
3. Положите каталоги браузеров и `versions.json` из нового захвата в
   `tests/data/` (в раскладке `capture.sh`, она же лежит в артефакте CI).
   Каталог `ca/` не копируйте: в нём одноразовый приватный ключ.
4. Пересоберите эталон:

   ```bash
   python3 scripts/fingerprint-drift/normalize.py scripts/fingerprint-drift/tests/data scripts/fingerprint-drift/baseline
   ```

5. Запустите `cargo test -p outline-transport`: тест
   `drift_baselines_describe_the_profiled_browser_majors` проверяет, что мажоры
   эталона совпадают с `PROFILES`.
6. Следующий плановый прогон закроет issue.
