# Монитор дрейфа браузерных отпечатков

🌐 [English](README.md)

`outline-ws-rust` выдаёт себя за браузер на всех слоях, которые видит DPI:
ClientHello по TCP и QUIC, transport parameters QUIC, преамбула HTTP/2 и
заголовки запросов. Профили (`crates/outline-transport/src/fingerprint_profile.rs`
и таблицы рядом) подогнаны под Chrome 156 и Firefox 159. `cargo test` ловит
регрессии нашего кода относительно этих захватов, но не замечает, что браузеры
ушли вперёд. Это делает монитор: раз в неделю
`.github/workflows/fingerprint-drift.yml` снимает свежие Chrome stable и Firefox
release, сравнивает их с `baseline/*.json` и держит открытой одну issue
`fingerprint-drift`, пока они расходятся.

Сравниваются только браузеры, наш клиент не участвует: эталон — это то, что
браузер отправлял, когда подгоняли профили.

## Состав

| Файл | Назначение |
|---|---|
| `capture.sh` | Ставит браузеры (`--install`), гоняет сценарии, пишет `versions.json` |
| `tls_sink.py` | Записывает каждый ClientHello, терминирует TLS, отвечает по h2/h1, записывает запросы |
| `../quic-initial-sink.py` | Записывает QUIC Initial-датаграммы |
| `ca.sh`, `page.html` | Эфемерный CA для `localtest.me`; страница с fetch GET/POST и WebSocket |
| `normalize.py` | pcap → JSON-снимок; единственное место, где решается, что считать шумом |
| `compare.py` | Снимок против эталона → markdown-отчёт; код 0 — совпадает, 1 — дрейф, 2 — снимок неполный |
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
tickets, поэтому последующие соединения не возобновляются (у возобновлённого
hello появляется `pre_shared_key`).

## Локальный запуск

Linux (или Docker) с браузерами:

```bash
scripts/fingerprint-drift/capture.sh --install /tmp/cap      # без --install, если браузеры уже стоят
python3 scripts/fingerprint-drift/normalize.py /tmp/cap /tmp/snap
python3 scripts/fingerprint-drift/compare.py scripts/fingerprint-drift/baseline /tmp/snap /tmp/report.md
```

`CHROME=` и `FIREFOX=` задают другие бинари, например `CHROME=chromium` на arm64.
У Google Chrome нет сборки под linux/arm64, а под QEMU-эмуляцией Docker на
Apple silicon Chrome падает. Юнит-тесты:
`python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests`.

## Когда открылась issue

1. Прочитать отчёт. Новый мажор — значит, новые строки UA и `sec-ch-ua`.
   Изменение hello, преамбулы или заголовков — значит, то же изменение нужно в
   таблицах профилей.
2. Перезамерить и обновить `PROFILES` и таблицы (чеклист — в комментарии к
   `PROFILES_REFRESHED_AT_UNIX`).
3. Пересобрать эталон из новых захватов. Положить каталоги браузеров и
   `versions.json` в `tests/data/` (в раскладке `capture.sh`, она же лежит в
   артефакте CI), но не каталог `ca/`: в нём одноразовый приватный ключ. Затем
   выполнить
   `python3 scripts/fingerprint-drift/normalize.py scripts/fingerprint-drift/tests/data scripts/fingerprint-drift/baseline`.
   `cargo test` проверит, что мажоры эталона совпадают с `PROFILES`.
4. Следующий прогон закроет issue.
