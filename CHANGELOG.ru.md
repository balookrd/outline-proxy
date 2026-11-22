# История изменений

`outline-proxy` — единый Cargo workspace, объединивший ранее раздельные
проекты сервера (ранее **`outline-ss-rust`**, теперь **`outline-server`**) и
клиента (ранее **`outline-ws-rust`**, теперь **`outline-client`**) и
расширенный дашбордом и клиентами под Android, macOS и Windows. В исторических
релизах до разделения использовались общие теги `v1.0.0` … `v1.4.4`, а в
линейке до `1.9.x` — раздельные теги `ss-v*` / `ws-v*` / `ui-v*` / `android-v*` /
`macos-v*`. Начиная с `v26.11.0`, весь репозиторий выпускается синхронно под
единым CalVer-тегом (`vYY.M.PATCH`). Подробная история ранней линейки `1.x` по
отдельным компонентам хранится в per-binary changelog'ах:

| Компонент | Changelog | English |
|-----------|-----------|---------|
| **Сервер** (`outline-server`) | [`bins/outline-server/CHANGELOG.ru.md`](bins/outline-server/CHANGELOG.ru.md) | [`CHANGELOG.md`](bins/outline-server/CHANGELOG.md) |
| **Клиент** (`outline-client`) | [`bins/outline-client/CHANGELOG.ru.md`](bins/outline-client/CHANGELOG.ru.md) | [`CHANGELOG.md`](bins/outline-client/CHANGELOG.md) |
| **Windows-клиент** (`outline-windows`) | [`bins/outline-windows/CHANGELOG.ru.md`](bins/outline-windows/CHANGELOG.ru.md) | [`CHANGELOG.md`](bins/outline-windows/CHANGELOG.md) |
| **Дашборд** (`outline-ui`) | [`bins/outline-ui/CHANGELOG.ru.md`](bins/outline-ui/CHANGELOG.ru.md) | [`CHANGELOG.md`](bins/outline-ui/CHANGELOG.md) |
| **Android-приложение** | [`android/CHANGELOG.ru.md`](android/CHANGELOG.ru.md) | [`CHANGELOG.md`](android/CHANGELOG.md) |

Оба бинаря были на **1.9.0**, выпущены 2026-08-24 под прежними тегами
`ss-v1.9.0` / `ws-v1.9.0`, вместе с `outline-ui` **1.2.0** и Android-приложением
**1.2.0** из той же нарезки — до перехода workspace на CalVer (`v26.11.0`) и
переименования крейтов в `outline-server` / `outline-client`.
Адаптивный
carrier-padding, TUN GSO / GRO / USO offload и connection sniffing с
переопределением назначения вышли в этой линейке раньше. Главная недавняя
работа охватывает всю систему:

- **BREAKING: серверные carrier-эндпоинты объединены (`outline-server`,
  ожидает релиза).** Блок `[websocket]`, per-user поля `ws_path_tcp` /
  `ws_path_udp` / `ws_path_vless` / `xhttp_path_*` и `[padding] enabled` /
  `paths` удалены и больше не парсятся. Каждый carrier-путь теперь — одна
  запись `[[endpoint]] { path, kind, padded }` в едином глобальном списке, а
  пользователи — чистые credentials, работающие на каждом эндпоинте своего
  kind; padding — атрибут эндпоинта, а не отдельный список путей. См.
  [`bins/outline-server/README.ru.md`](bins/outline-server/README.ru.md#модель-эндпоинтов)
  и [`docs/PADDING.ru.md`](docs/PADDING.ru.md); перед апгрейдом мигрируйте
  `config.toml`.
- **Адаптивный выбор носителя, H3/XHTTP/SOCKS5/TUN и DSCP-маркировка egress.**
  Клиент поддерживает per-uplink и direct `dscp` (`0..=63`, `direct_dscp`,
  `--dscp` / `OUTLINE_DSCP`) наряду с Linux `fwmark` — на TCP, UDP, HTTP/2,
  HTTP/3 (через патч `quinn-udp`, сохраняющий DSCP в `cmsg` вместе с битами
  ECN), Control API CRUD и в веб-интерфейсе `/ws/*`.
- **Mesh-кластер серверов.** Edge-узлы релеят сессию клиента на home-узел, что
  ей владеет, с метриками исхода релея и полной миграцией сессии при
  переключении edge — включая single-target UDP и VLESS-mux-бандлы.
- **Share-link для всего.** Combined-path Shadowsocks-юзеры получают share-link
  `ss://…` рядом с артефактами `vless://…`, а клиент может описать целый uplink —
  или одну fallback-жилу — из одного share-link-URI.
- **Детерминированный синхронный перевыбор** (`load_balancing.reselect_sync`),
  чтобы клон-пара узлов ротировалась на один uplink и уходила с одного egress.
- **Android-VPN-клиент** ([`android/`](android/)), переиспользующий uplink-стек
  `outline-client` без изменений — теперь с карточкой статуса туннеля в
  приложении (длительность, трафик, активный носитель), футером версии билда и
  конвейером выпуска подписанного APK (единые релизы `vYY.M.PATCH`, rolling
  `android-nightly`) — плюс агрегирующий dashboard-сервис **`outline-ui`**.
- **Windows-клиент** ([`bins/outline-windows/`](bins/outline-windows/)) на стеке
  Tauri v2 + Svelte 5 с поддержкой режимов SOCKS5 и TUN (Wintun), встроенным
  автоапдейтером с проверкой SHA-256 по `SHA256SUMS.txt`, защитой от zip-slip
  и автореконнектом туннеля.

Подробная история по версиям — в changelog'ах бинарей.

*English version: [CHANGELOG.md](CHANGELOG.md)*
