# История изменений

`outline-proxy` — единый Cargo workspace, объединивший два ранее раздельных
проекта: сервер **`outline-ss-rust`** и клиент **`outline-ws-rust`**. Два
бинаря версионируются и релизятся **независимо**, каждый под своими git-тегами:
`ss-v*` / `ws-v*` после слияния (например, `ss-v1.5.1`, `ws-v1.5.1`) и общие
теги `v1.0.0` … `v1.4.4` из периода до разделения. Единой версии workspace нет;
подробная история по версиям ведётся в per-binary changelog'ах:

| Компонент | Changelog | English |
|-----------|-----------|---------|
| **Сервер** (`outline-ss-rust`) | [`bins/outline-ss-rust/CHANGELOG.ru.md`](bins/outline-ss-rust/CHANGELOG.ru.md) | [`CHANGELOG.md`](bins/outline-ss-rust/CHANGELOG.md) |
| **Клиент** (`outline-ws-rust`) | [`bins/outline-ws-rust/CHANGELOG.ru.md`](bins/outline-ws-rust/CHANGELOG.ru.md) | [`CHANGELOG.md`](bins/outline-ws-rust/CHANGELOG.md) |
| **Дашборд** (`outline-ui`) | [`bins/outline-ui/CHANGELOG.ru.md`](bins/outline-ui/CHANGELOG.ru.md) | [`CHANGELOG.md`](bins/outline-ui/CHANGELOG.md) |
| **Android-приложение** | [`android/CHANGELOG.ru.md`](android/CHANGELOG.ru.md) | [`CHANGELOG.md`](android/CHANGELOG.md) |

Оба бинаря на **1.9.0**, выпущены 2026-08-24 (теги `ss-v1.9.0` / `ws-v1.9.0`),
вместе с `outline-ui` **1.2.0** и Android-приложением **1.2.0** из той же
нарезки.
Адаптивный
carrier-padding, TUN GSO / GRO / USO offload и connection sniffing с
переопределением назначения вышли в этой линейке раньше. Главная недавняя
работа охватывает всю систему:

- **BREAKING: серверные carrier-эндпоинты объединены (`outline-ss-rust`,
  ожидает релиза).** Блок `[websocket]`, per-user поля `ws_path_tcp` /
  `ws_path_udp` / `ws_path_vless` / `xhttp_path_*` и `[padding] enabled` /
  `paths` удалены и больше не парсятся. Каждый carrier-путь теперь — одна
  запись `[[endpoint]] { path, kind, padded }` в едином глобальном списке, а
  пользователи — чистые credentials, работающие на каждом эндпоинте своего
  kind; padding — атрибут эндпоинта, а не отдельный список путей. См.
  [`bins/outline-ss-rust/README.ru.md`](bins/outline-ss-rust/README.ru.md#модель-эндпоинтов)
  и [`docs/PADDING.ru.md`](docs/PADDING.ru.md); перед апгрейдом мигрируйте
  `config.toml`.
- **Mesh-кластер серверов.** Edge-узлы релеят сессию клиента на home-узел, что
  ей владеет, с метриками исхода релея и полной миграцией сессии при
  переключении edge — включая single-target UDP и VLESS-mux-бандлы.
- **Share-link для всего.** Combined-path Shadowsocks-юзеры получают share-link
  `ss://…` рядом с артефактами `vless://…`, а клиент может описать целый uplink —
  или одну fallback-жилу — из одного share-link-URI.
- **Детерминированный синхронный перевыбор** (`load_balancing.reselect_sync`),
  чтобы клон-пара узлов ротировалась на один uplink и уходила с одного egress.
- **Android-VPN-клиент** ([`android/`](android/)), переиспользующий uplink-стек
  `outline-ws-rust` без изменений — теперь с карточкой статуса туннеля в
  приложении (длительность, трафик, активный носитель), футером версии билда и
  конвейером выпуска подписанного APK (теги `android-v*`, rolling
  `android-nightly`) — плюс агрегирующий dashboard-сервис **`outline-ui`**.

Подробная история по версиям — в changelog'ах бинарей.

*English version: [CHANGELOG.md](CHANGELOG.md)*
