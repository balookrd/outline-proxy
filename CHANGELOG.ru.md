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

Оба бинаря сейчас на версии **1.5.1** (2026-06-15). Главное изменение в секции
`Unreleased` с обеих сторон — **адаптивный carrier-padding** для носителей
WS / XHTTP (против корреляции по размеру TLS-записей при TLS-in-TLS); серверную
(per-path) и клиентскую (глобальную) половины см. в changelog'ах бинарей.

*English version: [CHANGELOG.md](CHANGELOG.md)*
