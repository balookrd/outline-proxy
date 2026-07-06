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

**Сервер** (`outline-ss-rust`) сейчас на **1.6.0** (2026-07-01), **клиент**
(`outline-ws-rust`) — на **1.6.1** (2026-07-02); адаптивный carrier-padding
вышел в линейке 1.6. Главная недавняя работа — клиентский data-plane:
**TUN GSO / GRO / USO offload** (`[tun] gso` / `gro` / `uso`) для срезания
per-packet CPU и **connection sniffing с переопределением назначения**
(TLS SNI / HTTP Host на TCP, QUIC ClientHello на UDP), чтобы exit-узел
резолвил реальное имя хоста — плюс фиксы пропускной способности одиночного
flow на больших RTT (поднятые приёмные окна носителей + congestion control
BBR, зеркалимый сервером на его QUIC-листенере). Подробности — в changelog'ах
бинарей.

*English version: [CHANGELOG.md](CHANGELOG.md)*
