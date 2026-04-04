# Local Patches

Этот файл фиксирует локальные патчи на vendored зависимости, чтобы их было проще сопровождать при обновлениях.

## h3 0.0.8

- Upstream crate: `h3`
- Vendored path: [`vendor/h3`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/h3)
- Patch file: [`h3-0.0.8-git.patch`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/h3-0.0.8-git.patch)

### Purpose

Локальный patch нужен для поддержки `ws-over-http3`:

- добавляет `Protocol::WEBSOCKET` в `h3::ext::Protocol`
- разрешает значение `:protocol = "websocket"` для RFC 9220
- подавляет шумные warnings в vendored crate, чтобы сборка и тесты были чище

### Files changed relative to upstream

- [`vendor/h3/src/ext.rs`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/h3/src/ext.rs)
- [`vendor/h3/src/lib.rs`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/h3/src/lib.rs)

### Source of truth

Источником правды для локальных отличий считается [`h3-0.0.8-git.patch`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/h3-0.0.8-git.patch).

Если `vendor/h3` нужно пересобрать из чистого upstream checkout:

```bash
git apply /Users/mvmalykh/IdeaProjects/outline-ws-rust/h3-0.0.8-git.patch
```

### Maintenance note

При обновлении `h3` лучше:

1. взять чистый upstream crate нужной версии
2. попробовать применить [`h3-0.0.8-git.patch`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/h3-0.0.8-git.patch) вручную или адаптировать его
3. после переноса изменений обновить patch-файл в корне проекта

## sockudo-ws 1.7.5

- Upstream crate: `sockudo-ws`
- Vendored path: [`vendor/sockudo-ws`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/sockudo-ws)
- Patch file: [`sockudo-ws-mips.patch`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/sockudo-ws-mips.patch)

### Purpose

Локальный patch нужен для legacy MIPS router-сборок:

- отключает `tokio-rustls` default features, чтобы `release-router` не тащил `aws-lc-sys`
- добавляет fallback для targets без `AtomicU64`, чтобы `pubsub` собирался на MIPS32

### Files changed relative to upstream

- [`vendor/sockudo-ws/Cargo.toml`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/sockudo-ws/Cargo.toml)
- [`vendor/sockudo-ws/src/pubsub.rs`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/vendor/sockudo-ws/src/pubsub.rs)

### Source of truth

Источником правды для локальных отличий считается [`sockudo-ws-mips.patch`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/sockudo-ws-mips.patch).

Если `vendor/sockudo-ws` нужно пересобрать из чистого upstream checkout:

```bash
git apply /Users/mvmalykh/IdeaProjects/outline-ws-rust/sockudo-ws-mips.patch
```

### Maintenance note

При обновлении `sockudo-ws` лучше:

1. взять чистый upstream crate нужной версии
2. попробовать применить [`sockudo-ws-mips.patch`](/Users/mvmalykh/IdeaProjects/outline-ws-rust/sockudo-ws-mips.patch) вручную или адаптировать его
3. после переноса изменений обновить patch-файл в корне проекта
