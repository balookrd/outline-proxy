# Local Patches

Этот файл фиксирует локальные патчи на vendored зависимости, чтобы их было проще сопровождать при обновлениях.

## h3 0.0.8

- Upstream crate: `h3`
- Vendored path: [`vendor/h3`](/Users/mmalykhin/Documents/Playground/vendor/h3)
- Patch file: [`h3-0.0.8-git.patch`](/Users/mmalykhin/Documents/Playground/h3-0.0.8-git.patch)

### Purpose

Локальный patch нужен для поддержки `ws-over-http3`:

- добавляет `Protocol::WEBSOCKET` в `h3::ext::Protocol`
- разрешает значение `:protocol = "websocket"` для RFC 9220
- подавляет шумные warnings в vendored crate, чтобы сборка и тесты были чище

### Files changed relative to upstream

- [`vendor/h3/src/ext.rs`](/Users/mmalykhin/Documents/Playground/vendor/h3/src/ext.rs)
- [`vendor/h3/src/lib.rs`](/Users/mmalykhin/Documents/Playground/vendor/h3/src/lib.rs)

### Source of truth

Источником правды для локальных отличий считается [`h3-0.0.8-git.patch`](/Users/mmalykhin/Documents/Playground/h3-0.0.8-git.patch).

Если `vendor/h3` нужно пересобрать из чистого upstream checkout:

```bash
git apply /Users/mmalykhin/Documents/Playground/h3-0.0.8-git.patch
```

### Maintenance note

При обновлении `h3` лучше:

1. взять чистый upstream crate нужной версии
2. попробовать применить [`h3-0.0.8-git.patch`](/Users/mmalykhin/Documents/Playground/h3-0.0.8-git.patch) вручную или адаптировать его
3. после переноса изменений обновить patch-файл в корне проекта
