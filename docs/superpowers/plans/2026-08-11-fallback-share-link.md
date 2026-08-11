# `link` в `[[outline.uplinks.fallbacks]]` — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** научить `[[outline.uplinks.fallbacks]]` принимать share-link URI
(`vless://…`, `ss://…`), чтобы любой wire клиента описывался одной строкой, а
не набором раздельных полей.

**Architecture:** разворачивание ссылки уезжает из тела
`resolve_primary_wire_shape` в общий хелпер `expand_share_link` рядом с ним
(`config/load/uplinks/wire_shape.rs`); fallback получает pre-pass, который этим
хелпером заполняет поля своей секции до того, как отработает существующая
валидация `resolve_fallback`. Поле `transport` во fallback становится
опциональным: при наличии `link` транспорт выводится из схемы ссылки.

**Tech Stack:** Rust 2024, `serde` + `toml` / `toml_edit`, `anyhow`, `url`,
крейт `outline-uplink` (готовые парсеры `VlessShareLink` / `SsShareLink`).

Спека: [`docs/superpowers/specs/2026-08-11-fallback-share-link-design.md`](../specs/2026-08-11-fallback-share-link-design.md).

## Global Constraints

- Правки только в `bins/outline-ws-rust/` (плюс её `docs/` и `CHANGELOG*`);
  `crates/outline-uplink` не меняется — парсеры ссылок уже готовы.
- Тесты живут в `<dir>/tests/<basename>.rs`, inline `#[cfg(test)] mod tests {}`
  запрещён.
- Комментарии в коде, сообщения коммитов и текст в `CHANGELOG.md` — на
  английском. Общение с владельцем — на русском.
- `#[serde(deny_unknown_fields)]` на пользовательских секциях сохраняется.
- User-facing документация ведётся парами EN/RU и правится в одном изменении:
  `docs/UPLINK-CONFIGURATIONS.md` + `.ru.md`, `CHANGELOG.md` + `CHANGELOG.ru.md`.
- Секреты (PSK, пароли, UUID, ссылки с ними) не попадают в логи, тесты и
  коммиты; в примерах используются `example.com` и нулевые UUID.
- CI-гейт перед коммитом — ровно эти команды, в этом порядке (`fmt` падает
  первым и маскирует clippy):

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
```

```bash
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
```

```bash
cargo test --workspace --exclude sockudo-ws
```

- **Коммиты выполняются только с явного разрешения владельца** (правило
  репозитория: `git commit` / `git push` без команды не запускать). Шаги
  «Commit» ниже выполняются, когда разрешение получено; иначе изменения
  накапливаются в рабочем дереве, а владельцу показывается diff.

---

### Task 1: Общий хелпер разворачивания share-link

Чистый рефактор: поведение primary сохраняется, появляется точка, которую
переиспользует fallback. Единственное намеренное ужесточение — `vless://`-link
теперь конфликтует и с `tcp_*` / `udp_*` / `ss_*` полями; такие конфиги и
раньше не грузились (их отбивал per-transport gating ниже), меняется только
текст ошибки.

**Files:**
- Modify: `bins/outline-ws-rust/src/config/load/uplinks/wire_shape.rs:54-156`
- Test: `bins/outline-ws-rust/src/config/load/tests/uplinks.rs` (существующие
  `ss_share_link_*`), `bins/outline-ws-rust/src/config/tests/mod.rs`
  (существующие `load_config_*_share_link*`)

**Interfaces:**
- Produces: `LinkExpansion { transport: UplinkTransport, vless_ws_url:
  Option<Url>, vless_xhttp_url: Option<Url>, vless_mode: Option<TransportMode>,
  ss_ws_url: Option<Url>, ss_xhttp_url: Option<Url>, ss_mode:
  Option<TransportMode>, vless_id: Option<String>, cipher: Option<CipherKind>,
  password: Option<String> }`; `LinkConflictFields { … 15 полей bool … }`;
  `expand_share_link(context: &str, link: &str, declared:
  Option<UplinkTransport>, conflicts: LinkConflictFields) ->
  Result<LinkExpansion>`. Всё `pub(super)` — потребители внутри
  `config::load::uplinks`.

- [ ] **Step 1: Зафиксировать зелёную базу**

Run: `cargo test -p outline-ws-rust share_link`
Expected: PASS, 6+ тестов (`ss_share_link_expands_into_combined_ws_uplink`,
`ss_share_link_xhttp_targets_ss_xhttp_url`, `ss_share_link_rejects_explicit_credentials`,
`ss_share_link_rejects_transport_vless`, `load_config_expands_vless_share_link_field`,
`load_config_rejects_link_alongside_explicit_vless_url`).

- [ ] **Step 2: Добавить хелпер в `wire_shape.rs`**

Вставить перед `resolve_primary_wire_shape` (после определения
`PrimaryWireShape`, строка 52):

```rust
/// Which explicit fields the caller carries. A share link makes them
/// redundant, so a set flag aborts the load with a uniform message instead of
/// silently letting one source win over the other.
///
/// `method` / `password` are deliberately checked only against an `ss://`
/// link: an `ss://` URI carries the credentials itself, while a `vless://`
/// uplink may legitimately keep them for its SS fallbacks to inherit.
#[derive(Default)]
pub(super) struct LinkConflictFields {
    pub(super) tcp_ws_url: bool,
    pub(super) tcp_xhttp_url: bool,
    pub(super) tcp_mode: bool,
    pub(super) udp_ws_url: bool,
    pub(super) udp_xhttp_url: bool,
    pub(super) udp_mode: bool,
    pub(super) vless_ws_url: bool,
    pub(super) vless_xhttp_url: bool,
    pub(super) vless_mode: bool,
    pub(super) ss_ws_url: bool,
    pub(super) ss_xhttp_url: bool,
    pub(super) ss_mode: bool,
    pub(super) vless_id: bool,
    pub(super) method: bool,
    pub(super) password: bool,
}

/// Wire fields a share-link URI expands into.
pub(super) struct LinkExpansion {
    pub(super) transport: UplinkTransport,
    pub(super) vless_ws_url: Option<Url>,
    pub(super) vless_xhttp_url: Option<Url>,
    pub(super) vless_mode: Option<TransportMode>,
    pub(super) ss_ws_url: Option<Url>,
    pub(super) ss_xhttp_url: Option<Url>,
    pub(super) ss_mode: Option<TransportMode>,
    pub(super) vless_id: Option<String>,
    pub(super) cipher: Option<CipherKind>,
    pub(super) password: Option<String>,
}

/// Expand a `vless://` / `ss://` share link into wire fields.
///
/// Shared by the primary wire (`[[outline.uplinks]] link`) and the fallback
/// pre-pass (`[[outline.uplinks.fallbacks]] link`) so both surfaces agree on
/// which transport a link implies, which explicit fields it conflicts with and
/// how that conflict reads. `context` prefixes every error — `uplink edge-1`
/// or `uplink edge-1: fallbacks[2]`.
pub(super) fn expand_share_link(
    context: &str,
    link: &str,
    declared: Option<UplinkTransport>,
    conflicts: LinkConflictFields,
) -> Result<LinkExpansion> {
    let trimmed = link.trim();
    if trimmed.starts_with("ss://") {
        let parsed = SsShareLink::parse(trimmed)
            .with_context(|| format!("{context}: invalid ss share link"))?;
        // An `ss://` link carries a combined-path carrier *and* the
        // credentials, so it conflicts with every explicit wire field.
        for (set, field) in [
            (conflicts.vless_id, "vless_id"),
            (conflicts.vless_ws_url, "vless_ws_url"),
            (conflicts.vless_xhttp_url, "vless_xhttp_url"),
            (conflicts.vless_mode, "vless_mode"),
            (conflicts.ss_ws_url, "ss_ws_url"),
            (conflicts.ss_xhttp_url, "ss_xhttp_url"),
            (conflicts.ss_mode, "ss_mode"),
            (conflicts.method, "method"),
            (conflicts.password, "password"),
            (conflicts.tcp_ws_url, "tcp_ws_url"),
            (conflicts.tcp_xhttp_url, "tcp_xhttp_url"),
            (conflicts.tcp_mode, "tcp_mode"),
            (conflicts.udp_ws_url, "udp_ws_url"),
            (conflicts.udp_xhttp_url, "udp_xhttp_url"),
            (conflicts.udp_mode, "udp_mode"),
        ] {
            if set {
                bail!(
                    "{context}: `{field}` is mutually exclusive with an `ss://` `link`; remove one"
                );
            }
        }
        match declared {
            None | Some(UplinkTransport::Ss) => {},
            Some(other) => bail!(
                "{context}: an `ss://` `link` only applies to transport=ss, but transport={other} was set"
            ),
        }
        Ok(LinkExpansion {
            transport: UplinkTransport::Ss,
            vless_ws_url: None,
            vless_xhttp_url: None,
            vless_mode: None,
            ss_ws_url: parsed.ss_ws_url,
            ss_xhttp_url: parsed.ss_xhttp_url,
            ss_mode: Some(parsed.mode),
            vless_id: None,
            cipher: Some(parsed.cipher),
            password: Some(parsed.password),
        })
    } else {
        let parsed = VlessShareLink::parse(trimmed)
            .with_context(|| format!("{context}: invalid vless share link"))?;
        for (set, field) in [
            (conflicts.vless_id, "vless_id"),
            (conflicts.vless_ws_url, "vless_ws_url"),
            (conflicts.vless_xhttp_url, "vless_xhttp_url"),
            (conflicts.vless_mode, "vless_mode"),
            (conflicts.ss_ws_url, "ss_ws_url"),
            (conflicts.ss_xhttp_url, "ss_xhttp_url"),
            (conflicts.ss_mode, "ss_mode"),
            (conflicts.tcp_ws_url, "tcp_ws_url"),
            (conflicts.tcp_xhttp_url, "tcp_xhttp_url"),
            (conflicts.tcp_mode, "tcp_mode"),
            (conflicts.udp_ws_url, "udp_ws_url"),
            (conflicts.udp_xhttp_url, "udp_xhttp_url"),
            (conflicts.udp_mode, "udp_mode"),
        ] {
            if set {
                bail!("{context}: `{field}` is mutually exclusive with `link`; remove one");
            }
        }
        match declared {
            None | Some(UplinkTransport::Vless) => {},
            Some(other) => bail!(
                "{context}: a `vless://` `link` only applies to transport=vless, but transport={other} was set"
            ),
        }
        Ok(LinkExpansion {
            transport: UplinkTransport::Vless,
            vless_ws_url: parsed.vless_ws_url,
            vless_xhttp_url: parsed.vless_xhttp_url,
            vless_mode: Some(parsed.mode),
            ss_ws_url: None,
            ss_xhttp_url: None,
            ss_mode: None,
            vless_id: Some(parsed.uuid),
            cipher: None,
            password: None,
        })
    }
}
```

- [ ] **Step 3: Переписать link-ветку `resolve_primary_wire_shape` на хелпер**

Заменить блок `let transport = if let Some(raw_link) = link.as_deref() { … } else { transport.unwrap_or_default() };`
(строки 81-156 до рефактора) на:

```rust
    // `link = "vless://..."` / `"ss://..."` populates the matching transport
    // fields from a single share-link URI. We do this before the
    // transport-default fold so a bare `link` entry implies its transport
    // (`vless` for `vless://`, `ss` for `ss://`) without the user saying so
    // twice. The scheme picks the parser.
    let transport = if let Some(raw_link) = link.as_deref() {
        let expansion = expand_share_link(
            &format!("uplink {name}"),
            raw_link,
            transport,
            LinkConflictFields {
                tcp_ws_url: tcp_ws_url.is_some(),
                tcp_xhttp_url: tcp_xhttp_url.is_some(),
                tcp_mode: tcp_mode.is_some(),
                udp_ws_url: udp_ws_url.is_some(),
                udp_xhttp_url: udp_xhttp_url.is_some(),
                udp_mode: udp_mode.is_some(),
                vless_ws_url: vless_ws_url.is_some(),
                vless_xhttp_url: vless_xhttp_url.is_some(),
                vless_mode: vless_mode.is_some(),
                ss_ws_url: ss_ws_url.is_some(),
                ss_xhttp_url: ss_xhttp_url.is_some(),
                ss_mode: ss_mode.is_some(),
                vless_id: vless_id.is_some(),
                method: cipher.is_some(),
                password: password.is_some(),
            },
        )?;
        vless_ws_url = expansion.vless_ws_url;
        vless_xhttp_url = expansion.vless_xhttp_url;
        vless_mode = expansion.vless_mode;
        ss_ws_url = expansion.ss_ws_url;
        ss_xhttp_url = expansion.ss_xhttp_url;
        ss_mode = expansion.ss_mode;
        vless_id = expansion.vless_id;
        if expansion.cipher.is_some() {
            cipher = expansion.cipher;
        }
        if expansion.password.is_some() {
            password = expansion.password;
        }
        expansion.transport
    } else {
        transport.unwrap_or_default()
    };
```

- [ ] **Step 4: Прогнать тесты**

Run: `cargo test -p outline-ws-rust share_link`
Expected: PASS, тот же набор тестов, что в шаге 1.

Run: `cargo test -p outline-ws-rust --lib config`
Expected: PASS.

- [ ] **Step 5: Гейт и коммит**

```bash
cargo fmt --all && cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings
```

```bash
git add bins/outline-ws-rust/src/config/load/uplinks/wire_shape.rs
git commit -m "refactor(ws-config): extract share-link expansion into a shared helper"
```

---

### Task 2: `transport` во fallback становится опциональным

Отдельная задача, потому что она трогает 26 тестовых литералов и её можно
отревьюить независимо: поведение конфига не меняется — `transport` по-прежнему
обязателен, просто проверяется валидацией, а не serde.

**Files:**
- Modify: `bins/outline-ws-rust/src/config/schema.rs:517-518`
- Modify: `bins/outline-ws-rust/src/config/load/uplinks/fallback_resolution.rs:35`
- Test: `bins/outline-ws-rust/src/config/load/tests/uplinks.rs`

**Interfaces:**
- Consumes: ничего из Task 1.
- Produces: `FallbackSection.transport: Option<UplinkTransport>` — Task 3 и
  Task 4 полагаются на этот тип.

- [ ] **Step 1: Написать падающий тест**

Добавить в конец `bins/outline-ws-rust/src/config/load/tests/uplinks.rs`:

```rust
// ── Fallback transport is validated, not deserialised ───────────────────────

#[test]
fn fallback_without_transport_is_rejected() {
    let fb = FallbackSection {
        transport: None,
        tcp_ws_url: Some(Url::parse("wss://fb.example.com/tcp").unwrap()),
        tcp_mode: Some(TransportMode::WsH1),
        ..empty_fallback()
    };
    let err = resolve(ws_uplink_section("ss", "wss://main.example.com/tcp", vec![fb]))
        .expect_err("fallback without transport must fail");
    assert!(format!("{err:#}").contains("transport"), "unexpected error: {err}");
}
```

- [ ] **Step 2: Убедиться, что тест не компилируется**

Run: `cargo test -p outline-ws-rust fallback_without_transport`
Expected: FAIL — `expected `UplinkTransport`, found `Option<_>`` (поле ещё не
опционально).

- [ ] **Step 3: Сделать поле опциональным в схеме**

В `bins/outline-ws-rust/src/config/schema.rs` заменить в `FallbackSection`:

```rust
    pub(crate) transport: UplinkTransport,
```

на:

```rust
    /// `ss` / `vless`. Required unless `link` supplies the transport through
    /// its URI scheme (`ss://` → `ss`, `vless://` → `vless`); a value written
    /// next to a `link` must agree with the scheme.
    pub(crate) transport: Option<UplinkTransport>,
```

И в doc-комментарии структуры (строки 509-514) заменить фразу
`no `name` / `weight` / `group` / `link`` на
`no `name` / `weight` / `group`` — `link` теперь у fallback есть (появится в
Task 3, комментарий правим здесь заодно, чтобы не возвращаться).

- [ ] **Step 4: Потребовать транспорт в резолвере**

В `bins/outline-ws-rust/src/config/load/uplinks/fallback_resolution.rs` заменить:

```rust
    let transport = section.transport;
```

на:

```rust
    let transport = section.transport.ok_or_else(|| {
        anyhow!("uplink {parent_name}: fallbacks[{idx}] requires `transport` (`ss` or `vless`)")
    })?;
```

- [ ] **Step 5: Обновить тестовые литералы**

Run: `grep -n "transport: UplinkTransport::" bins/outline-ws-rust/src/config/load/tests/uplinks.rs`
Expected: 26 совпадений.

В каждом заменить `transport: UplinkTransport::Ss,` → `transport: Some(UplinkTransport::Ss),`
и `transport: UplinkTransport::Vless,` → `transport: Some(UplinkTransport::Vless),`.
Строки вида `section.transport = Some(UplinkTransport::Vless);` (это
`UplinkSection`, не fallback) не трогать.

Sed-вариант для файла целиком:

```bash
sed -i '' -E 's/transport: UplinkTransport::(Ss|Vless),/transport: Some(UplinkTransport::\1),/g' bins/outline-ws-rust/src/config/load/tests/uplinks.rs
```

(BSD sed на macOS: `-E` обязателен — в basic-режиме `\|` не работает.)

- [ ] **Step 6: Прогнать тесты**

Run: `cargo test -p outline-ws-rust fallback_without_transport`
Expected: PASS.

Run: `cargo test -p outline-ws-rust --lib config`
Expected: PASS — весь набор тестов конфига, включая fallback-валидацию.

- [ ] **Step 7: Гейт и коммит**

```bash
cargo fmt --all && cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings
```

```bash
git add bins/outline-ws-rust/src/config/schema.rs bins/outline-ws-rust/src/config/load/uplinks/fallback_resolution.rs bins/outline-ws-rust/src/config/load/tests/uplinks.rs
git commit -m "refactor(ws-config): validate fallback transport instead of requiring it in serde"
```

---

### Task 3: `link` во fallback-секции

**Files:**
- Modify: `bins/outline-ws-rust/src/config/schema.rs` (`FallbackSection`)
- Modify: `bins/outline-ws-rust/src/config/load/uplinks/fallback_resolution.rs`
- Test: `bins/outline-ws-rust/src/config/load/tests/uplinks.rs`,
  `bins/outline-ws-rust/src/config/tests/mod.rs`

**Interfaces:**
- Consumes: `expand_share_link` / `LinkConflictFields` / `LinkExpansion` из
  Task 1; `FallbackSection.transport: Option<UplinkTransport>` из Task 2.
- Produces: `FallbackSection.link: Option<String>` — на него опирается Task 4.

- [ ] **Step 1: Написать падающие тесты**

Добавить в конец `bins/outline-ws-rust/src/config/load/tests/uplinks.rs`
(константа `SS_USERINFO` уже объявлена в этом файле выше):

```rust
// ── Share links inside fallbacks ────────────────────────────────────────────

const VLESS_UUID: &str = "11111111-2222-3333-4444-555555555555";

/// A fallback carrying nothing but `link`, mirroring the minimal
/// `[[outline.uplinks.fallbacks]] link = "…"` shape.
fn link_only_fallback(link: &str) -> FallbackSection {
    FallbackSection {
        transport: None,
        link: Some(link.to_string()),
        ..empty_fallback()
    }
}

#[test]
fn ss_share_link_fallback_expands_into_combined_ss_wire() {
    // The parent is VLESS and carries no usable SS secret for this wire — the
    // link's own credentials must be what lands on it. `#edge` in the link is
    // ignored: identity belongs to the parent uplink.
    let fb = link_only_fallback(&format!(
        "ss://{SS_USERINFO}@ss.example.com:443?type=ws&security=tls&path=%2Fsecret%2Fss&alpn=h3#edge"
    ));
    let cfg = resolve(vless_uplink_section("parent", "https://cdn.example.com/xhttp", vec![fb]))
        .expect("ss share link in a fallback should resolve");

    assert_eq!(cfg.name, "parent", "a fallback link's #NAME must not rename the uplink");
    assert_eq!(cfg.fallbacks.len(), 1);
    let wire = &cfg.fallbacks[0];
    assert_eq!(wire.transport, UplinkTransport::Ss);
    assert_eq!(wire.ss_mode, Some(TransportMode::WsH3));
    assert_eq!(wire.cipher, CipherKind::Chacha20IetfPoly1305);
    assert_eq!(wire.password, "secret");
    let expected = Url::parse("wss://ss.example.com:443/secret/ss").unwrap();
    assert_eq!(wire.ss_ws_url.as_ref(), Some(&expected));
}

#[test]
fn ss_xhttp_share_link_fallback_targets_ss_xhttp_url() {
    let fb = link_only_fallback(&format!(
        "ss://{SS_USERINFO}@ss.example.com:443?type=xhttp&security=tls&path=%2Fxhttp&alpn=h3&mode=stream-one"
    ));
    let cfg = resolve(vless_uplink_section("edge", "https://cdn.example.com/xhttp", vec![fb]))
        .expect("ss xhttp share link in a fallback should resolve");

    let wire = &cfg.fallbacks[0];
    assert_eq!(wire.ss_mode, Some(TransportMode::XhttpH3));
    let expected = Url::parse("https://ss.example.com:443/xhttp?mode=stream-one").unwrap();
    assert_eq!(wire.ss_xhttp_url.as_ref(), Some(&expected));
    assert!(wire.ss_ws_url.is_none());
}

#[test]
fn vless_share_link_fallback_expands_into_vless_wire() {
    let fb = link_only_fallback(&format!(
        "vless://{VLESS_UUID}@vless.example.com:443?type=ws&security=tls&path=%2Fsecret%2Fvless&alpn=h3"
    ));
    let cfg = resolve(vless_uplink_section("edge", "https://cdn.example.com/xhttp", vec![fb]))
        .expect("vless share link in a fallback should resolve");

    let wire = &cfg.fallbacks[0];
    assert_eq!(wire.transport, UplinkTransport::Vless);
    assert_eq!(wire.vless_mode, TransportMode::WsH3);
    assert!(wire.vless_id.is_some(), "vless_id must come from the link");
    let expected = Url::parse("wss://vless.example.com:443/secret/vless").unwrap();
    assert_eq!(wire.vless_ws_url.as_ref(), Some(&expected));
}

#[test]
fn share_link_fallback_rejects_explicit_wire_field() {
    let mut fb = link_only_fallback(&format!(
        "ss://{SS_USERINFO}@ss.example.com:443?type=ws&security=tls"
    ));
    fb.ss_ws_url = Some(Url::parse("wss://other.example.com/ss").unwrap());
    let err = resolve(vless_uplink_section("edge", "https://cdn.example.com/xhttp", vec![fb]))
        .expect_err("explicit ss_ws_url must conflict with the link");
    let msg = format!("{err:#}");
    assert!(msg.contains("mutually exclusive"), "unexpected error: {msg}");
    assert!(msg.contains("fallbacks[0]"), "error must name the fallback: {msg}");
}

#[test]
fn share_link_fallback_rejects_mismatched_transport() {
    let mut fb = link_only_fallback(&format!(
        "ss://{SS_USERINFO}@ss.example.com:443?type=ws&security=tls"
    ));
    fb.transport = Some(UplinkTransport::Vless);
    let err = resolve(vless_uplink_section("edge", "https://cdn.example.com/xhttp", vec![fb]))
        .expect_err("ss:// link with transport=vless must error");
    assert!(format!("{err:#}").contains("transport=ss"), "unexpected error: {err}");
}

#[test]
fn share_link_fallback_keeps_inherited_non_wire_fields() {
    // `vless_uplink_section` sets fwmark = 99 / ipv6_first = true on the parent.
    let fb = link_only_fallback(&format!(
        "ss://{SS_USERINFO}@ss.example.com:443?type=ws&security=tls"
    ));
    let cfg = resolve(vless_uplink_section("edge", "https://cdn.example.com/xhttp", vec![fb]))
        .expect("link fallback should inherit non-wire fields");

    let wire = &cfg.fallbacks[0];
    assert_eq!(wire.fwmark, Some(99), "fwmark must still be inherited");
    assert!(wire.ipv6_first, "ipv6_first must still be inherited");
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `cargo test -p outline-ws-rust share_link_fallback`
Expected: FAIL — компиляция: `struct `FallbackSection` has no field named `link``.

- [ ] **Step 3: Добавить поле в схему**

В `bins/outline-ws-rust/src/config/schema.rs`, в `FallbackSection`, сразу после
`pub(crate) ss_mode: Option<TransportMode>,` вставить:

```rust
    /// Share-link URI for this wire. A `vless://UUID@HOST:PORT?...` link
    /// expands into `vless_id` / `vless_*_url` / `vless_mode`; an
    /// `ss://BASE64(method:password)@HOST:PORT?...` link expands into the
    /// combined-path `ss_*_url` / `ss_mode` plus `method` / `password`. The
    /// scheme also supplies `transport`. Mutually exclusive with the explicit
    /// wire fields; `#NAME` is ignored (identity belongs to the parent
    /// uplink). See `docs/UPLINK-CONFIGURATIONS.md` "Per-uplink fallback
    /// transports".
    pub(crate) link: Option<String>,
```

Тут же дополнить тестовый хелпер `empty_fallback()` в
`bins/outline-ws-rust/src/config/load/tests/uplinks.rs` — он перечисляет все
поля структуры и без новой строки не скомпилируется. После
`ss_mode: None,` добавить:

```rust
        link: None,
```

- [ ] **Step 4: Добавить pre-pass в резолвер**

В `bins/outline-ws-rust/src/config/load/uplinks/fallback_resolution.rs`
расширить импорты:

```rust
use std::borrow::Cow;

use anyhow::{Result, anyhow, bail};

use outline_transport::TransportMode;
use outline_uplink::{FallbackTransport, UplinkConfig, UplinkTransport};

use crate::config::schema::FallbackSection;

use super::credentials::{parse_vless_id, validate_shared_secret};
use super::wire_shape::{LinkConflictFields, expand_share_link};
```

Добавить функцию перед `resolve_fallback`:

```rust
/// Expand a fallback's `link = "…"` into its wire fields before the regular
/// validation runs, and resolve the wire's transport.
///
/// Filling the section rather than teaching `resolve_fallback` about links
/// keeps one description of a share link in the tree: the carrier↔URL checks,
/// the `h3`-feature gate and the parent-inheritance rules below then apply to
/// a link-configured wire exactly as they do to a hand-written one. The
/// credentials the link carries land in the section, so the inherit-from-parent
/// defaults never kick in for this wire — which is what lets an `ss://`
/// fallback sit under a VLESS parent with no explicit `method` / `password`.
fn apply_link<'a>(
    parent_name: &str,
    section: &'a FallbackSection,
    idx: usize,
) -> Result<(Cow<'a, FallbackSection>, UplinkTransport)> {
    let Some(raw_link) = section.link.as_deref() else {
        let transport = section.transport.ok_or_else(|| {
            anyhow!("uplink {parent_name}: fallbacks[{idx}] requires `transport` (`ss` or `vless`)")
        })?;
        return Ok((Cow::Borrowed(section), transport));
    };

    let expansion = expand_share_link(
        &format!("uplink {parent_name}: fallbacks[{idx}]"),
        raw_link,
        section.transport,
        LinkConflictFields {
            tcp_ws_url: section.tcp_ws_url.is_some(),
            tcp_xhttp_url: section.tcp_xhttp_url.is_some(),
            tcp_mode: section.tcp_mode.is_some(),
            udp_ws_url: section.udp_ws_url.is_some(),
            udp_xhttp_url: section.udp_xhttp_url.is_some(),
            udp_mode: section.udp_mode.is_some(),
            vless_ws_url: section.vless_ws_url.is_some(),
            vless_xhttp_url: section.vless_xhttp_url.is_some(),
            vless_mode: section.vless_mode.is_some(),
            ss_ws_url: section.ss_ws_url.is_some(),
            ss_xhttp_url: section.ss_xhttp_url.is_some(),
            ss_mode: section.ss_mode.is_some(),
            vless_id: section.vless_id.is_some(),
            method: section.method.is_some(),
            password: section.password.is_some(),
        },
    )?;

    let mut expanded = section.clone();
    expanded.transport = Some(expansion.transport);
    expanded.vless_ws_url = expansion.vless_ws_url;
    expanded.vless_xhttp_url = expansion.vless_xhttp_url;
    expanded.vless_mode = expansion.vless_mode;
    expanded.ss_ws_url = expansion.ss_ws_url;
    expanded.ss_xhttp_url = expansion.ss_xhttp_url;
    expanded.ss_mode = expansion.ss_mode;
    expanded.vless_id = expansion.vless_id;
    if expansion.cipher.is_some() {
        expanded.method = expansion.cipher;
    }
    if expansion.password.is_some() {
        expanded.password = expansion.password;
    }
    Ok((Cow::Owned(expanded), expansion.transport))
}
```

Заменить начало `resolve_fallback` (строки с `let parent_name = …` и
`let transport = section.transport.ok_or_else(…)` из Task 2) на:

```rust
    let parent_name = &parent.name;
    let (section, transport) = apply_link(parent_name, section, idx)?;
    let section = section.as_ref();
```

Остальное тело функции не трогать: `section` теперь `&FallbackSection` с уже
заполненными полями.

- [ ] **Step 5: Прогнать тесты**

Run: `cargo test -p outline-ws-rust share_link_fallback`
Expected: PASS — 6 тестов из шага 1.

Run: `cargo test -p outline-ws-rust --lib config`
Expected: PASS.

- [ ] **Step 6: Добавить TOML-тест сквозь загрузчик**

В `bins/outline-ws-rust/src/config/tests/mod.rs` после
`load_config_rejects_link_alongside_explicit_vless_url` (строка 1569) добавить:

```rust
#[tokio::test]
async fn load_config_expands_share_link_inside_fallbacks() {
    // A fallback wire described by nothing but `link` must resolve into the
    // same shape a hand-written `[[outline.uplinks.fallbacks]]` block does.
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");
    std::fs::write(
        &path,
        r#"
        [socks5]
        listen = "127.0.0.1:1080"

        [[outline.uplinks]]
        name = "edge"
        group = "main"
        link = "vless://11111111-2222-3333-4444-555555555555@vless.example.com:443?type=xhttp&security=tls&path=%2Fsecret%2Fxhttp&alpn=h3&mode=stream-one"

        [[outline.uplinks.fallbacks]]
        link = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@ss.example.com:443?type=ws&security=tls&path=%2Fsecret%2Fss&alpn=h3"

        [[uplink_group]]
        name = "main"
        "#,
    )
    .unwrap();

    let args = super::Args::parse_from(["test"]);
    let config = load_config(&path, &args).await.unwrap();
    let uplink = &config.groups[0].uplinks[0];
    assert_eq!(uplink.fallbacks.len(), 1);
    let wire = &uplink.fallbacks[0];
    assert_eq!(wire.transport, UplinkTransport::Ss);
    let url = wire.ss_ws_url.as_ref().expect("ss_ws_url expanded from the link");
    assert_eq!(url.scheme(), "wss");
    assert_eq!(url.host_str(), Some("ss.example.com"));
    assert_eq!(url.path(), "/secret/ss");
}
```

- [ ] **Step 7: Прогнать тест загрузчика**

Run: `cargo test -p outline-ws-rust load_config_expands_share_link_inside_fallbacks`
Expected: PASS.

- [ ] **Step 8: Гейт и коммит**

```bash
cargo fmt --all && cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings
```

```bash
git add bins/outline-ws-rust/src/config
git commit -m "feat(ws-config): accept share links in [[outline.uplinks.fallbacks]]"
```

---

### Task 4: `link` во fallback через `/control/uplinks`

**Files:**
- Modify: `bins/outline-ws-rust/src/http/control/uplinks_crud/payload.rs:67-86`
  (`FallbackPayload`), `:219-253` (`fallbacks_to_array`)
- Test: `bins/outline-ws-rust/src/http/control/uplinks_crud/tests/uplinks_crud.rs`

**Interfaces:**
- Consumes: `FallbackSection.link` и `FallbackSection.transport: Option<…>` из
  Task 2 и Task 3.
- Produces: `FallbackPayload.link: Option<String>`,
  `FallbackPayload.transport: Option<String>`.

- [ ] **Step 1: Написать падающий тест**

Добавить в `bins/outline-ws-rust/src/http/control/uplinks_crud/tests/uplinks_crud.rs`
после `rendered_toml_inserted_into_document_includes_fallbacks_array`:

```rust
#[test]
fn fallback_payload_accepts_share_link_without_transport() {
    let payload = UplinkPayload {
        name: Some("edge".into()),
        link: Some(
            "vless://11111111-2222-3333-4444-555555555555@vless.example.com:443\
             ?type=xhttp&security=tls&path=%2Fxhttp&alpn=h3"
                .into(),
        ),
        fallbacks: Some(vec![FallbackPayload {
            link: Some(
                "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@ss.example.com:443\
                 ?type=ws&security=tls&path=%2Fss&alpn=h3"
                    .into(),
            ),
            ..Default::default()
        }]),
        ..Default::default()
    };
    let section = payload_to_section(&payload, Some("core")).unwrap();
    let fbs = section.fallbacks.as_ref().expect("fallbacks must round-trip");
    assert_eq!(fbs.len(), 1);
    assert!(fbs[0].transport.is_none(), "transport comes from the link scheme");
    assert!(fbs[0].link.is_some(), "link must survive the JSON → TOML round-trip");
    // Validation walks the same pipeline as the TOML loader.
    validate_uplink_section(&section, 0).unwrap();
}

#[test]
fn rendered_fallback_toml_carries_link_and_omits_absent_transport() {
    let payload = UplinkPayload {
        name: Some("edge".into()),
        link: Some(
            "vless://11111111-2222-3333-4444-555555555555@vless.example.com:443\
             ?type=ws&security=tls&path=%2Fv&alpn=h3"
                .into(),
        ),
        fallbacks: Some(vec![FallbackPayload {
            link: Some(
                "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@ss.example.com:443\
                 ?type=ws&security=tls&path=%2Fss&alpn=h3"
                    .into(),
            ),
            ..Default::default()
        }]),
        ..Default::default()
    };
    let mut doc = r#"
[[uplink_group]]
name = "core"
"#
    .parse::<DocumentMut>()
    .unwrap();
    let arr = get_or_init_outline_uplinks(&mut doc);
    arr.push(payload_to_table(&payload));
    let rendered = doc.to_string();
    assert!(
        rendered.contains("[[outline.uplinks.fallbacks]]"),
        "rendered TOML must contain fallbacks array-of-tables:\n{rendered}",
    );
    assert!(rendered.contains("link = \"ss://"), "fallback link must be rendered:\n{rendered}");
    assert!(
        !rendered.contains("transport = \"\""),
        "absent transport must be omitted, not rendered empty:\n{rendered}",
    );
}

#[test]
fn patch_replaces_fallbacks_with_share_link_entry() {
    let mut doc = r#"
[[uplink_group]]
name = "core"

[[outline.uplinks]]
name = "edge"
group = "core"
transport = "vless"
vless_ws_url = "wss://primary.example.com/v"
vless_mode = "ws_h2"
vless_id = "00000000-0000-0000-0000-000000000000"
method = "chacha20-ietf-poly1305"
password = "some-long-password"

[[outline.uplinks.fallbacks]]
transport = "ws"
tcp_ws_url = "wss://old.example.com:8388/tcp"
"#
    .parse::<DocumentMut>()
    .unwrap();
    let arr = get_or_init_outline_uplinks(&mut doc);
    let idx = find_outline_uplink_index(arr, "core", "edge").unwrap();
    let tbl = arr.get_mut(idx).unwrap();
    let patch = UplinkPayload {
        fallbacks: Some(vec![FallbackPayload {
            link: Some(
                "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@ss.example.com:443\
                 ?type=ws&security=tls&path=%2Fss&alpn=h3"
                    .into(),
            ),
            ..Default::default()
        }]),
        ..Default::default()
    };
    merge_patch_into_table(tbl, &patch);
    let rendered = doc.to_string();
    assert!(rendered.contains("link = \"ss://"), "patched link must be rendered:\n{rendered}");
    assert!(
        !rendered.contains("old.example.com"),
        "patch must replace the existing fallbacks list:\n{rendered}",
    );
}
```

- [ ] **Step 2: Убедиться, что тесты падают**

Run: `cargo test -p outline-ws-rust fallback_payload_accepts_share_link`
Expected: FAIL — компиляция: `struct `FallbackPayload` has no field named `link``.

- [ ] **Step 3: Расширить payload**

В `bins/outline-ws-rust/src/http/control/uplinks_crud/payload.rs` заменить в
`FallbackPayload`:

```rust
    pub(crate) transport: String,
```

на:

```rust
    /// `ss` / `vless`. Optional when `link` is set — the URI scheme picks the
    /// transport, mirroring `[[outline.uplinks.fallbacks]]` in the TOML.
    pub(crate) transport: Option<String>,
    /// Share-link URI for this wire (`vless://…` / `ss://…`). Same semantics
    /// as `UplinkPayload::link`, applied to a single fallback wire.
    #[serde(alias = "share_link")]
    pub(crate) link: Option<String>,
```

И в doc-комментарии структуры заменить
`(no `name` / `weight` / `group` / `link`; those belong to the parent uplink)`
на `(no `name` / `weight` / `group`; those belong to the parent uplink)`.

- [ ] **Step 4: Рендерить новые поля в TOML**

В `fallbacks_to_array` заменить:

```rust
        sub.insert("transport", Item::Value(Value::from(fb.transport.as_str())));
```

на:

```rust
        set_str(&mut sub, "transport", fb.transport.as_deref());
        set_str(&mut sub, "link", fb.link.as_deref());
```

- [ ] **Step 5: Обновить существующие тестовые литералы**

Run: `grep -n "transport: \"" bins/outline-ws-rust/src/http/control/uplinks_crud/tests/uplinks_crud.rs`
Expected: 5 совпадений — все внутри `FallbackPayload { … }` (строки 293, 303,
340, 392, 507 на момент написания плана). Литералы `UplinkPayload` уже пишут
`transport: Some("vless".into())` и правки не требуют.

```bash
sed -i '' -E 's/transport: "(ws|vless|ss)"\.into\(\),/transport: Some("\1".into()),/g' bins/outline-ws-rust/src/http/control/uplinks_crud/tests/uplinks_crud.rs
```

Затем проверить глазами, что ни одна из заменённых строк не принадлежит
`UplinkPayload`: `grep -n "transport: Some(" …` — у `UplinkPayload` значение
уже было обёрнуто, двойной обёртки быть не должно.

- [ ] **Step 6: Прогнать тесты**

Run: `cargo test -p outline-ws-rust uplinks_crud`
Expected: PASS — включая два новых теста.

- [ ] **Step 7: Гейт и коммит**

```bash
cargo fmt --all && cargo clippy -p outline-ws-rust --all-targets --no-deps -- -D warnings
```

```bash
git add bins/outline-ws-rust/src/http/control/uplinks_crud
git commit -m "feat(ws-control): accept share links in fallback payloads"
```

---

### Task 5: Документация, пример конфига, CHANGELOG

**Files:**
- Modify: `bins/outline-ws-rust/config.toml` (блок примеров fallback,
  строки 602-637)
- Modify: `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md:2020-2033`
  (раздел «Per-uplink fallback transports» → «Fields»)
- Modify: `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.ru.md` (тот же
  раздел «Поля»)
- Modify: `bins/outline-ws-rust/CHANGELOG.md`,
  `bins/outline-ws-rust/CHANGELOG.ru.md` (секция `[Unreleased] / Added`)

**Interfaces:**
- Consumes: финальную схему из Task 3 и Task 4. Кода не добавляет.

- [ ] **Step 1: Пример в `config.toml`**

После блока примеров per-uplink fallback (после строки 637, перед комментарием
про `shuffle_wires`) вставить:

```toml
# The same uplink written entirely as share links: every wire — primary and
# each fallback — is one URI. The scheme picks the transport (`vless://` →
# vless, `ss://` → combined-path ss), `type` + `alpn` pick the carrier
# (`type=ws&alpn=h3` → ws_h3, `type=xhttp&alpn=h3` → xhttp_h3), and the
# credentials ride inside the URI. Identity and policy stay in TOML.
#
# [[outline.uplinks]]
# name = "edge-links"
# group = "main"
# weight = 1.0
# link = "vless://00000000-0000-0000-0000-000000000000@cdn.example.com:443?type=xhttp&security=tls&path=%2FSECRET%2Fxhttp&alpn=h3&mode=stream-one"
#
# [[outline.uplinks.fallbacks]]
# link = "vless://00000000-0000-0000-0000-000000000000@cdn.example.com:443?type=ws&security=tls&path=%2FSECRET%2Fws&alpn=h3"
#
# [[outline.uplinks.fallbacks]]
# link = "ss://BASE64URL@cdn.example.com:443?type=ws&security=tls&path=%2FSECRET%2Fss&alpn=h3"
```

- [ ] **Step 2: EN-документация**

В `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md`, раздел «Fields»
(строка 2022), заменить

```
top-level `[[outline.uplinks]]` schema **minus** the identity attributes
that belong to the parent (`name`, `weight`, `group`, `link`):
```

на

```
top-level `[[outline.uplinks]]` schema **minus** the identity attributes
that belong to the parent (`name`, `weight`, `group`):
```

В таблице `### Fields` заменить строку `transport` на:

```
| `transport` | unless `link` is set | `ss` / `vless` (`ss` also accepts the deprecated `ws` / `websocket` aliases). Omit it next to a `link` — the URI scheme supplies it; a value that disagrees with the scheme is rejected at load. **No uniqueness restriction** — same-transport-as-parent and duplicate-transport entries are explicitly allowed. The most common cross-family shape is a VLESS primary on `xhttp_h*` with a VLESS fallback on `ws_h*` (same `transport = "vless"`, different carrier family, different dial URL); two VLESS fallbacks at distinct hosts as belt-and-suspenders also work. The dial loop and per-wire mode tracking treat each fallback as its own wire regardless of `transport`. |
| `link` | — | Share-link URI for this wire (`vless://…` or `ss://…`), the same format section 5 and "Share-link URI (`ss://`)" describe. Expands into the wire fields of its transport plus the credentials it carries, so a link-configured fallback needs no other field. Mutually exclusive with the explicit wire fields (`tcp_*`, `udp_*`, `vless_*`, `ss_*`, `vless_id`; `method` / `password` conflict with an `ss://` link only). `#NAME` is ignored — identity belongs to the parent uplink. There is no single-URL form for the split `tcp_*` / `udp_*` SS layout; use the long form for it. |
```

Сразу после таблицы добавить пример:

````
An uplink whose wires are all share links — the shape a subscription-driven
config takes:

```toml
[[outline.uplinks]]
name   = "edge-links"
group  = "main"
weight = 1.0
link   = "vless://00000000-0000-0000-0000-000000000000@cdn.example.com:443?type=xhttp&security=tls&path=%2FSECRET%2Fxhttp&alpn=h3&mode=stream-one"

  [[outline.uplinks.fallbacks]]
  link = "vless://00000000-0000-0000-0000-000000000000@cdn.example.com:443?type=ws&security=tls&path=%2FSECRET%2Fws&alpn=h3"

  [[outline.uplinks.fallbacks]]
  link = "ss://BASE64URL@cdn.example.com:443?type=ws&security=tls&path=%2FSECRET%2Fss&alpn=h3"
```

Credentials ride inside each URI, so the parent's `cipher` / `password` are not
consulted for these wires — an `ss://` fallback under a VLESS parent needs no
explicit secret. Everything that is *not* wire shape still comes from the
parent: `fwmark`, `ipv6_first` and `fingerprint_profile` are inherited exactly
as they are for a hand-written fallback.
````

- [ ] **Step 3: RU-документация**

Внести те же правки в `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.ru.md`,
раздел «Поля»: убрать `link` из списка родительских атрибутов, заменить строку
`transport` на

```
| `transport` | если не задан `link` | `ss` / `vless` (`ss` также принимает deprecated-алиасы `ws` / `websocket`). Рядом с `link` его можно не писать — транспорт даёт схема URI; значение, противоречащее схеме, отбивается при загрузке. **Ограничений по уникальности нет** — same-transport-as-parent и duplicate-transport entries разрешены явно. Самая распространённая кросс-family форма: VLESS primary на `xhttp_h*` плюс VLESS fallback на `ws_h*` (тот же `transport = "vless"`, другая carrier-семья, другой dial URL); два VLESS fallback'а на разные хосты (belt-and-suspenders) тоже работают. Dial-loop и per-wire mode tracking трактуют каждый fallback как собственный wire независимо от `transport`. |
| `link` | — | Share-link URI этого wire (`vless://…` либо `ss://…`), тот же формат, что в разделе 5 и «Share-link URI (`ss://`)». Разворачивается в wire-поля своего транспорта плюс креды, которые несёт, поэтому fallback'у со ссылкой другие поля не нужны. Взаимоисключающ с явными wire-полями (`tcp_*`, `udp_*`, `vless_*`, `ss_*`, `vless_id`; `method` / `password` конфликтуют только с `ss://`-ссылкой). `#NAME` игнорируется — идентичность принадлежит родительскому аплинку. Для split-раскладки `tcp_*` / `udp_*` формы одной ссылкой нет — там остаётся длинная форма. |
```

и добавить тот же пример с переводом пояснения:

````
Аплинк, у которого все wire заданы ссылками — форма, в которую складывается
конфиг, собранный из подписки:

```toml
[[outline.uplinks]]
name   = "edge-links"
group  = "main"
weight = 1.0
link   = "vless://00000000-0000-0000-0000-000000000000@cdn.example.com:443?type=xhttp&security=tls&path=%2FSECRET%2Fxhttp&alpn=h3&mode=stream-one"

  [[outline.uplinks.fallbacks]]
  link = "vless://00000000-0000-0000-0000-000000000000@cdn.example.com:443?type=ws&security=tls&path=%2FSECRET%2Fws&alpn=h3"

  [[outline.uplinks.fallbacks]]
  link = "ss://BASE64URL@cdn.example.com:443?type=ws&security=tls&path=%2FSECRET%2Fss&alpn=h3"
```

Креды едут внутри каждой ссылки, поэтому `cipher` / `password` родителя для
этих wire не читаются — `ss://`-fallback под VLESS-родителем не требует явного
секрета. Всё, что не относится к wire-форме, по-прежнему приходит от родителя:
`fwmark`, `ipv6_first` и `fingerprint_profile` наследуются ровно так же, как у
рукописного fallback'а.
````

- [ ] **Step 4: CHANGELOG (EN)**

В `bins/outline-ws-rust/CHANGELOG.md`, первым пунктом секции
`## [Unreleased]` → `### Added`:

```markdown
- **`[[outline.uplinks.fallbacks]] link = "…"` — a fallback wire can now be described by a single share-link URI.** `link` was accepted on the uplink itself (and by the CLI and `/control/uplinks`) but not on its fallback wires, which is where most wires actually live: a production config here runs three uplinks of primary-plus-three-fallbacks, so nine of its twelve wires had no single-URL form and the shorthand covered a quarter of the file. A fallback now takes the same `vless://UUID@HOST:PORT?…` / `ss://BASE64(method:password)@HOST:PORT?…` URIs as the parent, with the scheme supplying the transport (`transport` becomes optional next to a `link`, and a value disagreeing with the scheme is rejected at load rather than silently ignored) and `type` + `alpn` supplying the carrier (`type=ws&alpn=h3` → `ws_h3`, `type=xhttp&alpn=h3` → `xhttp_h3`). The credentials ride inside the URI, so a link-configured wire never falls back to the parent's `cipher` / `password` — which is what lets an `ss://` fallback sit under a VLESS parent with no explicit secret, previously impossible without repeating the shared secret in the config. Everything that is not wire shape still comes from the parent: `fwmark`, `ipv6_first` and `fingerprint_profile` are inherited exactly as before, and `#NAME` in a fallback link is ignored because identity (name, weight, group) belongs to the uplink. Dial behaviour is untouched — the link fills the same fields a hand-written fallback sets, then walks the identical validation and the identical wire chain. The split `tcp_*` / `udp_*` SS layout still has no single-URL form. See "Per-uplink fallback transports" in `docs/UPLINK-CONFIGURATIONS.md`.
```

- [ ] **Step 5: CHANGELOG (RU)**

Тот же пункт в `bins/outline-ws-rust/CHANGELOG.ru.md`, первым в
`## [Unreleased]` → `### Добавлено` (сверить точное название заголовка в файле
и следовать ему):

```markdown
- **`[[outline.uplinks.fallbacks]] link = "…"` — fallback-wire теперь описывается одной share-link-ссылкой.** `link` принимался на самом аплинке (а также в CLI и `/control/uplinks`), но не на его fallback-wire — а именно там живёт большинство wire: в боевом конфиге три аплинка вида primary-плюс-три-fallback, то есть девять из двенадцати wire не имели формы одной ссылки, и сокращённая запись покрывала четверть файла. Fallback принимает те же URI `vless://UUID@HOST:PORT?…` / `ss://BASE64(method:password)@HOST:PORT?…`, что и родитель: транспорт даёт схема (`transport` рядом с `link` становится необязательным, а значение, противоречащее схеме, отбивается при загрузке, а не игнорируется молча), носитель — пара `type` + `alpn` (`type=ws&alpn=h3` → `ws_h3`, `type=xhttp&alpn=h3` → `xhttp_h3`). Креды едут внутри URI, поэтому wire со ссылкой никогда не откатывается к родительским `cipher` / `password` — именно это позволяет держать `ss://`-fallback под VLESS-родителем без явного секрета, что раньше требовало дублировать shared secret в конфиге. Всё, что не относится к wire-форме, по-прежнему приходит от родителя: `fwmark`, `ipv6_first` и `fingerprint_profile` наследуются как раньше, а `#NAME` в fallback-ссылке игнорируется — идентичность (имя, вес, группа) принадлежит аплинку. Поведение дайла не меняется: ссылка заполняет те же поля, что задаёт рукописный fallback, после чего проходит ту же валидацию и ту же цепочку wire. Для split-раскладки `tcp_*` / `udp_*` формы одной ссылкой по-прежнему нет. См. «Per-uplink fallback transports» в `docs/UPLINK-CONFIGURATIONS.md`.
```

- [ ] **Step 6: Полный гейт**

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
```

```bash
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
```

```bash
cargo test --workspace --exclude sockudo-ws
```

Expected: все три зелёные.

- [ ] **Step 7: Проверить, что пример конфига остался валидным TOML**

У бинаря нет режима «только проверить конфиг», а тестов, читающих
`bins/outline-ws-rust/config.toml`, в репозитории нет — новый блок целиком
закомментирован, поэтому достаточно убедиться, что файл по-прежнему парсится:

```bash
python3 -c "import tomllib; tomllib.load(open('bins/outline-ws-rust/config.toml','rb')); print('config.toml parses')"
```

Expected: `config.toml parses`.

- [ ] **Step 8: Коммит**

```bash
git add bins/outline-ws-rust/config.toml bins/outline-ws-rust/docs bins/outline-ws-rust/CHANGELOG.md bins/outline-ws-rust/CHANGELOG.ru.md
git commit -m "docs(ws): document share links in fallback wires"
```

---

## Проверка результата

После Task 5 конфиг такой формы должен грузиться и давать четыре wire на
аплинк — три fallback'а плюс primary:

```toml
[[outline.uplinks]]
name = "edge"
group = "main"
weight = 1.0
shuffle_wires = true
shuffle_timer = "1h"
padding = true
link = "vless://…?type=xhttp&security=tls&path=%2F…&alpn=h3&mode=stream-one"

[[outline.uplinks.fallbacks]]
link = "vless://…?type=ws&security=tls&path=%2F…&alpn=h3"

[[outline.uplinks.fallbacks]]
link = "ss://…?type=xhttp&security=tls&path=%2F…&alpn=h3&mode=stream-one"

[[outline.uplinks.fallbacks]]
link = "ss://…?type=ws&security=tls&path=%2F…&alpn=h3"
```

Что осталось за рамками плана (спека, «Вне объёма»): параметр `carrier=ws_h3`
в ссылках, миграция боевых конфигов парка и URI-aware переписывание
`phase_uplinks` в `ops/provision-node/install.sh`.
