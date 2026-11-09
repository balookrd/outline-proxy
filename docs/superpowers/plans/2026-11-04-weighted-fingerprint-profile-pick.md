# Взвешенный выбор профиля отпечатка — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Цель:** профиль браузера выбирается из пула ОС с весами, близкими к реальной
доле браузеров, по хэшу, который не зависит от версии Rust; оператор может
закрепить конкретный профиль за узлом.

**Почему.** Сейчас `process_stable` берёт `DefaultHasher(hostname) % len(pool)`.
В Linux-пуле два профиля, решает младший бит хэша, и на всех четырёх клиентах
(`NanoPi-NEO3-Plus`, `Beelink-T4-Pro`, `cloud1.beerloga.su`,
`cloud2.beerloga.su`) он оказался единицей: везде `firefox-159-linux` (шанс
1/16). Кроме того, `DefaultHasher` не гарантирует одинаковый вывод между
версиями Rust: после смены тулчейна профиль узла может молча смениться.

**Архитектура.** В `crates/outline-transport/src/fingerprint_profile.rs`:
1. `DefaultHasher` заменяется на собственный стабильный сид: FNV-1a 64 +
   финализатор splitmix64 (без новых зависимостей, вывод зафиксирован тестом).
2. У `Profile` появляется поле `weight: u32`. `pick` переводит 64-битный сид в
   `[0, total)` умножением со сдвигом (старшие биты, без смещения от `%`) и
   ищет отрезок по накопленным весам. Это касается всех стратегий: и
   `per_host_stable`, и `process_stable`, и `random`.
3. Процессное закрепление: `init_pinned_profile`. Если оно задано и ОС профиля
   совпадает, `ProcessStable` возвращает его вместо хэшевого выбора.

В `bins/outline-ws-rust` — верхнеуровневый ключ конфига
`fingerprint_profile_pin = "chrome" | "firefox" | "safari"` (браузер без
версии, чтобы обновление `PROFILES` не ломало конфиги), проверка при загрузке,
вызов `init_pinned_profile` в bootstrap.

**Стек:** Rust (edition 2024), `serde`, `toml`, `tokio` (тесты конфига).

## Глобальные ограничения

- Хэш: FNV-1a 64 (offset `0xcbf2_9ce4_8422_2325`, prime `0x0000_0100_0000_01b3`) + splitmix64. Никакого `DefaultHasher`/`RandomState` в выборе профиля.
- Новых зависимостей в `outline-transport` не добавлять.
- Веса (решение владельца, менять только в таблице `PROFILES`): Linux — `chrome-157-linux` 70, `firefox-159-linux` 30; macOS — `chrome-157-macos` 60, `safari-27-macos` 30, `firefox-159-macos` 10; Android — `chrome-157-android` 100.
- Имя ключа конфига — `fingerprint_profile_pin`. НЕ `fingerprint_profile_name`: так уже называется поле snapshot/topology с активным профилем.
- Значение `fingerprint_profile_pin` — браузер без версии: `chrome`, `firefox` или `safari`. Профиль этого браузера берётся из пула ОС. Имена с версией (`chrome-157-linux`) ключ НЕ принимает: при обновлении `PROFILES` они исчезают, и узел с таким закреплением не стартовал бы после выкладки бинаря.
- Инвариант таблицы `PROFILES`: в пуле одной ОС не больше одного профиля на браузер. Иначе закрепление по браузеру неоднозначно; держит тест.
- Закрепление действует только там, где эффективная стратегия — `process_stable`; для `none` / `per_host_stable` / `random` ключ игнорируется.
- Браузер, которого нет в пуле ОС (`safari` на Linux, `firefox` на Android), или неизвестное значение — ошибка загрузки конфига (TCP-SYN Linux + Safari hello = несовместимая пара).
- Тесты — в `tests/<module>.rs` рядом с модулем, без inline `mod tests {}`.
- Комментарии в коде и сообщения коммитов — на английском. Документация — EN и RU в одном изменении.
- `ConfigFile` — `deny_unknown_fields`: старый бинарь с новым ключом НЕ стартует. На узлах сначала бинарь, потом ключ.
- Коммиты только после явной команды владельца; `git commit -- <paths>` (в индексе бывает чужое: сейчас там `mesh_relay.rs` и план PMTUD — их не трогать).

## Ожидаемая раскладка парка после выкладки (без закрепления)

Посчитана тем же алгоритмом, что в задачах 1–2 (сид от hostname, веса 70/30):

| узел | hostname | u = seed / 2⁶⁴ | профиль |
|---|---|---|---|
| .104 | `NanoPi-NEO3-Plus` | 0.951 | firefox-159-linux |
| .102 | `Beelink-T4-Pro` | 0.734 | firefox-159-linux |
| cloud1 | `cloud1.beerloga.su` | 0.547 | chrome-157-linux |
| cloud2 | `cloud2.beerloga.su` | 0.537 | chrome-157-linux |

Chrome ⇔ `u < 0.70`. На 100 000 синтетических hostname доля Chrome вышла 0.701.
Итог 2/2: домашние узлы остаются на Firefox (их профиль не меняется), облака
переходят на Chrome. Мак-клиент владельца (macOS-пул) тоже может сменить
профиль — проверить его строкой лога после обновления.

## Затрагиваемые файлы

- `crates/outline-transport/src/fingerprint_profile.rs` — сид, веса, `pick`, закрепление.
- `crates/outline-transport/src/tests/fingerprint_profile.rs` — тесты модуля.
- `crates/outline-transport/src/lib.rs` — реэкспорт новых функций.
- `bins/outline-ws-rust/src/config/schema.rs` — ключ `fingerprint_profile_pin`.
- `bins/outline-ws-rust/src/config/types.rs` — поле `AppConfig::fingerprint_profile_pin`.
- `bins/outline-ws-rust/src/config/load/mod.rs` — проверка и проброс.
- `bins/outline-ws-rust/src/config/tests/mod.rs` — тесты загрузки.
- `bins/outline-ws-rust/src/bootstrap/mod.rs` — `init_pinned_profile`.
- `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md` + `.ru.md`, `bins/outline-ws-rust/CHANGELOG.md` + `.ru.md`.

Вне плана: `PATCH /control/config` (ключ правится файлом; `toml_edit` в
`config_crud.rs` сохраняет незнакомые ключи, поэтому UI его не сотрёт),
outline-ui, Android (`android/rust` не читает `fingerprint_profile_pin`).

---

### Task 1: Стабильный сид вместо `DefaultHasher`

**Files:**
- Modify: `crates/outline-transport/src/fingerprint_profile.rs` (импорты строки 41–43, `host_index` ~592, `process_index` ~624, `pick` ~555, `select_with_strategy_for_os` ~578)
- Test: `crates/outline-transport/src/tests/fingerprint_profile.rs`

**Interfaces:**
- Produces: `pub(crate) fn stable_seed(bytes: &[u8]) -> u64`; `fn host_seed(url: &Url) -> u64`; `fn process_seed() -> u64`; `fn pick(os: ProfileOs, seed: u64) -> &'static Profile` (сид теперь `u64`, не `usize`).

- [ ] **Step 1: Написать падающие тесты**

В конец `crates/outline-transport/src/tests/fingerprint_profile.rs` и в `use crate::fingerprint_profile::{...}` добавить `stable_seed`:

```rust
#[test]
fn fnv1a_matches_the_reference_vector() {
    // FNV-1a 64 reference values (draft-eastlake-fnv): "" -> offset basis,
    // "a" -> 0xaf63dc4c8601ec8c. Checked before the splitmix finaliser.
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    assert_eq!(crate::fingerprint_profile::fnv1a64(b"", OFFSET), OFFSET);
    assert_eq!(crate::fingerprint_profile::fnv1a64(b"a", OFFSET), 0xaf63_dc4c_8601_ec8c);
}

#[test]
fn stable_seed_is_pinned_across_toolchains() {
    // Golden values: a change here silently re-rolls the browser identity of
    // every deployed client on upgrade. Update only on a deliberate re-roll.
    assert_eq!(stable_seed(b"Beelink-T4-Pro"), 0xbbd5_4375_c5c6_d5d6);
    assert_eq!(stable_seed(b"cloud1.beerloga.su"), 0x8c15_c197_ba6e_7107);
}

#[test]
fn per_host_seed_is_pinned_across_toolchains() {
    let url = Url::parse("wss://example.com/path?q=1").unwrap();
    assert_eq!(crate::fingerprint_profile::host_seed(&url), 0xa88b_026a_c3b1_2678);
}
```

- [ ] **Step 2: Убедиться, что падают**

Run: `cargo test -p outline-transport --lib fingerprint_profile::tests:: 2>&1 | tail -20`
Expected: ошибка компиляции — `stable_seed`, `fnv1a64`, `host_seed` не найдены.

- [ ] **Step 3: Реализация**

В `fingerprint_profile.rs` убрать `use std::collections::hash_map::DefaultHasher;` и `use std::hash::{Hash, Hasher};` и добавить перед `host_index`:

```rust
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64 over `bytes`, continuing from `state` (pass [`FNV_OFFSET`] to
/// start). Unlike `DefaultHasher`, its output is fixed by definition, so a
/// toolchain upgrade cannot re-roll a deployed client's browser identity.
pub(crate) fn fnv1a64(bytes: &[u8], mut state: u64) -> u64 {
    for &b in bytes {
        state ^= u64::from(b);
        state = state.wrapping_mul(FNV_PRIME);
    }
    state
}

/// splitmix64 finaliser: FNV-1a leaves the high bits of short inputs poorly
/// mixed, and [`pick`] reads exactly the high bits.
fn splitmix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Toolchain-independent 64-bit seed for profile selection.
pub(crate) fn stable_seed(bytes: &[u8]) -> u64 {
    splitmix64(fnv1a64(bytes, FNV_OFFSET))
}
```

Заменить `host_index` на:

```rust
/// Stable seed of `(host, port)`; path and query do not take part.
pub(crate) fn host_seed(url: &Url) -> u64 {
    let host = url.host_str().unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(0);
    splitmix64(fnv1a64(&port.to_be_bytes(), fnv1a64(host.as_bytes(), FNV_OFFSET)))
}
```

Заменить `process_index` (doc-комментарий оставить, поправив «hash» на «stable seed») на:

```rust
fn process_seed() -> u64 {
    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(|| match read_hostname() {
        Some(name) => stable_seed(name.as_bytes()),
        None => rand::random::<u64>(),
    })
}
```

В `pick` поменять тип сида на `u64` и индекс на `(seed % len as u64) as usize` (веса придут в задаче 2). В `select_with_strategy_for_os`:

```rust
        Strategy::PerHostStable => Some(pick(os, host_seed(url))),
        Strategy::ProcessStable => Some(pick(os, process_seed())),
        Strategy::Random => Some(pick(os, rand::random::<u64>())),
```

- [ ] **Step 4: Тесты проходят**

Run: `cargo test -p outline-transport --lib fingerprint_profile 2>&1 | tail -5`
Expected: `test result: ok`, все тесты модуля зелёные (включая старые `select_with_per_host_stable_*`).

- [ ] **Step 5: Коммит (после команды владельца)**

```bash
git commit -m "fix(fingerprint): seed profile selection with a toolchain-stable hash" -- crates/outline-transport/src/fingerprint_profile.rs crates/outline-transport/src/tests/fingerprint_profile.rs
```

---

### Task 2: Веса профилей и взвешенный `pick`

**Files:**
- Modify: `crates/outline-transport/src/fingerprint_profile.rs` (`struct Profile` ~189, каждая запись `PROFILES` ~233–339, `pick` ~555)
- Test: `crates/outline-transport/src/tests/fingerprint_profile.rs`

**Interfaces:**
- Consumes: `pick(os, seed: u64)`, `stable_seed` из задачи 1.
- Produces: поле `Profile::weight: u32`; `pick` выбирает по весам.

- [ ] **Step 1: Падающие тесты**

```rust
#[test]
fn profile_weights_match_the_decided_shares() {
    let w = |n| by_name(n).weight;
    assert_eq!((w("chrome-157-linux"), w("firefox-159-linux")), (70, 30));
    assert_eq!(
        (w("chrome-157-macos"), w("safari-27-macos"), w("firefox-159-macos")),
        (60, 30, 10)
    );
    assert_eq!(w("chrome-157-android"), 100);
    assert!(PROFILES.iter().all(|p| p.weight > 0), "a zero weight is a dead profile");
}

#[test]
fn weighted_pick_tracks_the_weights() {
    // 100k synthetic hostnames through the real seed: each share must land
    // within 1.5 points of its weight.
    for os in ALL_OS {
        let total: u32 = pool_for(os).map(|p| p.weight).sum();
        let mut hits = std::collections::HashMap::<&str, u32>::new();
        const N: u32 = 100_000;
        for i in 0..N {
            let seed = stable_seed(format!("host-{i}").as_bytes());
            *hits.entry(crate::fingerprint_profile::pick(os, seed).name).or_default() += 1;
        }
        for p in pool_for(os) {
            let got = f64::from(*hits.get(p.name).unwrap_or(&0)) / f64::from(N);
            let want = f64::from(p.weight) / f64::from(total);
            assert!((got - want).abs() < 0.015, "{}: got {got:.3}, want {want:.3}", p.name);
        }
    }
}

#[test]
fn weighted_pick_maps_seed_edges_to_pool_edges() {
    use crate::fingerprint_profile::pick;
    assert_eq!(pick(ProfileOs::Linux, 0).name, "chrome-157-linux");
    assert_eq!(pick(ProfileOs::Linux, u64::MAX).name, "firefox-159-linux");
    // 0.70 * 2^64 is the Chrome/Firefox boundary on Linux.
    let boundary = (u128::from(u64::MAX) * 70 / 100) as u64;
    assert_eq!(pick(ProfileOs::Linux, boundary - (1 << 20)).name, "chrome-157-linux");
    assert_eq!(pick(ProfileOs::Linux, boundary + (1 << 20)).name, "firefox-159-linux");
}

#[test]
fn current_fleet_hostnames_split_between_chrome_and_firefox() {
    // Recorded rollout expectation (plan 2026-11-04): changing seed or weights
    // re-rolls the fleet; update together with the plan's table.
    use crate::fingerprint_profile::pick;
    let at = |h: &str| pick(ProfileOs::Linux, stable_seed(h.as_bytes())).name;
    assert_eq!(at("NanoPi-NEO3-Plus"), "firefox-159-linux");
    assert_eq!(at("Beelink-T4-Pro"), "firefox-159-linux");
    assert_eq!(at("cloud1.beerloga.su"), "chrome-157-linux");
    assert_eq!(at("cloud2.beerloga.su"), "chrome-157-linux");
}
```

`pick` сделать `pub(crate)`, чтобы тесты его видели.

- [ ] **Step 2: Убедиться, что падают**

Run: `cargo test -p outline-transport --lib fingerprint_profile 2>&1 | tail -20`
Expected: ошибка компиляции — у `Profile` нет поля `weight`.

- [ ] **Step 3: Реализация**

В `struct Profile` после `os`:

```rust
    /// Relative share of this identity inside its OS pool ([`pool_for`]),
    /// roughly the browser's real desktop/mobile share on that OS, so a
    /// large fleet looks like a plausible browser mix. Must be > 0.
    pub weight: u32,
```

В `PROFILES` после каждого `os: ...,`: `chrome-157-macos` → `weight: 60,`; `chrome-157-linux` → `weight: 70,`; `chrome-157-android` → `weight: 100,`; `firefox-159-macos` → `weight: 10,`; `firefox-159-linux` → `weight: 30,`; `safari-27-macos` → `weight: 30,`.

`pick` целиком:

```rust
/// Weighted pick from the `os` pool. The seed is mapped onto `[0, total)` by
/// multiply-shift — it reads the seed's high bits and has no modulo bias —
/// then walks the cumulative weights.
pub(crate) fn pick(os: ProfileOs, seed: u64) -> &'static Profile {
    let total: u64 = pool_for(os).map(|p| u64::from(p.weight)).sum();
    assert!(total > 0, "every OS has a non-empty, positively weighted pool");
    let mut x = ((u128::from(seed) * u128::from(total)) >> 64) as u64;
    for profile in pool_for(os) {
        let w = u64::from(profile.weight);
        if x < w {
            return profile;
        }
        x -= w;
    }
    unreachable!("x < total by construction")
}
```

Поправить doc-комментарий модуля (строки 14–16) и `PROFILES` (~230): выбор — взвешенный, веса в поле `weight`.

- [ ] **Step 4: Тесты проходят**

Run: `cargo test -p outline-transport --lib fingerprint_profile 2>&1 | tail -5`
Expected: `test result: ok`.

Run: `cargo test -p outline-uplink 2>&1 | grep -E "test result|FAILED|panicked" | head`
Expected: все `test result: ok` (тесты snapshot `fingerprint_profile_name` опираются на `select_with_strategy`, не на конкретный профиль; если какой-то тест жёстко ждал имя профиля — заменить ожидание на `select_with_strategy(..)` того же URL, а не на новую константу).

- [ ] **Step 5: Коммит (после команды владельца)**

```bash
git commit -m "feat(fingerprint): pick the browser profile by per-OS market-share weights" -- crates/outline-transport/src/fingerprint_profile.rs crates/outline-transport/src/tests/fingerprint_profile.rs
```

---

### Task 3: Закрепление профиля в `outline-transport`

**Files:**
- Modify: `crates/outline-transport/src/fingerprint_profile.rs` (рядом с `init_strategy` ~343 и `select_with_strategy_for_os` ~578)
- Modify: `crates/outline-transport/src/lib.rs:330-334` (реэкспорт)
- Test: `crates/outline-transport/src/tests/fingerprint_profile.rs`

**Interfaces:**
- Consumes: `pick`, `process_seed` из задач 1–2.
- Produces:
  - `pub fn resolve_pin(browser: &str) -> anyhow::Result<&'static Profile>` — профиль браузера (`chrome` / `firefox` / `safari`) из пула `host_os()`; ошибка при неизвестном браузере или браузере, которого нет в пуле ОС.
  - `pub fn init_pinned_profile(profile: &'static Profile)` — первый вызов выигрывает.
  - реэкспорт в `lib.rs`: `resolve_pin as resolve_fingerprint_profile_pin`, `init_pinned_profile as init_fingerprint_profile_pin`.

- [ ] **Step 1: Падающие тесты**

В `use crate::fingerprint_profile::{...}` добавить `resolve_pin_for_os, select_pinned_for_os`:

```rust
#[test]
fn resolve_pin_maps_a_browser_to_its_profile_in_the_os_pool() {
    let linux = |b| resolve_pin_for_os(b, ProfileOs::Linux).unwrap().name;
    assert_eq!(linux("firefox"), "firefox-159-linux");
    // Case and surrounding whitespace are tolerated, like the strategy key.
    assert_eq!(linux(" Chrome "), "chrome-157-linux");
    assert_eq!(resolve_pin_for_os("safari", ProfileOs::MacOs).unwrap().name, "safari-27-macos");
    assert_eq!(resolve_pin_for_os("chrome", ProfileOs::Android).unwrap().name, "chrome-157-android");
}

#[test]
fn resolve_pin_rejects_versioned_names_unknown_browsers_and_foreign_os() {
    // A versioned name would stop resolving at the next PROFILES refresh.
    let err = resolve_pin_for_os("chrome-157-linux", ProfileOs::Linux).unwrap_err().to_string();
    assert!(err.contains("chrome, firefox or safari"), "{err}");
    let err = resolve_pin_for_os("edge", ProfileOs::Linux).unwrap_err().to_string();
    assert!(err.contains("chrome, firefox or safari"), "{err}");
    let err = resolve_pin_for_os("safari", ProfileOs::Linux).unwrap_err().to_string();
    assert!(err.contains("chrome") && err.contains("firefox"), "lists what Linux offers: {err}");
    assert!(resolve_pin_for_os("firefox", ProfileOs::Android).is_err());
}

#[test]
fn each_os_pool_has_at_most_one_profile_per_browser() {
    // Pinning by browser relies on this: two Chrome profiles in one pool
    // would make `fingerprint_profile_pin = "chrome"` ambiguous.
    for os in ALL_OS {
        let mut seen = std::collections::HashSet::new();
        for p in pool_for(os) {
            assert!(seen.insert(p.tls), "{os:?}: second {:?} profile {}", p.tls, p.name);
        }
    }
}

#[test]
fn pin_overrides_only_process_stable() {
    let pin = by_name("chrome-157-linux");
    let url = Url::parse("wss://pinned.test/").unwrap();
    let os = ProfileOs::Linux;
    assert_eq!(select_pinned_for_os(&url, Strategy::ProcessStable, os, Some(pin)).unwrap().name, pin.name);
    assert!(select_pinned_for_os(&url, Strategy::None, os, Some(pin)).is_none());
    // per_host_stable keeps hashing the host, whatever the pin says.
    assert_eq!(
        select_pinned_for_os(&url, Strategy::PerHostStable, os, Some(pin)).unwrap().name,
        select_with_strategy_for_os(&url, Strategy::PerHostStable, os).unwrap().name,
    );
}

#[test]
fn pin_of_another_os_is_ignored() {
    let pin = by_name("safari-27-macos");
    let url = Url::parse("wss://pinned.test/").unwrap();
    let p = select_pinned_for_os(&url, Strategy::ProcessStable, ProfileOs::Linux, Some(pin)).unwrap();
    assert_eq!(p.os, ProfileOs::Linux);
}
```

- [ ] **Step 2: Убедиться, что падают**

Run: `cargo test -p outline-transport --lib fingerprint_profile 2>&1 | tail -20`
Expected: ошибка компиляции — `resolve_pin_for_os`, `select_pinned_for_os` не найдены.

- [ ] **Step 3: Реализация**

После `current_strategy`:

```rust
static PINNED: OnceLock<&'static Profile> = OnceLock::new();

/// Pin the profile [`Strategy::ProcessStable`] returns, instead of the
/// hostname-seeded weighted pick. First call wins, like [`init_strategy`].
/// Resolve the name with [`resolve_pin`] first.
pub fn init_pinned_profile(profile: &'static Profile) {
    let _ = PINNED.set(profile);
}

/// Config spelling of a browser family in `fingerprint_profile_pin`.
const fn browser_label(tls: TlsFingerprint) -> &'static str {
    match tls {
        TlsFingerprint::Chromium => "chrome",
        TlsFingerprint::Firefox => "firefox",
        TlsFingerprint::Safari => "safari",
    }
}

/// Resolves the `fingerprint_profile_pin` value — a browser without a version
/// (`chrome` / `firefox` / `safari`) — to that browser's profile in the pool of
/// the OS this binary runs on. Versionless on purpose: profile names carry the
/// browser major and change at every `PROFILES` refresh, and a pin that stops
/// resolving would keep the client from starting after an upgrade.
pub fn resolve_pin(browser: &str) -> Result<&'static Profile> {
    resolve_pin_for_os(browser, host_os())
}

/// [`resolve_pin`] for an explicit OS (tests cover every pool from one host).
pub fn resolve_pin_for_os(browser: &str, os: ProfileOs) -> Result<&'static Profile> {
    let wanted = browser.trim().to_ascii_lowercase();
    let tls = match wanted.as_str() {
        "chrome" => TlsFingerprint::Chromium,
        "firefox" => TlsFingerprint::Firefox,
        "safari" => TlsFingerprint::Safari,
        _ => bail!("unknown browser {wanted:?}; expected chrome, firefox or safari (no version)"),
    };
    let Some(profile) = pool_for(os).find(|p| p.tls == tls) else {
        let offered: Vec<_> = pool_for(os).map(|p| browser_label(p.tls)).collect();
        bail!("no {wanted} profile for {os:?}; this OS offers: {}", offered.join(", "));
    };
    Ok(profile)
}
```

Заменить тело `select_with_strategy_for_os` на делегирование и добавить `select_pinned_for_os`:

```rust
pub fn select_with_strategy_for_os(
    url: &Url,
    strategy: Strategy,
    os: ProfileOs,
) -> Option<&'static Profile> {
    select_pinned_for_os(url, strategy, os, PINNED.get().copied())
}

/// [`select_with_strategy_for_os`] with an explicit pin, so tests do not have
/// to set the process-wide `OnceLock`. A pin of another OS is ignored: the
/// per-OS rule beats the operator's override.
pub fn select_pinned_for_os(
    url: &Url,
    strategy: Strategy,
    os: ProfileOs,
    pin: Option<&'static Profile>,
) -> Option<&'static Profile> {
    match strategy {
        Strategy::None => None,
        Strategy::PerHostStable => Some(pick(os, host_seed(url))),
        Strategy::ProcessStable => Some(match pin {
            Some(p) if p.os == os => p,
            _ => pick(os, process_seed()),
        }),
        Strategy::Random => Some(pick(os, rand::random::<u64>())),
    }
}
```

В `crates/outline-transport/src/lib.rs` в блок `pub use fingerprint_profile::{...}` (строка ~330) добавить:

```rust
    init_pinned_profile as init_fingerprint_profile_pin,
    resolve_pin as resolve_fingerprint_profile_pin,
```

Snapshot (`crates/outline-uplink/src/manager/snapshot.rs:573`) ходит через `select_with_strategy` → закрепление автоматически видно в `fingerprint_profile_name` дашборда, правка там не нужна.

- [ ] **Step 4: Тесты проходят**

Run: `cargo test -p outline-transport --lib fingerprint_profile 2>&1 | tail -5`
Expected: `test result: ok`.

- [ ] **Step 5: Коммит (после команды владельца)**

```bash
git commit -m "feat(fingerprint): let the operator pin the process-stable profile" -- crates/outline-transport/src/fingerprint_profile.rs crates/outline-transport/src/tests/fingerprint_profile.rs crates/outline-transport/src/lib.rs
```

---

### Task 4: Ключ `fingerprint_profile_pin` в конфиге ws-rust

**Files:**
- Modify: `bins/outline-ws-rust/src/config/schema.rs:108` (рядом с `fingerprint_profile` в `ConfigFile`)
- Modify: `bins/outline-ws-rust/src/config/types.rs:62` (`AppConfig`)
- Modify: `bins/outline-ws-rust/src/config/load/mod.rs:137-178`
- Modify: `bins/outline-ws-rust/src/bootstrap/mod.rs:129`
- Test: `bins/outline-ws-rust/src/config/tests/mod.rs`

**Interfaces:**
- Consumes: `outline_transport::resolve_fingerprint_profile_pin`, `outline_transport::init_fingerprint_profile_pin` из задачи 3.
- Produces: `AppConfig::fingerprint_profile_pin: Option<&'static outline_transport::fingerprint_profile::Profile>`.

- [ ] **Step 1: Падающие тесты**

В `bins/outline-ws-rust/src/config/tests/mod.rs` рядом с `load_config_defaults_fingerprint_profile_to_none_when_missing`:

```rust
async fn load_with_top_level(extra: &str) -> anyhow::Result<super::AppConfig> {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.toml");
    std::fs::write(
        &path,
        format!(
            r#"
            tcp_ws_url = "wss://example.com/secret/tcp"
            method = "chacha20-ietf-poly1305"
            password = "Secret0"
            fingerprint_profile = "stable"
            {extra}

            [socks5]
            listen = "127.0.0.1:1080"
            "#
        ),
    )
    .unwrap();
    let args = super::Args::parse_from(["test"]);
    load_config(&path, &args).await
}

#[tokio::test]
async fn load_config_resolves_fingerprint_profile_pin_for_the_host_os() {
    // Chrome is in every OS pool, so this holds on macOS and Linux runners.
    let config = load_with_top_level("fingerprint_profile_pin = \"chrome\"").await.unwrap();
    let pin = config.fingerprint_profile_pin.expect("pin resolved");
    assert_eq!(pin.tls, outline_transport::fingerprint_profile::TlsFingerprint::Chromium);
    assert_eq!(pin.os, outline_transport::fingerprint_profile::host_os());
}

#[tokio::test]
async fn load_config_rejects_a_versioned_fingerprint_profile_pin() {
    // Versioned names would break at the next profile refresh; only the browser is accepted.
    let err = load_with_top_level("fingerprint_profile_pin = \"chrome-157-linux\"").await.unwrap_err();
    assert!(format!("{err:#}").contains("chrome, firefox or safari"), "{err:#}");
}

#[tokio::test]
async fn load_config_leaves_fingerprint_profile_pin_unset_by_default() {
    let config = load_with_top_level("").await.unwrap();
    assert!(config.fingerprint_profile_pin.is_none());
}

#[tokio::test]
async fn load_config_rejects_unknown_fingerprint_profile_pin() {
    let err = load_with_top_level("fingerprint_profile_pin = \"edge\"").await.unwrap_err();
    assert!(format!("{err:#}").contains("fingerprint_profile_pin"), "{err:#}");
}
```

Если `super::AppConfig` в этом модуле не виден под таким путём — импортировать тем же путём, что использует `load_config` (`use super::{..., AppConfig}`), а не дублировать тип.

- [ ] **Step 2: Убедиться, что падают**

Run: `cargo test -p outline-ws-rust --lib config::tests::load_config_ 2>&1 | tail -20`
Expected: ошибка компиляции — у `AppConfig` нет поля `fingerprint_profile_pin`.

- [ ] **Step 3: Реализация**

`schema.rs`, после `fingerprint_profile` в `ConfigFile`:

```rust
    /// Browser `process_stable` must use on this node instead of the
    /// hostname-seeded weighted pick: `"chrome"`, `"firefox"` or `"safari"`,
    /// without a version, so a profile refresh never invalidates the config.
    /// The browser must be in the pool of the OS the client runs on.
    /// Ignored by other strategies.
    pub(super) fingerprint_profile_pin: Option<String>,
```

`types.rs`, после `fingerprint_profile`:

```rust
    /// Operator-pinned `process_stable` profile (`fingerprint_profile_pin`),
    /// already resolved against the host OS at load time.
    pub fingerprint_profile_pin: Option<&'static outline_transport::fingerprint_profile::Profile>,
```

`load/mod.rs`, после вычисления `fingerprint_profile`:

```rust
    // Resolved here, not in bootstrap, so a typo or a foreign-OS profile
    // fails the config load with the list of selectable names.
    let fingerprint_profile_pin = file
        .as_ref()
        .and_then(|f| f.fingerprint_profile_pin.as_deref())
        .map(outline_transport::resolve_fingerprint_profile_pin)
        .transpose()
        .context("invalid fingerprint_profile_pin")?;
```

и `fingerprint_profile_pin,` в литерал `AppConfig { ... }` рядом с `fingerprint_profile,`.

`bootstrap/mod.rs`, сразу после `init_fingerprint_profile_strategy(...)`:

```rust
    if let Some(profile) = config.fingerprint_profile_pin {
        outline_transport::init_fingerprint_profile_pin(profile);
        tracing::info!(profile = profile.name, "fingerprint profile pinned for process_stable");
    }
```

Если компилятор укажет другие литералы `AppConfig { .. }` (тесты, `control`), добавить в них `fingerprint_profile_pin: None`.

- [ ] **Step 4: Тесты проходят**

Run: `cargo test -p outline-ws-rust --lib config:: 2>&1 | tail -5`
Expected: `test result: ok`.

- [ ] **Step 5: Коммит (после команды владельца)**

```bash
git commit -m "feat(ws-rust): add the fingerprint_profile_pin config key" -- bins/outline-ws-rust/src/config/schema.rs bins/outline-ws-rust/src/config/types.rs bins/outline-ws-rust/src/config/load/mod.rs bins/outline-ws-rust/src/bootstrap/mod.rs bins/outline-ws-rust/src/config/tests/mod.rs
```

---

### Task 5: Документация EN/RU

**Files:**
- Modify: `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md` (раздел `## Browser fingerprint diversification`, ~1832–2010) и `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.ru.md` (тот же раздел)
- Modify: `bins/outline-ws-rust/CHANGELOG.md`, `bins/outline-ws-rust/CHANGELOG.ru.md` (секция Unreleased)

- [ ] **Step 1: EN-раздел.** После описания `process_stable` добавить подраздел `### Weighted pick and pinning`:

```markdown
### Weighted pick and pinning

The profile is drawn from the pool of the OS the client runs on with
per-browser weights close to the real browser mix: Linux — Chrome 70,
Firefox 30; macOS — Chrome 60, Safari 30, Firefox 10; Android — Chrome.
The seed (hostname for `process_stable`, `host:port` for `per_host_stable`)
goes through FNV-1a + splitmix64, so the choice does not change across Rust
toolchain upgrades.

Weights describe the odds of one node, not the split of a small fleet: four
Linux nodes all land on Chrome with probability ≈ 0.24. To fix a node's
identity, pin the browser:

```toml
fingerprint_profile = "stable"
fingerprint_profile_pin = "chrome"   # chrome | firefox | safari
```

The value is a browser without a version: the client uses that browser's
current profile from its OS pool (on Linux today `chrome-157-linux`), so a
profile refresh in a new release does not touch the config. Versioned names
(`chrome-157-linux`) are rejected. The pin applies wherever the effective
strategy is `process_stable`; other strategies ignore it. A browser missing
from the OS pool (`safari` on Linux, `firefox` on Android) or an unknown value
fails the config load. Older binaries reject the key
(`deny_unknown_fields`): deploy the binary first, then add the key.
```

- [ ] **Step 2: RU-раздел.** В `.ru.md` тот же подраздел `### Взвешенный выбор и закрепление`:

```markdown
### Взвешенный выбор и закрепление

Профиль берётся из пула ОС, на которой работает клиент, с весами, близкими к
реальной доле браузеров: Linux — Chrome 70, Firefox 30; macOS — Chrome 60,
Safari 30, Firefox 10; Android — Chrome. Сид (hostname для `process_stable`,
`host:port` для `per_host_stable`) считается через FNV-1a + splitmix64,
поэтому выбор не меняется при обновлении тулчейна Rust.

Веса задают шансы одного узла, а не раскладку маленького парка: четыре
Linux-узла все попадут на Chrome с вероятностью ≈ 0.24. Чтобы зафиксировать
профиль узла, закрепите браузер:

```toml
fingerprint_profile = "stable"
fingerprint_profile_pin = "chrome"   # chrome | firefox | safari
```

Значение — браузер без версии: клиент берёт текущий профиль этого браузера
из пула своей ОС (сейчас на Linux это `chrome-157-linux`), поэтому обновление
профилей в новом релизе конфиг не затрагивает. Имена с версией
(`chrome-157-linux`) не принимаются. Закрепление действует везде, где
эффективная стратегия — `process_stable`; остальные стратегии его игнорируют.
Браузер, которого нет в пуле ОС (`safari` на Linux, `firefox` на Android), или
неизвестное значение — ошибка загрузки конфига. Старые бинари ключ не знают
(`deny_unknown_fields`): сначала выкладывается бинарь, потом добавляется ключ.
```

- [ ] **Step 3: CHANGELOG.** В Unreleased обеих версий:
  - EN: `- Fingerprint profiles are picked by per-OS browser-share weights with a toolchain-stable seed (FNV-1a + splitmix64); new key `fingerprint_profile_pin = "chrome" | "firefox" | "safari"` pins the process-stable browser (no version, survives profile refreshes). On upgrade some nodes switch browser identity once.`
  - RU: `- Профиль отпечатка выбирается по весам доли браузеров в пуле ОС, сид стабилен между версиями Rust (FNV-1a + splitmix64); новый ключ `fingerprint_profile_pin = "chrome" | "firefox" | "safari"` закрепляет браузер для process_stable (без версии, переживает обновление профилей). При обновлении часть узлов один раз сменит браузерную идентичность.`

- [ ] **Step 4: Проверить паритет.** Run: `grep -c "fingerprint_profile_pin" bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.ru.md bins/outline-ws-rust/CHANGELOG.md bins/outline-ws-rust/CHANGELOG.ru.md`
Expected: одинаковое ненулевое число в паре docs и в паре CHANGELOG.

- [ ] **Step 5: Коммит (после команды владельца)**

```bash
git commit -m "docs(ws-rust): document weighted fingerprint pick and fingerprint_profile_pin" -- bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.ru.md bins/outline-ws-rust/CHANGELOG.md bins/outline-ws-rust/CHANGELOG.ru.md
```

---

### Task 6: CI-гейт локально

- [ ] **Step 1:** весь гейт из `AGENTS.md` в этом порядке:

```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui -p outline-metrics -p outline-net -p outline-routing -p outline-transport -p outline-tun -p outline-uplink -p outline-wire -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --all-targets --no-deps -- -D warnings
cargo test --workspace --exclude sockudo-ws
cargo check -p outline-ws-rust --no-default-features
(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
```

Expected: всё зелёное. `android/rust` тянет `outline-transport` по path —
новое поле `Profile::weight` его не ломает, но проверить обязательно.

- [ ] **Step 2:** linux-тест в docker (на macOS `host_os()` = MacOs, и
  `load_config_resolves_fingerprint_profile_pin_for_the_host_os` гоняет
  macOS-ветку): по методике [[repro-linux-ci-failure-in-docker]] прогнать
  `cargo test -p outline-transport --lib fingerprint_profile` и
  `cargo test -p outline-ws-rust --lib config::` в linux-контейнере.

- [ ] **Step 3:** после пуша (по команде) — `gh run list --limit 3` и
  `gh run watch`, все три job'а CI зелёные.

---

### Task 7: Выкладка на парк (по одному узлу, с согласия владельца)

Порядок: cloud2 → cloud1 → .102 → .104. Каждый узел — `ops/deploy/deploy-binary.sh`
(бэкап + автооткат), рестарт только после явного «да» владельца.

- [ ] **Step 1:** на узле после рестарта:

```bash
sudo journalctl -u outline-ws-rust --since "-5 min" | grep -m3 "fingerprint profile bound to host"
```

Expected: cloud1/cloud2 — `profile=chrome-157-linux`; .102/.104 —
`profile=firefox-159-linux` (как в таблице выше).

- [ ] **Step 2:** проверить, что UI показывает тот же профиль (`fingerprint_profile_name` в `/control/topology`).

- [ ] **Step 3:** закрепление пока НЕ включать: раскладка 2/2 и так получилась.
  Ключ `fingerprint_profile_pin` добавлять только если владелец захочет другую.

- [ ] **Step 4:** мак-клиент владельца: после обновления посмотреть строку лога
  `fingerprint profile bound to host` и сообщить, сменился ли профиль.

## Откат

Откат бинаря через `deploy-binary.sh` возвращает старый выбор (`DefaultHasher`,
равные доли). Если на узле успели добавить `fingerprint_profile_pin`, его нужно
убрать ДО отката: старый бинарь с этим ключом не стартует.
