# Спецификация: Egress-маркировка `dscp` наряду с `fwmark` и vendored-патч `quinn-udp`

Дата: 2026-11-22
Статус: задание для отдельной сессии реализации

---

## 1. Контекст и мотивация

При переносе шлюзовой связки (`outline-client` + `ocserv` + WireGuard) в Kubernetes (`k3s` с Flannel/CNI, `hostNetwork: false`) возникает проблема разделения исходящего трафика между двумя провайдерами (`ISP1` и `ISP2`) из одного процесса `outline-client` (включая ночной `reselect_at` и `direct`-трафик):

1. В текущем Linux-варианте на голых хостах для выбора резервного/второго провайдера используется `fwmark` (`SO_MARK = 18` на аплинках и `direct_fwmark = 18` для прямых соединений), который перенаправляется в таблицу маршрутизации второго провайдера (`table 1018`, VLAN 3).
2. При запуске `outline-client` внутри обычного пода (`hostNetwork: false`) ядро Linux **обнуляет `skb->mark` при выходе пакета из `netns` пода через `veth` в `cni0`**. Поэтому хостовое правило `ip rule fwmark 18 lookup 1018` перестаёт работать, а под без `hostNetwork: true` или `Multus` не может направлять разные аплинки и `direct`-трафик через разных провайдеров.
3. **Решение на уровне IP-заголовка — DSCP (Differentiated Services Code Point, старшие 6 бит поля TOS/Traffic Class):** в отличие от `skb->mark`, биты DSCP живут в самом IPv4/IPv6-заголовке и **переживают границу `netns`** (`veth` → `cni0`). Хостовый `nftables` на входе `cni0` переводит специальное значение DSCP обратно в хостовый `fwmark` и сразу обнуляет DSCP до выхода пакета наружу.

### Референсная хостовая схема (`nftables` на ноде k3s)

Чтобы не происходил случайный захват чужого трафика и не менялся внешний сетевой отпечаток (fingerprint) на DPI/NAT:

- **Не использовать стандартные классы** вроде `18` (`0x12`, `AF21` — дефолт OpenSSH `IPQoS af21 cs1`), `46` (`EF`) или `CS1..CS7`.
- **Выбирать значение из RFC 2474 Pool 2 (`xxxx11`, локальное/экспериментальное)**, например `59` (`0x3b`) или `63` (`0x3f`).
- **Тройная изоляция в `nftables` и обязательный сброс DSCP в `cs0` (`0`) до выхода на провайдера:**

```nft
table inet k3s_egress_mark {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        # 1. Только трафик из pod-сети (отсекает трафик самого хоста и входящие с WAN)
        # 2. Только внешний трафик (не задевает LAN, Service CIDR и pod-to-pod)
        # 3. Перекладываем локальный DSCP 0x3b в хостовый fwmark 0x12 и СРАЗУ сбрасываем DSCP в 0
        iifname "cni0" ip daddr != { 10.0.0.0/8, 198.51.100.0/24, 192.168.0.0/16 } ip dscp 0x3b \
            meta mark set (meta mark | 0x12) ip dscp set cs0
        iifname "cni0" ip6 daddr != { fc00::/7, fe80::/10 } ip6 dscp 0x3b \
            meta mark set (meta mark | 0x12) ip6 dscp set cs0
    }
}
```

*(Домашняя подсеть и локальные исключения в реальном окружении подставляются из `FLEET.local.md`; также на хосте для VLAN 3 используется `ip rule fwmark 0x12/0x00ff lookup 1018`, чтобы не конфликтовать с битами `0x4000`/`0x8000` у `kube-proxy`.)*

Такой подход сохраняет `hostNetwork: false` (свободную миграцию пода, отсутствие `CAP_NET_ADMIN` ради `SO_MARK` и отсутствие `Multus CNI`) при полном сохранении ночного `reselect_at` и `direct`-выхода через второго провайдера.

---

## 2. Область задачи (Scope)

### Обязательная часть (P0)

1. **Vendored-патч `vendor/quinn-udp` (`0.5.16`)**: сохранение DSCP в `cmsg` при `sendmsg`/`sendmsg_x` для всех QUIC/HTTP3-носителей (`xhttp_h3`, `ws_h3`).
2. **Сокетный слой (`crates/outline-net`)**: установка `IP_TOS` / `IPV6_TCLASS` на TCP (до `connect()`) и UDP (при `bind()`) рядом с `fwmark`, с поддержкой dual-stack IPv6 (`set_only_v6(false)`).
3. **Транспорт и кэши/пулы (`crates/outline-transport`)**: проброс `dscp` в `DialNetworkOptions`, включение `dscp` во все ключи кэшей и пулов носителей (`ConnectionKey`, `H2ConnectionKey`, H3 carrier slot picker, `PmtuKey::for_dial`) и `cert_check`.
4. **Аплинки и пробы (`crates/outline-uplink`)**: `dscp: Option<u8>` в `UplinkConfig`, `FallbackTransport`, `WireSpec`, `StandbyCtx`, `ProbeEndpoint`, `cert_check`.
5. **TUN-маршрутизация (`crates/outline-tun`)**: `direct_dscp: Option<u8>` и `TunRoute::Direct { fwmark, dscp }`.
6. **Конфигурация, CLI, прокси и Control API (`bins/outline-client`)**:
   - поля `dscp` (`[outline]`, `[[outline.uplinks]]`, `[[outline.uplinks.fallbacks]]`, CLI `--dscp`) и `direct_dscp` (верхний уровень конфига);
   - строгая валидация `0..=63`;
   - наследование (fallback → uplink → `[outline]` → CLI), идентичное `fwmark`;
   - обновление предупреждений `ipsec_bypass` / `bypass_when_down` в `bootstrap/mod.rs`;
   - полная поддержка в Control API (`/control/config`, `/control/uplinks`, `/control/apply`).
7. **Web UI (`bins/outline-ui/frontend`)**: отображение и редактирование `direct_dscp` и per-uplink / per-fallback `dscp` во вкладках `/ws/*` и фикстурах тестов.
8. **Тесты (включая реальный Linux loopback QUIC cmsg-тест в Docker)**, проверка `android/rust` и полный CI-гейт.
9. **Двуязычная документация (EN + RU)**: `PATCHES.md`/`PATCHES.ru.md`, `AGENTS.md`, `README.md`/`README.ru.md`, `bins/outline-client/README.md`/`bins/outline-client/README.ru.md`, `CHANGELOG.md`/`CHANGELOG.ru.md`.

### Вне области P0 / отдельная фаза (P1)

- Per-user `dscp` в `bins/outline-server` (рядом с `bins/outline-server/src/fwmark.rs`, `config/user_entry.rs`, `server/nat/table.rs`, `server/transport/*`, `/ss` в `outline-ui`) **не входит в P0**, чтобы не усложнять первую итерацию. Для серверных задач достаточно P0 на стороне клиента; при желании серверную сторону вынести в отдельную спецификацию после приёмки P0.

---

## 3. Техническое обоснование и дизайн vendored-патча `vendor/quinn-udp` (`0.5.16`)

### Почему без патча QUIC/HTTP3 теряет DSCP

В текущем `Cargo.lock` и `android/rust/Cargo.lock` используется `quinn-udp 0.5.16`. В файле `src/unix.rs` (`prepare_msg`, строки ~614–624) при **каждом** `sendmsg` в `cmsg` принудительно пишется `IP_TOS` (для IPv4 и IPv4-mapped IPv6) или `IPV6_TCLASS` (для IPv6):

```rust
let ecn = transmit.ecn.map_or(0, |x| x as libc::c_int);
if is_ipv4 {
    if !sendmsg_einval {
        encoder.push(libc::IPPROTO_IP, libc::IP_TOS, ecn as IpTosTy);
    }
} else {
    encoder.push(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, ecn);
}
```

На Linux (и ряде других Unix-ядер) передача `IP_TOS` / `IPV6_TCLASS` в ancillary data `sendmsg` **полностью переопределяет значение, выставленное через `setsockopt(IP_TOS / IPV6_TCLASS)`** на время этого вызова. Поскольку `ecn` имеет диапазон `0..=3`, старшие 6 бит DSCP зануляются в каждом исходящем QUIC-пакете, даже если на сокете вызван `setsockopt(IP_TOS)`.

### Почему вендорится только `quinn-udp`, а не `quinn`

В `quinn 0.11.11` (`src/runtime/tokio.rs:30–35`) метод `TokioRuntime::wrap_udp_socket` создаёт `quinn_udp::UdpSocketState::new((&sock).into())` напрямую из переданного `std::net::UdpSocket`. Никакой отдельной обёртки и форка `quinn` или изменения публичного API `quinn-udp` не требуется — достаточно, чтобы `quinn_udp::UdpSocketState` автоматически считывал сокетный DSCP при создании состояния сокета и сохранял его во всех последующих `prepare_msg`.

### Детали патча `vendor/quinn-udp` (`0.5.16`)

1. **Поля состояния в `vendor/quinn-udp/src/unix.rs` (`UdpSocketState`):**
   - Добавить в `UdpSocketState`:
     - `dscp_v4: u8` — старшие 6 бит (`tos & 0xfc`), прочитанные с сокета `IPPROTO_IP / IP_TOS`;
     - `dscp_v6: u8` — старшие 6 бит (`tclass & 0xfc`), прочитанные с сокета `IPPROTO_IPV6 / IPV6_TCLASS`.
2. **Инициализация в `UdpSocketState::new(sock: UdpSockRef<'_>)`:**
   - Прочитать `getsockopt` **один раз** при инициализации (ноль оверхеда на hot-path `send`):
     - если `is_ipv4 || !io.only_v6()?` → прочитать `libc::IPPROTO_IP, libc::IP_TOS` и сохранить `(val as u8) & 0xfc` в `dscp_v4` (при ошибке `getsockopt` — `0`);
     - если `!is_ipv4` → прочитать `libc::IPPROTO_IPV6, libc::IPV6_TCLASS` и сохранить `(val as u8) & 0xfc` в `dscp_v6` (при ошибке `getsockopt` — `0`).
   - Обратить внимание на тип возврата `getsockopt` для `IP_TOS` / `IPV6_TCLASS` на разных Unix-платформах (на FreeBSD `IP_TOS` ожидает `IpTosTy` / `c_uchar` или `c_int`; считывать через `c_int` с проверкой `optlen` или платформенно-безопасным хелпером по аналогии с `set_socket_option` в том же файле `unix.rs`, поддерживая и `c_uchar`, и `c_int`).
3. **Кодирование в `prepare_msg(...)` и проброс во все ветки `send(...)`:**
   - Добавить параметры `dscp_v4: u8, dscp_v6: u8` в `prepare_msg(...)`.
   - Заменить вычисление значения для `cmsg`:
     ```rust
     let ecn = transmit.ecn.map_or(0, |x| x as libc::c_int);
     let tos_v4 = libc::c_int::from(dscp_v4) | ecn;
     let tclass_v6 = libc::c_int::from(dscp_v6) | ecn;
     ```
     и передавать `tos_v4 as IpTosTy` в `IP_TOS` и `tclass_v6` в `IPV6_TCLASS`.
   - Проверить **все** call-site'ы `prepare_msg` в `src/unix.rs`:
     - основная ветка `send()` (Linux/Android/FreeBSD, включая retry-вызов при `sendmsg_einval`);
     - ветка `#[cfg(apple_fast)]` (`sendmsg_x`);
     - ветка `#[cfg(any(target_os = "openbsd", target_os = "netbsd", apple_slow))]`.
4. **Windows (`src/windows.rs`):**
   - По аналогии изучить `src/windows.rs`: на старте `dscp` запрещён на не-Unix (как и `fwmark`), но сам код `windows.rs` не должен ломаться при сборке `outline-windows` на `x86_64-pc-windows-msvc`. Оставить `windows.rs` без изменений, если там ничего не мешает, либо описать это явно в `PATCHES*.md`.
5. **Инварианты патча:**
   - При отсутствии сокетного DSCP `dscp_v4 == 0` и `dscp_v6 == 0`, значит `0 | ecn == ecn` — поведение побайтово идентично upstream.
   - Биты ECN (`0x03`, `ECT(0)`, `ECT(1)`, `CE`) никогда не затираются маской `& 0xfc`.
   - При `sendmsg_einval` fallback'е `IP_TOS` cmsg не добавляется, и ядро само использует сокетный `IP_TOS` (уже содержащий `dscp << 2`).

### Монорепо-инварианты для нового vendored-крейта

1. Разместить копию upstream `quinn-udp 0.5.16` в `vendor/quinn-udp/`.
   - **Сохранить `build.rs`** (`vendor/quinn-udp/build.rs` настраивает `cfg_aliases` для `apple`, `apple_fast`, `apple_slow`, `bsd`, `solarish`, `wasm_browser` — без него сборка сломается!).
   - Выполнить обычный `vendoring-trim` по образцу других крейтов в `vendor/` (убрать `[dev-dependencies]`, `[[test]]`, `[[bench]]`, `tests/`, `benches/` из `vendor/quinn-udp/Cargo.toml` и каталога, чтобы workspace не тащил лишние dev-зависимости `criterion` и старый `tokio 1.28`). Проверить, какие runtime-зависимости остаются (`cfg-aliases` в `[build-dependencies]`, `libc`, `log`, `tracing`).
2. Подключить `[patch.crates-io]` **в обоих манифестах**:
   - Корневой [`Cargo.toml`](Cargo.toml): `quinn-udp = { path = "vendor/quinn-udp" }`.
   - Detached workspace [`android/rust/Cargo.toml`](android/rust/Cargo.toml): `quinn-udp = { path = "../../vendor/quinn-udp" }`.
   *(Не оставлять `android/rust` на crates.io `quinn-udp`, иначе и поведение на Android будет без патча, и `./scripts/audit-vendored.sh` разойдётся.)*
3. Сгенерировать diff-артефакт `quinn-udp-0.5.16.patch` в корне репозитория против чистого upstream `quinn-udp 0.5.16` (`src/` + `Cargo.toml`) и документировать в `PATCHES.md`, `PATCHES.ru.md`, `AGENTS.md`.
4. **Не запускать `cargo fmt` на `vendor/quinn-udp/*`**; в `.github/workflows/ci.yml` проверить, что `audit-vendored.sh` видит `quinn-udp` и проходит чисто.
5. Если в `quinn_udp` добавляются какие-либо новые публичные символы/методы (хотя при дизайне через `getsockopt` в `UdpSocketState::new` это не требуется), вызывать их строго через гейт `crates/outline-transport/src/quic/vendored.rs` с добавлением grep-инварианта в `.github/workflows/ci.yml`. Если публичный API `quinn-udp` не меняется (патч чисто поведенческий внутри `UdpSocketState::new` + `prepare_msg`), явно отразить это в `PATCHES.md`/`PATCHES.ru.md`.

---

## 4. Семантика `dscp` и карта изменений по крейтам

### 4.1. Тип, диапазон, порядок применения и совместимость с `fwmark`

- **Тип в конфигах и runtime:** `Option<u8>`.
- **Допустимый диапазон:** `0..=63` (6-битное значение DSCP, согласно RFC 2474). Любое значение `> 63` (например, `64`, `255`, отрицательные числа в TOML/JSON) **обязательно отклоняется** при парсинге/валидации конфигурации и в Control API (`400 Bad Request`).
  - *Важно:* `dscp = Some(0)` — валидное явное значение («выставить CS0 = 0», в отличие от `None` = «не трогать TOS/TCLASS»). При этом `dscp = Some(0)` на не-Unix должно проверяться консистентно с `is_some()`.
- **Преобразование в `setsockopt`:** `let tos: libc::c_int = i32::from(dscp) << 2;` (младшие 2 бита ECN остаются `0`; для `IP_TOS` на сокетах `quinn-udp` сама затем объединяет старшие 6 бит с per-packet ECN).
- **Независимость от `fwmark`:**
  - `fwmark` и `dscp` ортогональны: могут использоваться по отдельности (`fwmark` без `dscp`, `dscp` без `fwmark`) или вместе.
  - Проверить в коде: везде, где проверяется «можно ли идти быстрым путём без raw `socket2`», должно быть `fwmark.is_none() && dscp.is_none() && !prefer_public_raw_needed(addr)`.
  - Наличие `dscp` само по себе **не требует** `CAP_NET_ADMIN` и `PrivateUsers=no` (в отличие от `SO_MARK`), поэтому на Linux без `CAP_NET_ADMIN` сокеты с `dscp` обязаны успешно создаваться и отправлять трафик.
- **Платформенная поддержка:**
  - `#[cfg(unix)]` (Linux, Android, macOS, BSD): `IP_TOS` и `IPV6_TCLASS` работают без привилегий.
  - `#[cfg(not(unix))]` (Windows): `apply_dscp` при `Some(_)` возвращает явную ошибку (`"dscp is only supported on Unix"`).
  - На `#[cfg(unix)]`:
    - Для `Domain::IPV4`: `setsockopt(fd, libc::IPPROTO_IP, libc::IP_TOS, &tos, ...)`.
    - Для `Domain::IPV6`: `setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_TCLASS, &tos, ...)`. Если у сокета включён dual-stack (`!only_v6`, как в `bind_udp_socket` на `[::]:0`), дополнительно выставить **best-effort** `IPPROTO_IP / IP_TOS` (игнорируя возможный `ENOPROTOOPT` / `EINVAL` на ядрах, где это запрещено на AF_INET6, или применяя после `set_only_v6(false)`), потому что `quinn-udp` для IPv4-mapped `::ffff:a.b.c.d` адресов в `prepare_msg` шлёт `IPPROTO_IP / IP_TOS`!
  - **Порядок для TCP:** `apply_dscp` обязан вызываться **до `socket.connect(...)`**, чтобы уже первый `SYN`-пакет (и вся сессия в conntrack / на маршрутизаторе) уходил с нужным DSCP.

### 4.2. Рекомендация против `clippy::too_many_arguments`

Во избежание раздувания сигнатур (`connect_tcp_socket`, `bind_udp_socket`, `ConnectionKey::new`, `H2ConnectionKey::new`, `H3ConnectionKey::with_slot`, `pick_h3_carrier_slot`, `PmtuKey::for_dial`, `TunRoute::Direct` и т. д.) рекомендуется ввести в `outline-net` (и переиспользовать вверх по стеку или в паре с отдельными полями) компактную `Copy`-структуру, например:

```rust
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SocketMark {
    pub fwmark: Option<u32>,
    pub dscp: Option<u8>,
}
```

При желании низкоуровневые обёртки `outline_net` могут принимать `SocketMark` (либо оставить существующие публичные сигнатуры или обновить все внутренние вызовы в монорепо, что гарантирует отсутствие забытых мест).

### 4.3. Точная карта изменений по крейтам и файлам

#### 1. `crates/outline-net/src/lib.rs`
- Добавить валидирующую/применяющую функцию `apply_dscp(socket: &Socket, domain: Domain, dscp: Option<u8>, dual_stack_v6: bool) -> Result<()>` (или `apply_socket_marks` для `(fwmark, dscp)`).
- Каждый `unsafe` вызов `libc::setsockopt` снабдить конкретным комментарием `// SAFETY:` с точным инвариантом (требование `undocumented_unsafe_blocks = "warn"` + `-D warnings`).
- **Важно по `#[cfg]`:** сейчас `connect_tcp_socket_raw` и `prefer_public_raw_needed` разделены на `#[cfg(target_os = "linux")]` и `#[cfg(not(target_os = "linux"))]`. Поскольку `dscp` должен работать на любом `#[cfg(unix)]` (включая macOS для локальной отладки и Android), нужно разделить в `connect_tcp_socket_raw`:
  - `#[cfg(unix)]`: создание `Socket`, `apply_fwmark` (внутри сам проверяет `target_os = "linux"`), `apply_dscp` (до `connect`), IPv6 source binding (`target_os = "linux"`), non-blocking `connect` и `writable().await` + `take_error()` + `configure_tcp_stream_low_latency`.
  - `#[cfg(not(unix))]`: `bail!("fwmark and dscp are not supported on this platform")`.
- Обновить:
  - `connect_tcp_socket(addr, ...)` — быстрый путь только при `fwmark.is_none() && dscp.is_none() && !prefer_public_raw_needed(addr)`;
  - `connect_tcp_socket_direct(addr, ...)`;
  - `bind_udp_socket(bind_addr, ...)` — вызывать `apply_dscp` **после** `set_only_v6(false)` и **до** `bind()`;
  - `bind_udp_socket_direct(bind_addr, ...)`.

#### 2. `crates/outline-transport/src/`
- `dial_plan.rs`: добавить `pub dscp: Option<u8>` в `DialNetworkOptions` (и пробросить в `dial_plan` / `h2` / `h3` / `ws_h1` / `xhttp_h1` / `cert_check`).
- **КРИТИЧНО — изоляция ключей кэшей и пулов носителей:**
  - `shared_cache.rs`: добавить `pub(crate) dscp: Option<u8>` в `ConnectionKey` (`ConnectionKey::new`) — иначе два аплинка к одному серверу с разным DSCP переиспользуют одно TCP/TLS/QUIC соединение с чужим DSCP.
  - `h2/shared.rs`: прокинуть `dscp` в `H2ConnectionKey::new`, `connect_h2_connection`, `connect_tls_h2` и `connect_tcp_socket`.
  - `h3/shared.rs`: прокинуть `dscp` в `H3ConnectionKey::with_slot`, `pick_h3_carrier_slot`, `client_endpoint`, `bind_udp_socket` и `PmtuKey::for_dial`.
  - `quic/pmtu_cache.rs`: добавить `pub(crate) dscp: Option<u8>` в `PmtuKey`, учитывать его в `for_dial` (`local_source_ip` + `bind_udp_socket`) и в `PmtuKey::as_str()` (например, `|dscp=..`), так как разный DSCP после policy-routing уводит в разные пути (разный ISP / разный MTU!).
  - `cert_check.rs`: пробросить `dscp` в `connect_tcp_socket`.
- Проверить также `ws_h1` и `xhttp/h1.rs` (найти все вызовы `connect_tcp_socket` и `bind_udp_socket` в `crates/outline-transport/src/`), чтобы ни одна ветка не осталась без `dscp`.

#### 3. `crates/outline-uplink/src/`
- `config.rs`: добавить `pub dscp: Option<u8>` в `FallbackTransport` и `UplinkConfig`, прокинуть в `wire_view` / конструкторы / геттеры.
- `wire_spec.rs`: добавить `pub dscp: Option<u8>` в `WireSpec` (`WireSpec::from_uplink`, `WireSpec::from_fallback`, `WireSpec::of`).
- `manager/standby/ctx.rs` и `manager/standby/refill.rs`: добавить `pub(super) dscp: Option<u8>` в `StandbyCtx`, заполнять из `spec.dscp` и передавать в `DialNetworkOptions` при дозаправке пула.
- `manager/cert_check.rs`: прокинуть `ep.dscp` в `cert_check`.
- `probe/endpoint.rs`: добавить `pub(crate) dscp: Option<u8>` в `ProbeEndpoint`, дедупликацию и ключ пробы (разные `dscp` на одном `host:port` должны пробироваться независимо, как разные `fwmark`!), передавать в `connect_tcp_socket` и в `DialNetworkOptions`.
- `manager/wire_dial.rs` и остальные call-site'ы `DialNetworkOptions` в `outline-uplink`: пробросить `dscp`.

#### 4. `crates/outline-tun/src/`
- `routing.rs`:
  - добавить `direct_dscp: Option<u8>` в `TunRouting` / `TunRouter`;
  - расширить `TunRoute::Direct { fwmark: Option<u32>, dscp: Option<u8> }`;
  - добавить `direct_dscp` во все ветки возврата `TunRoute::Direct` и в `TunRouting::new(...)`.
- `tcp/engine/tasks/upstream/connect.rs`: извлекать `(fwmark, dscp)` из `TunRoute::Direct` и передавать в `connect_tcp_socket_direct`.
- `udp/engine.rs`: пробросить `(fwmark, dscp)` в `handle_direct_packet` → `bind_udp_socket_direct`.
- `config.rs`: обновить doc-комментарии у `ipsec_bypass` / `bypass_when_down` (упомянуть `direct_dscp` наряду с `direct_fwmark`).

#### 5. `bins/outline-client/src/`
- `config/schema.rs`:
  - `FileConfig`: `direct_dscp: Option<u8>` (с doc-комментарием: диапазон `0..=63`, работает на Unix без `CAP_NET_ADMIN`, полезно в k3s/контейнерах);
  - `OutlineSection`, `UplinkSection`, `FallbackSection`: `dscp: Option<u8>`.
- `config/args.rs`: CLI-флаг `--dscp <0..=63>` (рядом с `--fwmark`).
- `config/types.rs` и `proxy/config.rs`: `pub direct_dscp: Option<u8>`.
- `config/compat.rs`: прокинуть `dscp` при миграции legacy top-level ключей в `[outline]`.
- `config/load/`:
  - `mod.rs`: валидация `direct_dscp <= 63` (понятная ошибка при `> 63`);
  - `uplinks/source_precedence.rs`: `dscp: Option<u8>` и правило приоритета `CLI -> [outline]` / `uplink -> [outline]` (точно как `fwmark`);
  - `uplinks/fallback_resolution.rs`: наследование `section.dscp.or(parent.dscp)` (точно как `fwmark`) + валидация `0..=63`;
  - `uplinks/mod.rs`: валидация `dscp <= 63` для primary и всех fallbacks, проброс в `UplinkConfig`.
- `bootstrap/mod.rs`:
  - передавать `config.direct_dscp` в `TunRouting::new(...)`;
  - предупреждения о петле маршрутизации при `ipsec_bypass` и `bypass_when_down` на Linux выдавать только когда **оба** `config.direct_fwmark.is_none() && config.direct_dscp.is_none()`.
- `proxy/`:
  - `dispatcher.rs`: `Route::Direct { fwmark: Option<u32>, dscp: Option<u8> }`;
  - `tcp/direct.rs`, `tcp/connect/mod.rs`: передача `dscp` в `connect_tcp_socket_direct`;
  - `udp/in_tcp.rs`, `udp/socks5.rs`: передача `config.direct_dscp` в `bind_udp_socket_direct`.
- `http/control/`:
  - `config_crud.rs`: чтение, патч (`PatchConfigRequest`), валидация (`0..=63`) и сброс/запись `direct_dscp` через `toml_edit`;
  - `uplinks_crud/payload.rs` (и связанные файлы валидации/редактирования в `uplinks_crud/`): поддержка `dscp` у аплинков и у каждого fallback'а (валидация `0..=63`, сериализация в `toml_edit` и возврат в JSON).

#### 6. `bins/outline-ui/frontend/`
- `src/lib/types.ts`: поля `dscp?: number | null` в типах uplink/fallback и `direct_dscp?: number | null` в конфиге `ws`.
- `src/lib/uplinkForm.ts`: поле `dscp` (валидация целого `0..=63`, сборка/разборка payload для uplink и fallbacks).
- `src/features/ws/UplinkDrawer.svelte`: поля ввода `dscp` (`min=0 max=63 step=1`, placeholder `"default"` / `"inherit parent"`) для uplink и fallback.
- `src/features/ws/Uplinks.svelte`: отображение `dscp=<n>` в сводке флагов аплинка рядом с `fwmark`.
- `src/features/ws/WsSettings.svelte`: поле `Direct Dscp` (`min=0 max=63 step=1`) рядом с `Direct Fwmark`.
- `src/test/fixtures.ts` и unit-тесты формы (`uplinkForm` / др.).

#### 7. Документация (строго EN + RU в одном изменении)
- `PATCHES.md` и `PATCHES.ru.md`: задокументировать новый vendored-крейт `vendor/quinn-udp` (`0.5.16`), ссылку на `quinn-udp-0.5.16.patch`, причину патча, перечень правок (`src/unix.rs`, `Cargo.toml`) и обновление таблицы инвариантов.
- `AGENTS.md`: упомянуть `vendor/quinn-udp` и `quinn-udp-0.5.16.patch` в разделах «Структура», «Монорепо-инварианты (Единый `vendor/`)» и «Vendored patches».
- `README.md` и `README.ru.md`, `bins/outline-client/README.md` и `bins/outline-client/README.ru.md`: описание `dscp` (на аплинках, fallback, в `[outline]`, CLI `--dscp`) и `direct_dscp`, диапазона `0..=63`, порядка приоритета и типового сценария использования в k3s/контейнерах (`nftables` `cni0` → `fwmark`).
- `CHANGELOG.md` и `CHANGELOG.ru.md`: запись о добавлении `dscp`/`direct_dscp` и патча `quinn-udp`.

---

## 5. План тестирования и верификации

Все новые тесты в крейтах и бинарях размещать в подкаталогах `tests/` рядом с модулем (`<dir>/tests/<basename>.rs`), без inline `#[cfg(test)] mod tests {}` (инвариант `AGENTS.md`).

### 5.1. Обязательные тестовые сценарии (TDD: сперва убедиться в падении без фичи/патча)

1. **Конфиг, валидация и наследование (`bins/outline-client`, `crates/outline-uplink`):**
   - Валидны граничные значения `0`, `59`, `63` для `dscp` и `direct_dscp`.
   - Значения `64`, `255` отклоняются при загрузке TOML-конфига и через Control API (`PATCH /control/config`, CRUD uplinks/fallbacks).
   - Проверка приоритета: `fallback.dscp` → `uplink.dscp` → `[outline].dscp`; CLI `--dscp` переопределяет `[outline].dscp`.
   - Совместная работа `fwmark` + `dscp` одновременно в одном аплинке и в `direct_*`.
2. **Изоляция кэшей, пулов и проб (`crates/outline-transport`, `crates/outline-uplink`):**
   - `ConnectionKey`, `H2ConnectionKey`, H3 carrier slot key, `PmtuKey` различаются при изменении только `dscp` (например `None` vs `Some(59)` vs `Some(40)`).
   - `ProbeEndpoint` не дедуплицирует два аплинка на один `host:port`, если у них разный `dscp`.
3. **Сокетный слой (`crates/outline-net`, `#[cfg(unix)]`):**
   - IPv4 TCP (`connect_tcp_socket` к локальному `TcpListener`): `getsockopt(IPPROTO_IP, IP_TOS)` == `59 << 2` (`0xec`), и проверяется, что опция уже выставлена на сокете к моменту установления соединения.
   - IPv4 UDP (`bind_udp_socket`): `getsockopt(IPPROTO_IP, IP_TOS)` == `59 << 2`.
   - IPv6 TCP и UDP (`bind_udp_socket` на `[::]:0`): `getsockopt(IPPROTO_IPV6, IPV6_TCLASS)` == `59 << 2` (и для dual-stack UDP по возможности `IP_TOS` тоже `59 << 2`).
   - Проверка `dscp = Some(0)` vs `None`, а также совместимость `fwmark` + `dscp` на Linux.
4. **Интеграционный тест патча `vendor/quinn-udp` с реальным QUIC (`#[cfg(target_os = "linux")]` в Docker и где доступно на Unix):**
   - Поднять серверный `UdpSocket` (IPv4 loopback `127.0.0.1:0`, а также отдельный тест для IPv6 `[::1]:0`) с включённым `IP_RECVTOS` / `IPV6_RECVTCLASS`.
   - Поднять клиентский `quinn::Endpoint` поверх `outline_net::bind_udp_socket(..., dscp = Some(59))` и отправить реальный QUIC handshake (`endpoint.connect(...)`).
   - Прочитать входящую датаграмму на сервере через `libc::recvmsg` с разбором `cmsg`:
     - убедиться, что принятый IPv4 `IP_TOS` / IPv6 `IPV6_TCLASS` удовлетворяет `(tos >> 2) == 59` (то есть `quinn-udp` в `prepare_msg` **не перезатёр** DSCP нулём!);
     - убедиться, что при `dscp = None` `(tos >> 2) == 0`;
     - проверить, что ECN-биты `transmit.ecn` (если заданы в `quinn-udp`) сохраняются в младших 2 битах (`tos & 0x03`) вместе с DSCP в старших 6 битах (`tos & 0xfc`).
5. **Frontend (`bins/outline-ui/frontend`):**
   - Unit-тесты `uplinkForm` и сериализации/валидации `dscp` (`0..=63`, пустое поле → `null`).

### 5.2. Обязательный прогон в Docker на Linux и полный CI-гейт

Согласно `AGENTS.md`, macOS-компилятор молча пропускает `#[cfg(target_os = "linux")]`, поэтому перед коммитом прогнать Linux-сборку и тесты `outline-net` / `outline-transport` / `outline-client` / `quinn-udp` внутри Linux Docker-контейнера.

Финальный CI-гейт (выполнять в точном порядке из `AGENTS.md` и не забывать `target/debug/` cleanup):

```bash
cargo fmt --check -p outline-server -p outline-client -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings
cargo test --workspace --exclude sockudo-ws --exclude outline-windows
RUN_E2E_FAILOVER=1 cargo test -p outline-client --features test-tls --test 'e2e_*' -- --test-threads=1

(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)

cargo check -p outline-server --no-default-features
cargo check -p outline-client --no-default-features
./scripts/audit-vendored.sh
./.github/scripts/check-served-key-path.sh

pnpm -C bins/outline-ui/frontend test
pnpm -C bins/outline-ui/frontend build
cargo check -p outline-ui --features embed-assets
```

---

## 6. Подводные камни (Pitfalls)

1. **Dual-stack IPv6 сокеты и `quinn-udp`:** на Linux `bind_udp_socket("[::]:0")` вызывает `set_only_v6(false)`. Если клиент подключается к IPv4-цели через IPv4-mapped адрес, `quinn-udp::prepare_msg` выбирает `is_ipv4 = true` и шлёт `IPPROTO_IP / IP_TOS`, а не `IPV6_TCLASS`. Поэтому `apply_dscp` на `Domain::IPV6` с `only_v6 == false` обязан выставлять **и `IPV6_TCLASS`, и `IP_TOS`**, а `UdpSocketState::new` в `vendor/quinn-udp` обязан читать оба значения в `dscp_v4` и `dscp_v6`.
2. **Detached workspace `android/rust`:** у `android/rust/Cargo.toml` свой `[patch.crates-io]` и свой `Cargo.lock`. Если прописать `quinn-udp` только в корневом `Cargo.toml`, Android-сборка соберёт непатченный `quinn-udp`, а `./scripts/audit-vendored.sh` поведёт себя некорректно. Обязательно обновить оба манифеста и оба `Cargo.lock` (выполнить `cargo update -p quinn-udp` или проверку в обоих).
3. **`build.rs` у `quinn-udp`:** при создании `vendor/quinn-udp` нельзя удалять `build.rs` и зависимость `cfg-aliases` в `[build-dependencies]`, иначе сломаются `#[cfg(apple_fast)]` / `#[cfg(bsd)]` / `#[cfg(solarish)]` и другие платформенные ветки.
4. **`cargo fmt --all` трогает `vendor/*`:** форматировать только наши пакеты (или откатывать format-only diff в `vendor/`), чтобы `quinn-udp-0.5.16.patch` оставался минимальным и чистым.
5. **`// SAFETY:` инварианты:** на каждый новый `unsafe` блок `setsockopt`/`getsockopt` в `crates/outline-net` (наши крейты под `-D warnings` и `undocumented_unsafe_blocks = "warn"`) писать развёрнутый `// SAFETY:` комментарий.
6. **Не сбрасывать `cargo-audit` предупреждения/ошибки:** проверить `./scripts/audit-vendored.sh` после правки `[patch.crates-io]` и lock-файлов.
7. **Не деплоить на боевые хосты автоматически** и **не стейджить чужие изменения в git** — коммитить строго через `git commit -- <paths>`.

---

## 7. Готовый стартовый промпт для отдельной сессии

```text
Реализуй задачу из спецификации docs/superpowers/specs/2026-11-22-dscp-egress-marking-design.md (обязательный скоуп P0: поддержка dscp / direct_dscp наряду с fwmark в outline-client, crates/outline-{net,transport,uplink,tun}, outline-ui/ws и vendored-патч vendor/quinn-udp 0.5.16).

Требования:
1. Перед стартом прочитай AGENTS.md целиком и указанную спецификацию целиком.
2. Сначала составь краткий пошаговый план реализации (включая план проверок в Linux Docker), затем реализуй изменения строго по TDD (сначала падающие тесты, в т.ч. реальный тест QUIC cmsg recvmsg на loopback, затем код и патч).
3. Соблюди все монорепо-инварианты: обновление android/rust/Cargo.toml, quinn-udp-0.5.16.patch, двуязычную документацию (EN + RU: PATCHES*.md, AGENTS.md, README*.md, bins/outline-client/README*.md, CHANGELOG*.md), // SAFETY: комментарии, без форматирования vendor/*.
4. Прогони проверку Linux-специфики в Docker и весь CI-гейт из AGENTS.md + audit-vendored.sh + frontend tests/build, подчини debug-артефакты после тестов. Боевые хосты не трогать и ничего не деплоить.
```
