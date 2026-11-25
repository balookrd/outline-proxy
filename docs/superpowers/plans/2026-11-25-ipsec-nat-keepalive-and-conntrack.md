# План реализации: RFC 3948 NAT-keepalive и увеличенный idle-таймаут для `tun.ipsec_bypass`

> **Для исполнителей:** использовать `superpowers:subagent-driven-development` или `superpowers:executing-plans`, выполняя задачи последовательно с TDD и проверкой CI-гейта.

**Цель:** устранить обрывы VoWiFi / IKEv2 NAT-T при работе через `outline-client` (`tun.ipsec_bypass = true`) за многоуровневым NAT (когда паузы между исходящими пакетами мобильного модема в режиме энергосбережения превышают таймауты промежуточных NAT/conntrack или общий `[tun] idle_timeout_secs`).

**Архитектура:**
В `crates/outline-tun` для прямых UDP-потоков, прошедших через `tun.ipsec_bypass = true` (`remote_port == 500 || 4500`):
1. Sender-таска прямого сокета для порта NAT-T (`4500`) при простое `20 с` без клиентских датаграмм отправляет стандартный 1-байтовый пакет **RFC 3948 §2.3 NAT-keepalive (`0xff`)** на `target_addr`. Это удерживает все промежуточные NAT/conntrack-таблицы по пути на одном внешнем порту, а ePDG/IPsec-шлюз штатно и бесшумно отбрасывает такой пакет на входе.
2. Синтетический `0xff` **не обновляет `last_seen`** потока (и не искажает клиентские счётчики трафика), поэтому при уходе клиента из сети сокет не остаётся жить бесконечно.
3. Потоки `ipsec_bypass` (`500`/`4500`) получают собственный `idle_timeout = max(3600 с, tun.idle_timeout_secs)`, что позволяет переживать длинные паузы модема (Doze) без раздувания общего `tun.idle_timeout_secs` для обычных DNS/QUIC/STUN-потоков.

**Стек:** Rust 2024 (`outline-tun`, `tokio`).

## Глобальные ограничения

- Не менять схему `config.toml` / Control API / `outline-ui` / `android` (YAGNI: поведение активируется автоматически при `tun.ipsec_bypass = true` с безопасными RFC-дефолтами).
- Сохранить guardrail **Bounded resources** (`AGENTS.md`): `DirectUdpFlowState` остаётся в `direct_flows` под `max_flows` и `direct_eviction_index`, `AbortOnDrop` гарантированно останавливает sender-таску с keepalive при закрытии потока, а `last_seen` обновляется только реальными пакетами клиента и ответами шлюза.
- Двуязычная документация: обновить одновременно `bins/outline-client/README.md` и `bins/outline-client/README.ru.md` (плюс `crates/outline-tun/src/config.rs` и `bins/outline-client/AGENTS.md`).
- Тесты держать в `crates/outline-tun/src/udp/tests/types.rs` и `crates/outline-tun/src/udp/tests/direct.rs` (без inline `#[cfg(test)] mod tests {}`).
- После проверок очищать промежуточные debug-артефакты (`target/debug/`); после финального `git push` — `cargo clean`.

---

### Задача 1: Per-flow `idle_timeout` в `FlowStamp` и `DirectUdpFlowState`

**Файлы:**
- Изменить: `crates/outline-tun/src/routing.rs:292-306`
- Изменить: `crates/outline-tun/src/udp/types.rs:135-185, 258-265`
- Изменить: `crates/outline-tun/src/udp/engine.rs:687-695`
- Тест: `crates/outline-tun/src/udp/tests/types.rs`

**Интерфейсы:**
- Производит:
  - `pub(crate) const IPSEC_NAT_T_PORT: u16 = 4500;` в `crates/outline-tun/src/routing.rs`
  - `pub(crate) fn ipsec_bypass(&self) -> bool` у `TunRouting`
  - `fn idle_timeout(&self, default: Duration) -> Duration` в `trait FlowStamp`
  - поле `pub(super) idle_timeout: Option<Duration>` в `DirectUdpFlowState`

- [ ] **Шаг 1: Написать падающий тест в `crates/outline-tun/src/udp/tests/types.rs`**

Добавить в `TestFlow` поле `idle_timeout_override: Option<Duration>` (и реализовать `fn idle_timeout(&self, default: Duration) -> Duration { self.idle_timeout_override.unwrap_or(default) }`), а также тест `idle_sweep_respects_per_flow_idle_timeout_override`:

```rust
#[tokio::test]
async fn idle_sweep_respects_per_flow_idle_timeout_override() {
    let flows: TestTable = Arc::new(RwLock::new(HashMap::new()));
    let now = Instant::now();
    let short_key = flow_key(41001);
    let long_key = flow_key(41002);

    {
        let mut guard = flows.write().await;
        guard.insert(
            short_key.clone(),
            Arc::new(Mutex::new(TestFlow {
                id: 1,
                last_seen: now - Duration::from_secs(60),
                eviction_indexed_at: now - Duration::from_secs(60),
                idle_timeout_override: None,
            })),
        );
        guard.insert(
            long_key.clone(),
            Arc::new(Mutex::new(TestFlow {
                id: 2,
                last_seen: now - Duration::from_secs(60),
                eviction_indexed_at: now - Duration::from_secs(60),
                idle_timeout_override: Some(Duration::from_secs(300)),
            })),
        );
    }

    let drained = drain_idle_flows(&flows, Duration::from_secs(30), now).await;
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].0, short_key);
    assert!(flows.read().await.contains_key(&long_key));

    let drained_later =
        drain_idle_flows(&flows, Duration::from_secs(30), now + Duration::from_secs(250)).await;
    assert_eq!(drained_later.len(), 1);
    assert_eq!(drained_later[0].0, long_key);
}
```

- [ ] **Шаг 2: Прогнать тест и убедиться, что он падает**

Команда: `cargo test -p outline-tun idle_sweep_respects_per_flow_idle_timeout_override`
Ожидаемо: FAIL (метод `idle_timeout` отсутствует в `FlowStamp`).

- [ ] **Шаг 3: Внести минимальные правки в `routing.rs`, `types.rs` и `engine.rs`**

1. В `crates/outline-tun/src/routing.rs`:
   - Вынести `pub(crate) const IPSEC_NAT_T_PORT: u16 = 4500;` и использовать его в `is_ipsec_port`.
   - Добавить `pub(crate) fn ipsec_bypass(&self) -> bool { self.ipsec_bypass }` в `impl TunRouting`.
2. В `crates/outline-tun/src/udp/types.rs`:
   - В `trait FlowStamp` добавить метод по умолчанию:
     ```rust
     fn idle_timeout(&self, default: Duration) -> Duration {
         default
     }
     ```
   - В `DirectUdpFlowState` добавить поле `pub(super) idle_timeout: Option<Duration>`.
   - В `impl FlowStamp for DirectUdpFlowState` переопределить `idle_timeout` через `self.idle_timeout.unwrap_or(default)`.
   - В `drain_idle_flows` заменить сравнение `>= idle_timeout` на `>= flow.idle_timeout(idle_timeout)`.
3. В `crates/outline-tun/src/udp/engine.rs`: инициализировать `idle_timeout: None` в `DirectUdpFlowState` (будет заменено на `flow_idle_timeout` в Задаче 2).

- [ ] **Шаг 4: Прогнать тесты**

Команда: `cargo test -p outline-tun udp::types`
Ожидаемо: PASS.

---

### Задача 2: RFC 3948 NAT-keepalive (`0xff`) и `ipsec_idle_timeout` в `TunUdpEngine`

**Файлы:**
- Изменить: `crates/outline-tun/src/udp/engine.rs:50-180, 559-737`
- Тест: `crates/outline-tun/src/udp/tests/direct.rs`

**Интерфейсы:**
- Потребляет: `TunRouting::ipsec_bypass()`, `routing::IPSEC_NAT_T_PORT`, `routing::is_ipsec_port()`, `DirectUdpFlowState.idle_timeout`.
- Производит:
  - Константы `IPSEC_NAT_KEEPALIVE_PAYLOAD: [u8; 1] = [0xff]`, `DEFAULT_IPSEC_NAT_KEEPALIVE_INTERVAL = Duration::from_secs(20)`, `DEFAULT_IPSEC_IDLE_TIMEOUT = Duration::from_secs(3600)`.
  - `#[cfg(test)] pub(crate) fn with_ipsec_test_params(...)` (или отдельный конструктор-обёртка под `#[cfg(test)]`), позволяющий тестам использовать эфемерный `127.0.0.1:0` peer-сокет вместо жёсткого порта `4500` и миллисекундные таймеры.

- [ ] **Шаг 1: Написать падающие тесты в `crates/outline-tun/src/udp/tests/direct.rs`**

Добавить 3 теста:
1. `ipsec_bypass_nat_t_port_emits_rfc3948_keepalive_on_idle`:
   - при `ipsec_bypass = true` после первого клиентского пакета на тестовый `nat_t_port` и паузы > `keepalive_interval` peer-сокет получает датаграмму ровно из 1 байта `[0xff]`.
2. `ipsec_bypass_disabled_or_other_port_does_not_emit_keepalive`:
   - при `ipsec_bypass = false` (или при `ipsec_bypass = true` и `remote_port != nat_t_port`) peer-сокет не получает `[0xff]`.
3. `ipsec_nat_keepalive_does_not_extend_last_seen_past_ipsec_idle_timeout`:
   - `general idle_timeout = 80 ms`, `keepalive_interval = 30 ms`, `ipsec_idle_timeout = 220 ms`;
   - после `120 ms` поток переживает `cleanup_idle_flows()` и продолжает слать `[0xff]`;
   - после `300 ms` `cleanup_idle_flows()` удаляет поток из `direct_flows` (синтетический `[0xff]` не сдвинул `last_seen`), и отправка `[0xff]` прекращается.

- [ ] **Шаг 2: Прогнать тесты и убедиться, что они падают**

Команда: `cargo test -p outline-tun udp::tests::direct::ipsec_`
Ожидаемо: FAIL.

- [ ] **Шаг 3: Реализовать NAT-keepalive и `ipsec_idle_timeout` в `crates/outline-tun/src/udp/engine.rs`**

1. В `TunUdpEngineInner` добавить:
   - `ipsec_nat_t_port: u16` (по умолчанию `crate::routing::IPSEC_NAT_T_PORT`)
   - `ipsec_nat_keepalive_interval: Duration` (по умолчанию `DEFAULT_IPSEC_NAT_KEEPALIVE_INTERVAL`)
   - `ipsec_idle_timeout: Duration` (по умолчанию `DEFAULT_IPSEC_IDLE_TIMEOUT`)
2. В `handle_direct_packet`:
   - Определить:
     ```rust
     let ipsec_bypass = self.inner.dispatch.ipsec_bypass();
     let is_nat_t = ipsec_bypass && key.remote_port == self.inner.ipsec_nat_t_port;
     let is_ipsec = is_nat_t || (ipsec_bypass && crate::routing::is_ipsec_port(key.remote_port));
     let nat_keepalive = (is_nat_t && !self.inner.ipsec_nat_keepalive_interval.is_zero())
         .then_some(self.inner.ipsec_nat_keepalive_interval);
     let flow_idle_timeout =
         is_ipsec.then(|| self.inner.ipsec_idle_timeout.max(self.inner.idle_timeout));
     ```
   - В sender-таске при `Some(interval)` ждать `tokio::time::timeout(interval, outbound_rx.recv()).await`; при `Err(_)` выполнять `sender_sock.send_to(&IPSEC_NAT_KEEPALIVE_PAYLOAD, target_addr).await` с `debug!`-логом при ошибке, без обновления `last_seen` и без записи в `up_counters`.
   - Сохранить `idle_timeout: flow_idle_timeout` в `DirectUdpFlowState`.

- [ ] **Шаг 4: Прогнать тесты**

Команда: `cargo test -p outline-tun udp::tests::direct`
Ожидаемо: PASS.

---

### Задача 3: Обновление двуязычной документации (EN + RU)

**Файлы:**
- Изменить: `crates/outline-tun/src/config.rs:46-58`
- Изменить: `bins/outline-client/README.md` (раздел `tun.ipsec_bypass`)
- Изменить: `bins/outline-client/README.ru.md` (раздел `tun.ipsec_bypass`)
- Изменить: `bins/outline-client/AGENTS.md` (упоминание `tun.ipsec_bypass`)

- [ ] **Шаг 1: Синхронизировать описание `tun.ipsec_bypass`**

Описать в EN- и RU-версиях, что при `tun.ipsec_bypass = true`:
- прямые потоки на UDP `4500` отправляют RFC 3948 §2.3 NAT-keepalive (`0xff`, 1 байт) каждые `20 с` простоя, удерживая промежуточные NAT/conntrack-таблицы;
- синтетический keepalive не продлевает `last_seen`, а idle-таймаут прямых потоков UDP `500`/`4500` составляет `max(3600 с, tun.idle_timeout_secs)`.

---

### Задача 4: CI-гейт, очистка debug-артефактов и коммит

- [ ] **Шаг 1: Прогнать локальный CI-гейт (`AGENTS.md`)**

```bash
cargo fmt --check -p outline-server -p outline-client -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings
cargo test --workspace --exclude sockudo-ws --exclude outline-windows
(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)
```

- [ ] **Шаг 2: Очистить `target/debug/` и сделать коммит `git commit -- <свои файлы>`**
