# План реализации: Устранение регрессии H3 accept timeout и классификация H3_NO_ERROR

> **Для агентов-исполнителей:** ОБЯЗАТЕЛЬНЫЙ НАВЫК: использовать superpowers:subagent-driven-development или superpowers:executing-plans для пошагового выполнения. Шаги используют синтаксис чекбоксов (`- [ ]`).

**Цель:** Устранить ложные сбои аплинков и обрывы туннелей в HTTP/3: снять искусственный 60-секундный таймаут ожидания новых запросов в `outline-ss-rust` и классифицировать `ApplicationClose: H3_NO_ERROR` на стороне клиента `outline-ws-rust` как штатное закрытие соединения, а не сбой носителя.

**Архитектура:**
1. В `outline-ss-rust` (`bins/outline-ss-rust/src/server/h3/http.rs`): таймаут slowloris (15 с) сохраняется только для первого запроса соединения (`is_first_request`); после успешного приёма первого запроса цикл `h3_conn.accept().await` ожидает новые стримы без искусственного ограничения в 60 с, полагаясь на естественный протокольный idle timeout QUIC (`max_idle_timeout = 30s` под Caddy), учитывающий активность открытых стримов и keep-alive.
2. В `outline-ws-rust` (`bins/outline-ws-rust/src/error_class.rs`): в перечень строк чистого закрытия WebSocket/H3 (`EXTERNAL_WS_CLOSE_STRINGS`) добавляются `"applicationclose: h3_no_error"` и `"h3_no_error"`. Это предотвращает эскалацию закрытия H3 в `report_runtime_failure`, cooldown и capping носителя.
3. В `outline-tun` (`crates/outline-tun/src/udp/lifecycle.rs`): функция `is_clean_ws_close` расширяется распознаванием закрытия `H3_NO_ERROR`, предотвращая переход UDP flow reader в `CarrierFailure`.
4. Двуязычная документация (`CHANGELOG.md` / `CHANGELOG.ru.md`) обновляется с описанием проблемы и исправления.

**Стек технологий:** Rust (Edition 2024), Tokio, Quinn / H3, Cargo workspace.

## Глобальные ограничения

- Язык диалогов, рассуждений и планов: русский.
- Терминология: «носитель» для carrier, «гейт» для gate.
- Очистка промежуточных debug-артефактов `target/` после тестов и `cargo clean` после пуша.
- Никакого автоматического деплоя на хосты парка без явного разрешения владельца.

---

### Задача 1: Исправление серверного цикла accept в `outline-ss-rust`

**Файлы:**
- Изменить: `bins/outline-ss-rust/src/server/h3/http.rs:59-75`
- Тест: `bins/outline-ss-rust/src/server/tests/h3.rs`

- [ ] **Шаг 1: Написать тест на поведение accept-таймаута первого и последующих запросов**
Добавить тест или проверить существующие тесты в `bins/outline-ss-rust/src/server/tests/h3.rs`.

- [ ] **Шаг 2: Запустить тест и убедиться в текущем поведении**
Запустить: `cargo test -p outline-ss-rust --test h3`

- [ ] **Шаг 3: Исправить цикл ожидания запросов в `bins/outline-ss-rust/src/server/h3/http.rs`**
Изменить логику:
```rust
let accept_res = if is_first_request {
    match tokio::time::timeout(Duration::from_secs(15), h3_conn.accept()).await {
        Ok(res) => res,
        Err(_) => {
            debug!(peer = %peer_addr, "HTTP/3 initial request timeout; closing");
            break;
        },
    }
} else {
    h3_conn.accept().await
};
```

- [ ] **Шаг 4: Запустить тесты `outline-ss-rust`**
Запустить: `cargo test -p outline-ss-rust`
Ожидается: PASS

- [ ] **Шаг 5: Закоммитить изменения**
```bash
git add bins/outline-ss-rust/src/server/h3/http.rs
git commit -m "fix(ss): remove post-first-request 60s idle timeout on HTTP/3 accept loop"
```

---

### Задача 2: Классификация `H3_NO_ERROR` на стороне клиента `outline-ws-rust`

**Файлы:**
- Изменить: `bins/outline-ws-rust/src/error_class.rs:33-40`
- Тест: `bins/outline-ws-rust/src/tests/error_class.rs`

- [ ] **Шаг 1: Написать failing test в `bins/outline-ws-rust/src/tests/error_class.rs`**
Добавить проверку:
```rust
#[test]
fn h3_no_error_remote_close_is_classified_as_clean_close() {
    let err = anyhow!(
        "websocket read failed: IO error: I/O error: Connection error: Remote error: ApplicationClose: H3_NO_ERROR: I/O error: Connection error: Remote error: ApplicationClose: H3_NO_ERROR"
    );
    assert!(is_ws_closed(&err));
    assert!(!is_upstream_runtime_failure(&err));
}
```

- [ ] **Шаг 2: Запустить тест и убедиться, что он падает**
Запустить: `cargo test -p outline-ws-rust --test error_class h3_no_error`
Ожидается: FAIL

- [ ] **Шаг 3: Добавить строки в `EXTERNAL_WS_CLOSE_STRINGS` в `bins/outline-ws-rust/src/error_class.rs`**
```rust
const EXTERNAL_WS_CLOSE_STRINGS: &[&str] = &[
    "connection reset without closing handshake",
    "peer closed connection without sending tls close_notify",
    "applicationclose: h3_no_error",
    "h3_no_error",
];
```

- [ ] **Шаг 4: Запустить тест и убедиться, что он проходит**
Запустить: `cargo test -p outline-ws-rust --test error_class h3_no_error`
Ожидается: PASS

- [ ] **Шаг 5: Закоммитить изменения**
```bash
git add bins/outline-ws-rust/src/error_class.rs bins/outline-ws-rust/src/tests/error_class.rs
git commit -m "fix(ws): classify H3_NO_ERROR application close as clean close"
```

---

### Задача 3: Классификация `H3_NO_ERROR` в TUN UDP flow reader `outline-tun`

**Файлы:**
- Изменить: `crates/outline-tun/src/udp/lifecycle.rs:1115-1122`
- Тест: `crates/outline-tun/src/udp/tests/lifecycle.rs`

- [ ] **Шаг 1: Написать failing test в `crates/outline-tun/src/udp/tests/lifecycle.rs`**
Добавить проверку, что ошибка `ApplicationClose: H3_NO_ERROR` не эскалируется в `CarrierFailure`:
```rust
#[test]
fn h3_no_error_reader_stop_classifies_as_clean_close() {
    let err = anyhow!(
        "websocket read failed: IO error: I/O error: Connection error: Remote error: ApplicationClose: H3_NO_ERROR"
    );
    let stop = ReaderStop::classify(&err);
    assert_eq!(stop, ReaderStop::CleanClose);
    assert!(!stop.escalates_to_carrier());
}
```

- [ ] **Шаг 2: Запустить тест и убедиться, что он падает**
Запустить: `cargo test -p outline-tun --lib udp::tests::lifecycle::h3_no_error`
Ожидается: FAIL

- [ ] **Шаг 3: Реализовать поддержку в `crates/outline-tun/src/udp/lifecycle.rs`**
Обновить `is_clean_ws_close`:
```rust
fn is_clean_ws_close(error: &anyhow::Error) -> bool {
    if error.chain().any(|cause| cause.downcast_ref::<WsClosed>().is_some()) {
        return true;
    }
    let lower = error.to_string().to_ascii_lowercase();
    lower.contains("h3_no_error")
}
```

- [ ] **Шаг 4: Запустить тесты `outline-tun`**
Запустить: `cargo test -p outline-tun --lib`
Ожидается: PASS

- [ ] **Шаг 5: Закоммитить изменения**
```bash
git add crates/outline-tun/src/udp/lifecycle.rs crates/outline-tun/src/udp/tests/lifecycle.rs
git commit -m "fix(tun): treat H3_NO_ERROR as clean close in UDP flow reader"
```

---

### Задача 4: Обновление документации (двуязычная EN/RU)

**Файлы:**
- Изменить: `bins/outline-ss-rust/CHANGELOG.md`
- Изменить: `bins/outline-ss-rust/CHANGELOG.ru.md`
- Изменить: `bins/outline-ws-rust/CHANGELOG.md`
- Изменить: `bins/outline-ws-rust/CHANGELOG.ru.md`

- [ ] **Шаг 1: Добавить записи в CHANGELOG для сервера и клиента**
Описать устранение 60-секундного таймаута на сервере и классификацию `H3_NO_ERROR` на клиенте в обеих языковых версиях.

- [ ] **Шаг 2: Закоммитить изменения документации**
```bash
git add bins/outline-ss-rust/CHANGELOG.md bins/outline-ss-rust/CHANGELOG.ru.md \
        bins/outline-ws-rust/CHANGELOG.md bins/outline-ws-rust/CHANGELOG.ru.md
git commit -m "docs(changelog): document H3 accept timeout and close classification fixes"
```

---

### Задача 5: Полный CI-гейт и очистка debug-артефактов

- [ ] **Шаг 1: Запустить локальный гейт**
```bash
cargo fmt --check -p outline-ss-rust -p outline-ws-rust -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings
cargo test --workspace --exclude sockudo-ws --exclude outline-windows
```

- [ ] **Шаг 2: Очистить промежуточные debug-артефакты компиляции**
```bash
rm -rf target/debug/deps target/debug/incremental
```
