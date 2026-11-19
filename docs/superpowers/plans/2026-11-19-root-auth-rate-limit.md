# Серверный in-memory rate-limiting для http_root_auth по IP

План закрытия вектора брутфорса HTTP Basic Auth на корневом маршруте `/`.

---

## 1. Контекст

При `http_root_auth = true` доступ к корню сайта (`/`) защищён HTTP Basic Auth.
Счётчик неудачных попыток (`auth_attempts`) хранился только в cookie клиента:
- До 3 попыток возвращается `401 Unauthorized`.
- На 3-й попытке и далее возвращается `403 Forbidden` с TTL 300 секунд.
Если клиент стирает cookie или отправляет запросы без Cookie-заголовка, сервер сбрасывал счётчик в 0, что открывало возможность неограниченного подбора паролей.

---

## 2. Архитектурное решение

В `bins/outline-ss-rust/src/server/auth.rs`:
- Добавить `RootAuthRateLimiter`:
  - `LruCache<IpAddr, FailureRecord>` емкостью 1024 записей под `parking_lot::Mutex`.
  - Запись: `FailureRecord { count: u8, last_failure: Instant }`.
  - TTL: 300 секунд (`ROOT_HTTP_AUTH_COOKIE_TTL_SECS`).
- Методы:
  - `failed_attempts(&self, ip: IpAddr) -> u8`
  - `record_failure(&self, ip: IpAddr, cookie_attempts: u8) -> u8`
  - `reset(&self, ip: IpAddr)`
- Добавить поле `rate_limiter: Arc<RootAuthRateLimiter>` в `AuthPolicy` (`state.rs`).
- Использовать в `transport/mod.rs` (axum TCP) и `h3/http.rs` (HTTP/3).

---

## 3. План тестирования

1. Тест в `bins/outline-ss-rust/src/server/tests/auth.rs`:
   - 3 запроса с неверным паролем без передачи `Cookie` заголовка.
   - 1-й и 2-й запросы получают `401 Unauthorized`.
   - 3-й и 4-й запросы получают `403 Forbidden`.
   - Проверка успешной авторизации правильным паролем и сброса счетчика.
2. Прогон полного локального CI-гейта.
