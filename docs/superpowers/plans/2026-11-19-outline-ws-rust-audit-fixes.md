# План устранения дефектов надежности и безопасности в клиентском стеке outline-ws-rust

## 1. Введение и цели
В рамках аудита клиентского стека `outline-proxy` (`bins/outline-ws-rust/` и связанных библиотек `crates/outline-tun/`, `crates/outline-transport/`, `crates/outline-uplink/`, `crates/outline-routing/`, `crates/outline-net/`, `crates/outline-metrics/`, `crates/socks5-proto/`, `crates/shadowsocks-crypto/`) подтвержден ряд критических дефектов надежности (DoS, утечки памяти, зависания CPU, десинхронизация состояния) и уязвимостей безопасности (Path Traversal/File Oracle, утечка учетных данных, обход фильтрации IP, Timing attacks).

Цель настоящих работ: полное устранение выявленных дефектов с соблюдением принципов TDD, сохранением всех инвариантов монорепозитория, отсутствием регрессий и успешным прохождением CI-гейта.

---

## 2. Перечень задач и архитектурные решения

### Этап 1: Высокий приоритет (High: H-9, H-10, H-11, H-12, H-13, H-14, H-15, H-16)

#### 1. [H-9] Бесконечный CPU-цикл в TLS data-path probe (`crates/outline-uplink/src/probe/tls.rs`)
- **Проблема**: `conn.read_tls(&mut cursor)` внутри цикла `while (cursor.position() as usize) < chunk_len` при заполнении внутреннего буфера rustls возвращает `Ok(0)`. Поскольку `conn.process_new_packets()` вынесен за пределы `while`, курсор не продвигается, и поток зависает в бесконечном синхронном цикле со 100% CPU.
- **Решение**: Вызывать `conn.process_new_packets()` внутри цикла чтения или прерывать цикл при `read_tls == 0`, обрабатывать пакеты и продолжать чтение при необходимости. Если буфер не продвигается после `process_new_packets`, возвращать ошибку.
- **Тесты**: Добавить юнит-тест в `crates/outline-uplink/src/probe/tests/tls.rs`, эмулирующий возврат `Ok(0)` от `read_tls` при незавершенном чанке.

#### 2. [H-10] Обход IPv4 CIDR-правил через IPv4-mapped IPv6 `::ffff:a.b.c.d` (`crates/outline-routing/src/cidr.rs`)
- **Проблема**: `CidrSet::contains` для `TargetAddr::IpV6(ip, _)` вызывает только `contains_v6(&self.v6, ...)`. Клиент или атакующий, передающий IPv4-mapped IPv6 адрес (`::ffff:x.y.z.w`), обходит все правила `self.v4`.
- **Решение**: В `CidrSet::contains` проверять, является ли IPv6 адрес IPv4-mapped (`ip.to_ipv4_mapped()` или проверка префикса `::ffff:0:0/96`). Если да — выполнять проверку `contains_v4(&self.v4, u32::from(mapped_v4))`.
- **Тесты**: Добавить тест в `crates/outline-routing/src/tests/` на сопоставление IPv4-mapped IPv6 с правилами IPv4 CIDR.

#### 3. [H-11] Cancel-unsafety и гонка `UplinkRegistry::apply_new_groups` (`crates/outline-uplink/src/registry.rs`)
- **Проблема**: В `apply_new_groups` отсутствовала взаимная блокировка от параллельных вызовов. Вызов `take_carrier_loss_registries()` и `spawn_*` происходил до вызова `initialize_strict_active_selection().await`. При отмене future на `.await` реестры `carried` терялись, а запущенные задачи `new_state` утекали.
- **Решение**: Добавить `apply_lock: tokio::sync::Mutex<()>` в `UplinkRegistry`. Оформить перенос реестров и запуск фоновых задач либо после завершения всех `await`, либо под RAII Drop Guard, который при преждевременной отмене/панике глушит `new_state` (`shutdown()`) и возвращает `carried` реестры в старые менеджеры.
- **Тесты**: Тест на отмену `apply_new_groups` с проверкой сохранения `carrier_loss_registries` и остановки задач.

#### 4. [H-12] SS-2022 UDP replay protection: потеря переупорядоченных пакетов и откат `server_session_id` (`crates/outline-transport/src/udp_transport.rs`)
- **Проблема**: Одиночный `packet_id <= last_server_packet_id` приводит к дропу переупорядоченных пакетов на H3 DATAGRAM. Также пакет с произвольным `session_id` мог перезаписать `server_session_id`.
- **Решение**: Реализовать скользящее битовое окно проверки повторов по RFC 6479 (sliding replay window) размером 128 пакетов. Зафиксировать `server_session_id` после первого принятого пакета сессии (пакеты с другим `session_id` в рамках одной сессии клиента отклоняются).
- **Тесты**: Тесты в `udp_transport.rs` на переупорядоченные пакеты (например, 5, затем 4, 3, затем 6) и отклонение дубликатов / пакетов вне окна / поддельного session_id.

#### 5. [H-13] Утечка строк файлов, File Oracle и OOM DoS в `/control/routes` (`bins/outline-ws-rust/src/http/control/routes_crud/mutate.rs`, `src/config/load/routing.rs`, `crates/outline-routing/src/cidr.rs`)
- **Проблема**: `resolve_config_path` разрешал абсолютные пути; `read_prefixes_from_file` читал файлы без лимита размера; синтаксическая ошибка CIDR выводила сырую строку файла в HTTP-ответ 400.
- **Решение**: В Control API путях маршрутов запретить абсолютные пути (пути должны быть относительными к `config_dir`). В `read_prefixes_from_file` и `read_domains_from_file` ограничить чтение до 10 МиБ, проверять тип файла (регулярный). Санитизировать сообщения об ошибках парсинга префиксов, не возвращая сырые строки неизвестных файлов.
- **Тесты**: Тесты на отказ от абсолютных путей в CRUD routes и отсутствие утечки содержимого файлов в ошибках.

#### 6. [H-14] Неограниченный рост `sack_scoreboard` в TUN TCP (`crates/outline-tun/src/tcp/state_machine/congestion.rs`)
- **Проблема**: Блоки SACK не проверялись против `state.server_seq` (SND.NXT) и могли расти неограниченно, приводя к аллокациям и DoS.
- **Решение**: Блоки SACK с диапазонами за пределами `server_seq` отбрасывать или обрезать до `server_seq`. Ограничить максимальный размер `sack_scoreboard` (например, 32 диапазона).
- **Тесты**: Тест с генерацией множества некорректных и будущих SACK блоков.

#### 7. [H-15] Обход лимита OOO-сегментов и раздувание RAM через `Bytes::slice` в TUN TCP reassembly (`crates/outline-tun/src/tcp/state_machine/recv.rs`, `wire.rs`)
- **Проблема**: Предварительная проверка лимита предполагала добавление не более 1..2 сегментов, тогда как цикл `holes` мог нарезать десятки под-сегментов. Мелкие срезы через `Bytes::slice` удерживали в памяти большие буферы.
- **Решение**: Рассчитывать точное число создаваемых сегментов перед вставкой в очередь; при мелких срезах от больших `Bytes` буферов выполнять `Bytes::copy_from_slice`, чтобы освобождать исходный буфер пакета.
- **Тесты**: Тест на сборку пакетов со множественными отверстиями (holes) с проверкой жесткого соблюдения лимитов.

#### 8. [H-16] Раскрытие секретов аплинков в `GET /control/uplinks` (`bins/outline-ws-rust/src/http/control/uplinks_crud/list.rs`)
- **Проблема**: `table_to_json(tbl)` возвращал сырую TOML-таблицу с паролями, UUID и ключами.
- **Решение**: Маскировать (`[REDACTED]`) чувствительные поля (`password`, `uuid`, `key`, `link`, учетные данные в URL) перед формированием JSON ответа.
- **Тесты**: Тест `handle_list` на отсутствие открытых паролей и UUID в JSON.

---

### Этап 2: Средний приоритет (Medium: M-11 .. M-20)

#### 9. [M-11] Timing side-channel в SOCKS5 и Control API (`crates/socks5-proto/src/handshake.rs`, `bins/outline-ws-rust/src/http/mod.rs`)
- **Решение**: В `constant_time_eq` сравнивать постоянные по длине хэши (SHA-256) обоих значений без раннего выхода по длине. В `matches_socks5_user` исключить short-circuit `&&` и проходить по всем пользователям за постоянное время.

#### 10. [M-12] Корректность UDP checksum `0x0000 -> 0xFFFF` и проверка `u16::MAX` (`crates/outline-tun/src/udp/wire.rs`)
- **Решение**: В `build_ipv4_udp_packet` и `build_ipv6_udp_packet` проверять `total_len <= u16::MAX`. Заменять вычисленный чексумм `0x0000` на `0xFFFF` согласно RFC 8200 §8.1 и RFC 768.

#### 11. [M-13] Control API: таймаут чтения тела, устранение `.expect()`, проверка ссылок на группу (`bins/outline-ws-rust/src/http/`)
- **Решение**:
  - `read_limited_body`: добавить таймаут чтения (например, 15 с, `408 Request Timeout`).
  - `uplinks_crud/mutate.rs`: заменить `.expect()` на безопасный возврат ошибки `Result<&mut ArrayOfTables, String>`.
  - `groups_crud/mutate.rs`: в `apply_delete` проверять, не используется ли удаляемая группа в секциях `[[route]]` (`via`, `fallback`).

#### 12. [M-14] Устранение дрейфа gauge `outline_ws_tun_flows_active` на TUN UDP (`crates/outline-tun/src/udp/lifecycle.rs`, `crates/outline-metrics/src/tun.rs`)
- **Решение**: Не вызывать `dec()` для активных потоков, если имя аплинка равно `"connecting"`.

#### 13. [M-15] Защита TUN TCP от SYN-флуда и соблюдение `max_carrier_flows` при `route_by_sni` (`crates/outline-tun/src/tcp/`)
- **Решение**:
  - В `insert_flow` не вытеснять установленные (`Established`) потоки в пользу новых `SynReceived`.
  - В `connect.rs` при миграции с direct на tunnel через SNI вызывать полноценное получение слота с эвикшном (`try_acquire` / `pop_oldest`).

#### 14. [M-16] Исправление SOCKS5 Direct UDP сокетов и устойчивость к единичным ошибкам (`bins/outline-ws-rust/src/proxy/udp/`)
- **Решение**:
  - Биндить прямой UDP сокет на `0.0.0.0:0` / `[::]:0`, а не на IP локального клиента SOCKS5.
  - Ошибку `send_udp_direct` логировать и продолжать цикл (`continue`), не закрывая всю SOCKS5 ассоциацию.

#### 15. [M-17] Защита дефрагментатора TUN от 0-байтных фрагментов и корректный учет бюджета (`crates/outline-tun/src/defrag/`)
- **Решение**: Игнорировать или безопасно отбрасывать 0-байтные фрагменты без нарушения цепочки; корректно синхронизировать `total_buffered_bytes`.

#### 16. [M-18] Транспортный уровень (XHTTP, H2, H3, VLESS)
- **Решение**:
  - `xhttp/h1.rs`, `h2.rs`: обернуть весь `send_fin` (включая lock и ready) в `FIN_TIMEOUT`.
  - `xhttp/h1.rs`: добавить `POST_TIMEOUT` для POST-запросов данных.
  - `xhttp/h2.rs`: настроить пинги/keepalive для H2 соединения.
  - `stream_one` (h2/h3): при ошибке отправки аплинка явно слать ошибку в `in_tx`, а не чистый Close.
  - `SharedH3Connection`: клонировать `send_request` под кратким локом и выполнять `.send_request.await` вне мьютекса (устранение HoL blocking).
  - `vless/udp_mux_core.rs`: проверять `close_signal` в `session_for`; отклонять новые слоты при превышении лимита in-flight dials.

#### 17. [M-19] Uplink-менеджмент
- **Решение**:
  - `reselect.rs`: корректно рассчитывать последовательный `day_key` (дни от эпохи), исключить скачок 1 января; устранить TOCTOU при выборе активного слота.
  - `share_link.rs`: явно возвращать ошибку неподдерживаемости при `security=reality` вместо тихого даунгрейда.
  - `selection.rs`: использовать `supports_udp_any()` вместо `supports_udp()` при проверке `global_udp_strict_health`.
  - `selection.rs`: использовать `try_from_secs_f64` с насыщением до `Duration::MAX` для предотвращения паник при делении на вес.

#### 18. [M-20] Атомарная запись файлов и watcher маршрутов
- **Решение**:
  - `fs_util.rs`, `state.rs`, `pmtu_cache.rs`: генерировать уникальные имена временных файлов (pid + timestamp/random) и использовать безопасное создание.
  - `outline-routing/src/table.rs`: обновлять `last_mtimes` только после успешного выполнения `reload_rule_sets`.

#### 19. [L-..] Сопутствующие улучшения
- **Решение**: SACK wrapping_sub при переполнении; проверка `group_name` в `ensure_flow_gauges`; вызов `StandbyPool::clear()` при выключении аплинка; сокрытие паролей в `Debug` для `socks5-proto`; замена `from_raw_fd` на `SockRef`; инкремент `sessions_opened` в пуле `xhttp_h3`.

---

## 3. План верификации (CI-гейт)
После реализации каждого этапа:
1. Запуск целевых тестов затронутых пакетов.
2. Прогон полного lint- и test-набора:
   ```bash
   cargo fmt --check -p outline-ws-rust -p outline-tun -p outline-transport -p outline-uplink -p outline-routing -p outline-metrics -p outline-net -p socks5-proto -p shadowsocks-crypto
   cargo clippy -p outline-ws-rust -p outline-tun -p outline-transport -p outline-uplink -p outline-routing -p outline-metrics -p outline-net -p socks5-proto -p shadowsocks-crypto --all-targets --no-deps -- -D warnings
   cargo test -p outline-ws-rust -p outline-tun -p outline-transport -p outline-uplink -p outline-routing -p outline-metrics -p outline-net -p socks5-proto -p shadowsocks-crypto
   ```
3. Никаких деплоев на внешние хосты.
