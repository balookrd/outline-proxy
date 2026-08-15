# План: подписка на конфиг по URL (Android)

> **Для агентов-исполнителей:** ОБЯЗАТЕЛЬНЫЙ САБ-СКИЛЛ: superpowers:executing-plans
> или superpowers:subagent-driven-development. Шаги размечены чекбоксами.

**Цель:** профиль берёт свой TOML из HTTPS-URL — скачивает при добавлении,
обновляет в фоне (12 ч), переживает недоступность источника кэшем.

**Архитектура:** `configUrl`+`cachedToml` в `ServerProfile`; `ConfigFetcher`
(HTTPS + валидация) качает; `SubscriptionWorker` (WorkManager) обновляет кэш по
расписанию; форма/список показывают URL, статус и ручное обновление.

Спека: [2026-08-15-android-config-subscription-design.md](../specs/2026-08-15-android-config-subscription-design.md)

## Глобальные ограничения

- `minSdk = 24`, JDK 17 (`JAVA_HOME=~/Library/Java/JavaVirtualMachines/liberica-17.0.20`).
- Комментарии/коммиты — по-английски; общение/спеки — по-русски.
- Не логировать URL целиком (секретный токен в пути) — маскировать.
- Не коммитить без явной команды владельца.
- Тесты — `app/src/test/java/com/outline/proxy/`, JUnit 4, стиль `ExternalControlTest`.

## Файлы

- Изменить: `ServerProfile.kt` (поля + приоритет `toToml`)
- Создать: `ConfigFetcher.kt` (`ConfigValidation`, `ConfigFetcher`, `FetchResult`)
- Создать: `SubscriptionWorker.kt`
- Изменить: `MainActivity.kt` (форма + карточка + фоновая регистрация)
- Изменить: `build.gradle.kts` (WorkManager, если ещё не добавлен)
- Тесты: `ConfigValidationTest.kt`, `SubscriptionProfileTest.kt`

---

### Задача 1: ServerProfile — configUrl + кэш (TDD)

- [ ] **Тест** `SubscriptionProfileTest.kt`: `toToml()` при `configUrl` отдаёт
  `cachedToml` (приоритет над `rawTomlOverride` и полями); JSON round-trip новых
  полей; `isSubscription` = `configUrl.isNotBlank()`.
- [ ] Прогнать — падает.
- [ ] Добавить в `ServerProfile` поля `configUrl`, `cachedToml`, `updatedAt`,
  свойство `isSubscription`, ветку в `toToml()`, сериализацию в `toJson`/`fromJson`.
- [ ] Прогнать — зелено.

### Задача 2: ConfigFetcher + валидация (TDD чистой части)

- [ ] **Тест** `ConfigValidationTest.kt`: `looksLikeConfig` = true на реальном
  `alice.toml`-фрагменте (`[tun]`/`[[outline.uplinks]]`), false на HTML, пустом,
  случайном тексте.
- [ ] Прогнать — падает.
- [ ] Создать `ConfigFetcher.kt`: `ConfigValidation.looksLikeConfig`,
  `FetchResult { Success(toml) | Failure(reason) }`,
  `suspend ConfigFetcher.fetch(url): FetchResult` (HTTPS-only, `HttpURLConnection`,
  таймауты, лимит 200 КБ, валидация, маскирующее логирование).
- [ ] Прогнать — зелено.

### Задача 3: SubscriptionWorker + WorkManager

- [ ] Добавить `androidx.work:work-runtime-ktx:2.11.0` в `build.gradle.kts`
  (если keep-alive ещё не добавил).
- [ ] Создать `SubscriptionWorker.kt`: periodic 12 ч, тег `outline-subscription`,
  для каждого профиля с `configUrl` — `fetch`, при `Success` перезаписать кэш +
  `updatedAt`, при `Failure` — оставить. `schedule(context)`/`cancel(context)`.
- [ ] Собрать.

### Задача 4: UI — форма и карточка

- [ ] В `ProfileEditorDialog` добавить поле «Config URL (subscription)»; при
  непустом — скрыть vless/ss/transport, показать пояснение. Сохранение подписки
  запускает `fetch` с индикатором; ошибка при пустом кэше не даёт сохранить.
- [ ] В `ProfileCard` для подписки показать «updated N h ago / never» + кнопку
  refresh (немедленный `fetch`, обновляет кэш через `onSave`).
- [ ] Зарегистрировать `SubscriptionWorker.schedule` при наличии подписок,
  `cancel` — когда их нет (в `persist()` MainActivity).
- [ ] Connect при пустом кэше подписки — предупредить (проверка в `onConnect`).
- [ ] Собрать + тесты.

### Задача 5: Сборка и устройство

- [ ] `assembleDebug` + `testDebugUnitTest` — зелено.
- [ ] `installDebug`, добавить профиль с реальным URL `alice.toml`, убедиться в
  скачивании (logcat), подключиться, проверить кнопку refresh.
- [ ] Синтетика: `http://`-URL отклонён; URL на не-TOML → кэш цел.
- [ ] Обновить README EN+RU (раздел про подписку и что проверено).

## Самопроверка

Покрытие спеки: модель (1), fetcher+валидация (2), worker/расписание (3),
UI+статус+refresh+connect-guard (4), устройство+доки (5). Безопасность (HTTPS,
маскирование) — в задаче 2. Пересечение с keep-alive (WorkManager) — задача 3.
Имена: `ConfigFetcher.fetch`, `FetchResult`, `ConfigValidation.looksLikeConfig`,
`ServerProfile.isSubscription`/`cachedToml`/`configUrl`/`updatedAt`,
`SubscriptionWorker.schedule/cancel` — сквозные.
