# Android: локализация EN/RU по системной локали + автоимя сервера + clear в поиске — план

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Android-клиент показывает UI на русском или английском по системной локали телефона (вынос всех строк в ресурсы); при пустом имени сервера оно берётся из `#remark`/hostname ссылки; в поиске Split Tunnel появляется кнопка очистки поля.

**Architecture:** Стандартная Android resource-локализация — `res/values/strings.xml` (EN, fallback) + `res/values-ru/strings.xml` (RU), Compose через `stringResource`, не-Compose через `context.getString`; выбор языка делает система, без рантайм-кода. Presentation-логика (`LinkQuality`/`LinkInfo`) рефакторится на возврат семантики, строки резолвятся в UI. Автоимя и clear-кнопка — точечные правки в `MainActivity`.

**Tech Stack:** Kotlin, Jetpack Compose (Material 3), Android resources/plurals, JUnit (чистый JVM, без Robolectric), Gradle.

## Global Constraints

- **SDK/стек:** `minSdk 24`, `targetSdk 36`, `compileSdk 37`; чистый Compose, **без** `androidx.appcompat`, без `LocaleManager`/`localeConfig`, без ручного переключателя языка.
- **Выбор языка — только система:** `res/values/strings.xml` = английский (дефолт и fallback для любой нерусской локали); `res/values-ru/strings.xml` = русский. Полный паритет ключей.
- **НЕ переводить:** протоколы/carrier (`ss/vless/ws/xhttp/h3/h2/tcp/udp`), RAN (`2G/3G/LTE/5G`), `Wi-Fi`/`Ethernet`, единицы (`B/KB/MB/GB`, `ms`, `s`, формат `hh:mm:ss`), бренд (`Outline`, `Outline Proxy`, `outline-proxy`), имена серверов и версии/commit, OEM-имена пакетов/активити, log-tags, JSON-поля, URL, значения `transport` (`"vless"`/`"ss"`). Числа форматируются на `String.format(Locale.ROOT, …)`.
- **Русский — по правилам `ru-text`** (типографика, короткие UX-формулировки). Закреплённая терминология: `carrier`→«носитель» (не «карьер»), `gate`→«гейт». Перед финалом — прогон `ru-text:ru-check` по обоим фактам перевода.
- **Глоссарий (закреплённые переводы, использовать единообразно):** Connect→Подключить, Disconnect→Отключить, Connected→Подключено, Disconnected→Отключено, Connecting→Подключение, No link→Нет связи, Server→Сервер, Servers→Серверы, Add server→Добавить сервер, Name→Название, Save→Сохранить, Cancel→Отмена, Delete→Удалить, Edit→Изменить, Refresh→Обновить, Later→Позже, Download→Скачать, Allow→Разрешить, Back→Назад, Subscription→Подписка, Active→Активна, Split Tunneling→Раздельный туннель, External Control→Внешнее управление, Keeping Alive→Поддержание связи, Search apps→Поиск приложений, Clear→Очистить, Cellular→Сотовая, Network→Сеть.
- **Верификация каждой задачи со сборкой:** `cd android && ./gradlew :app:testDebugUnitTest` (для задач с unit-тестами) и `./gradlew :app:assembleDebug`; строковые задачи дополнительно `./gradlew :app:lintDebug` (см. Task 3 — `MissingTranslation` fatal). Rust не меняется, но гейт из `AGENTS.md` должен оставаться зелёным: `(cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings)`.
- **Коммиты:** шаги `git commit` в задачах — точки фиксации TDD-цикла. Фактический `git commit` выполнять **только по явному разрешению владельца** (правило репо: не коммитить без команды). До разрешения — `git add` + показать `git diff --staged` и ждать.
- **Тесты рядом с кодом:** `android/app/src/test/java/com/outline/proxy/…` (существующая раскладка проекта).

---

## Порядок и зависимости

F2 (Task 1–2) и F3 (внутри Task 10) независимы от локализации, но `a11y_clear_search` для F3 требует каркас strings (Task 3). Локализация статусов (Task 4) должна идти до/вместе с поверхностными задачами, использующими статусы. Рекомендуемый порядок — как пронумеровано.

---

### Task 1: Хелперы имени сервера (`deriveName`/`remarkOf`/`hostOf`) — F2

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/ServerProfile.kt` (в `companion object`)
- Test: `android/app/src/test/java/com/outline/proxy/ServerNameTest.kt`

**Interfaces:**
- Produces:
  - `ServerProfile.remarkOf(link: String): String?`
  - `ServerProfile.hostOf(link: String): String?`
  - `ServerProfile.deriveName(link: String): String?` = `remarkOf(link) ?: hostOf(link)`

- [ ] **Step 1: Написать падающий тест** — `ServerNameTest.kt`:

```kotlin
package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ServerNameTest {
    @Test fun remarkPreferredPlain() {
        assertEquals("Germany", ServerProfile.deriveName("vless://uuid@de.example.com:443?x=1#Germany"))
    }
    @Test fun remarkPercentDecoded() {
        assertEquals("DE Berlin", ServerProfile.deriveName("vless://uuid@h:443#DE%20Berlin"))
    }
    @Test fun remarkEmojiFlag() {
        assertEquals("🇩🇪", ServerProfile.deriveName("ss://YWVzOnB3@h.example.com:8388#%F0%9F%87%A9%F0%9F%87%AA"))
    }
    @Test fun hostFallbackWhenNoRemark() {
        assertEquals("de.example.com", ServerProfile.deriveName("vless://uuid@de.example.com:443?x=1"))
    }
    @Test fun ssBase64UserinfoHost() {
        assertEquals("h.example.com", ServerProfile.hostOf("ss://YWVzLTI1Ni1nY206cHc@h.example.com:8388"))
    }
    @Test fun httpsSubscriptionHost() {
        assertEquals("sub.example.com", ServerProfile.deriveName("https://sub.example.com/path/cfg?token=abc"))
    }
    @Test fun ipv6Literal() {
        assertEquals("2001:db8::1", ServerProfile.hostOf("vless://uuid@[2001:db8::1]:443"))
    }
    @Test fun trailingPathQueryStripped() {
        assertEquals("h.example.com", ServerProfile.hostOf("https://h.example.com/a/b?q=1"))
    }
    @Test fun garbageIsNull() {
        assertNull(ServerProfile.hostOf("   "))
        assertNull(ServerProfile.remarkOf("vless://uuid@h:443"))
    }
}
```

- [ ] **Step 2: Запустить — убедиться, что падает**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests "com.outline.proxy.ServerNameTest"`
Expected: FAIL — `Unresolved reference: deriveName/hostOf/remarkOf`.

- [ ] **Step 3: Реализовать хелперы** — в `ServerProfile.companion object` добавить:

```kotlin
/** The `#remark` label of a share link, percent-decoded; null when absent/blank. */
fun remarkOf(link: String): String? {
    val hash = link.lastIndexOf('#')
    if (hash < 0 || hash == link.length - 1) return null
    val raw = link.substring(hash + 1)
    val decoded = runCatching {
        java.net.URLDecoder.decode(raw, "UTF-8")
    }.getOrDefault(raw).trim()
    return decoded.ifBlank { null }
}

/** The host of a share link / URL — pure string parse, no android.net.Uri. */
fun hostOf(link: String): String? {
    var s = link.trim()
    if (s.isEmpty()) return null
    val scheme = s.indexOf("://")
    if (scheme >= 0) s = s.substring(scheme + 3)
    // authority ends at the first '/', '?' or '#'
    s = s.takeWhile { it != '/' && it != '?' && it != '#' }
    // drop userinfo (ss:// base64 sits before '@'); take the last '@'
    val at = s.lastIndexOf('@')
    if (at >= 0) s = s.substring(at + 1)
    // IPv6 literal in brackets
    if (s.startsWith("[")) {
        val end = s.indexOf(']')
        if (end > 0) return s.substring(1, end)
    }
    // strip :port
    val colon = s.indexOf(':')
    if (colon >= 0) s = s.substring(0, colon)
    return s.ifBlank { null }
}

/** Name for a server with a blank Name field: the link's remark, else its host. */
fun deriveName(link: String): String? = remarkOf(link) ?: hostOf(link)
```

- [ ] **Step 4: Запустить — убедиться, что проходит**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests "com.outline.proxy.ServerNameTest"`
Expected: PASS (все 9).

- [ ] **Step 5: Зафиксировать** (по разрешению владельца)

```bash
git add android/app/src/main/java/com/outline/proxy/ServerProfile.kt android/app/src/test/java/com/outline/proxy/ServerNameTest.kt
git commit -m "feat(android): derive server name from share-link remark/host"
```

---

### Task 2: Подстановка имени при сохранении сервера — F2

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/MainActivity.kt:629-638` (функция `save()` в `ProfileEditorDialog`)

**Interfaces:**
- Consumes: `ServerProfile.deriveName(link)` из Task 1.

- [ ] **Step 1: Правка `save()`** — заменить сборку `base` на вариант с подстановкой пустого имени:

```kotlin
fun save() {
    // Blank Name → derive from the link the user pasted: its #remark, else host.
    val derivedName = name.ifBlank {
        val src = when {
            configUrl.isNotBlank() -> configUrl
            transport == "vless" -> vlessLink
            else -> ssLink
        }
        ServerProfile.deriveName(src).orEmpty()
    }
    val base = initial.copy(
        name = derivedName,
        transport = transport,
        vlessLink = vlessLink,
        ssLink = ssLink,
        paddingEnabled = paddingEnabled,
        rawTomlOverride = rawOverride,
        configUrl = configUrl.trim(),
    )
    if (!isSubscription) {
        onConfirm(base)
        return
    }
    // ... (остальная подписочная ветка без изменений)
```

- [ ] **Step 2: Сборка**

Run: `cd android && ./gradlew :app:assembleDebug`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Ручная проверка** (эмулятор/устройство): Add server → оставить Name пустым → вставить `vless://…#Test` → Save → в списке сервер называется «Test»; повторить со ссылкой без `#` → имя = hostname; с Config URL → имя = host подписки.

- [ ] **Step 4: Зафиксировать** (по разрешению владельца)

```bash
git add android/app/src/main/java/com/outline/proxy/MainActivity.kt
git commit -m "feat(android): auto-fill blank server name from link"
```

---

### Task 3: Каркас ресурсов строк + lint-паритет + статусы туннеля — F1

**Files:**
- Create: `android/app/src/main/res/values/strings.xml`
- Create: `android/app/src/main/res/values-ru/strings.xml`
- Modify: `android/app/build.gradle.kts` (блок `android { … }` — добавить `lint`)

**Interfaces:**
- Produces: ключи статусов, используемые Task 4/6/14: `status_connecting`, `status_connected`, `status_connected_slow`, `status_no_link`, `status_disconnected`.

- [ ] **Step 1: Создать `res/values/strings.xml`** (английский, стартовый набор — статусы; остальные ключи добавляются поверхностными задачами):

```xml
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <!-- Tunnel status, shared by home screen, notification and QS tile. -->
    <string name="status_connecting">Connecting</string>
    <string name="status_connected">Connected</string>
    <string name="status_connected_slow">Connected · slow</string>
    <string name="status_no_link">No link</string>
    <string name="status_disconnected">Disconnected</string>
</resources>
```

- [ ] **Step 2: Создать `res/values-ru/strings.xml`** (русский, тот же набор ключей):

```xml
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="status_connecting">Подключение</string>
    <string name="status_connected">Подключено</string>
    <string name="status_connected_slow">Подключено · медленно</string>
    <string name="status_no_link">Нет связи</string>
    <string name="status_disconnected">Отключено</string>
</resources>
```

- [ ] **Step 3: Включить lint-паритет переводов** — в `android/app/build.gradle.kts`, внутри `android { … }` добавить:

```kotlin
lint {
    // Keep EN/RU string sets in lockstep: a key present in one file and
    // missing in the other (or extra) fails the build instead of warning.
    fatal += setOf("MissingTranslation", "ExtraTranslation")
}
```

- [ ] **Step 4: Прогнать lint и сборку**

Run: `cd android && ./gradlew :app:lintDebug :app:assembleDebug`
Expected: BUILD SUCCESSFUL, без `MissingTranslation`.

- [ ] **Step 5: Зафиксировать** (по разрешению владельца)

```bash
git add android/app/src/main/res/values/strings.xml android/app/src/main/res/values-ru/strings.xml android/app/build.gradle.kts
git commit -m "feat(android): add EN/RU string resources scaffold with translation lint gate"
```

---

### Task 4: Рефактор `LinkQuality` + перевод статусов у всех потребителей — F1

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/LinkQuality.kt` (убрать строкогенерацию)
- Modify: `android/app/src/main/java/com/outline/proxy/HomeScreen.kt:219-228` (статус на `stringResource`)
- Modify: `android/app/src/main/java/com/outline/proxy/OutlineVpnService.kt` (статусы `Connecting…/No link/Connected/Disconnected` → `getString`)
- Modify: `android/app/src/main/java/com/outline/proxy/OutlineTileService.kt:71` (`Connected`/`Disconnected` → `getString`)
- Modify: `android/app/src/main/java/com/outline/proxy/UiKit.kt:43` (`No link` → `stringResource`, если это статус)
- Modify: `android/app/src/test/java/com/outline/proxy/LinkQualityTest.kt`

**Interfaces:**
- Consumes: `status_*` из Task 3.
- Produces: `LinkQuality.isSlow(latencyMs: Int?): Boolean` остаётся единственным API качества; `connectedLabel` удалён.

- [ ] **Step 1: Обновить тест** `LinkQualityTest.kt` — убрать проверки `connectedLabel`, оставить/добавить проверки `isSlow`:

```kotlin
@Test fun slowAtOrAboveThreshold() {
    assertTrue(LinkQuality.isSlow(1000))
    assertTrue(LinkQuality.isSlow(4200))
}
@Test fun notSlowBelowThresholdOrUnknown() {
    assertFalse(LinkQuality.isSlow(999))
    assertFalse(LinkQuality.isSlow(null))
}
```

- [ ] **Step 2: Запустить — убедиться, что падает** (ссылки на удалённый `connectedLabel` в тесте/коде)

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests "com.outline.proxy.LinkQualityTest"`
Expected: FAIL (компиляция — `connectedLabel` ещё есть/уже нет) или падение старых ассертов.

- [ ] **Step 3: Удалить `connectedLabel`** из `LinkQuality.kt` (оставить `SLOW_LATENCY_MS`, `isSlow`, `worstOf`).

- [ ] **Step 4: Перевести статус в `HomeScreen.StatusCard`** — заменить блок `statusText`:

```kotlin
val statusText = when {
    !connected -> stringResource(R.string.status_disconnected)
    hasLiveLink -> if (LinkQuality.isSlow(linkLatencyMs))
        stringResource(R.string.status_connected_slow)
    else stringResource(R.string.status_connected)
    connecting -> stringResource(R.string.status_connecting) + connectingDots(active = true)
    else -> stringResource(R.string.status_no_link)
}
```

(«Connecting» без многоточия — анимированные точки добавляет `connectingDots`; многоточие в ресурсе не нужно.)

- [ ] **Step 5: Перевести статус в `OutlineVpnService`** — там, где строятся статусы (около строк 646, 810–836): заменить литералы на `getString(R.string.status_disconnected)`, `getString(R.string.status_connecting)`, `getString(R.string.status_no_link)`, а «Connected/Connected · slow» — через `if (LinkQuality.isSlow(latency)) getString(R.string.status_connected_slow) else getString(R.string.status_connected)`. Дефолт параметра `status` в `buildNotification` сменить на вычисление в вызывающих местах (не литерал), либо на `getString(R.string.status_connecting)`.

- [ ] **Step 6: Перевести `OutlineTileService.renderTile`** (строка 71):

```kotlin
tile.subtitle = name ?: getString(if (running) R.string.status_connected else R.string.status_disconnected)
```

- [ ] **Step 7: `UiKit.kt:43`** — если строcovый `"No link"` это статус по умолчанию, заменить на `stringResource(R.string.status_no_link)`; если это иной контекст — оставить на профильную задачу и не трогать здесь.

- [ ] **Step 8: Тесты + сборка + lint**

Run: `cd android && ./gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug`
Expected: PASS/SUCCESSFUL, паритет EN/RU держится.

- [ ] **Step 9: Зафиксировать** (по разрешению владельца)

```bash
git add -A android/app/src/main/java/com/outline/proxy android/app/src/test/java/com/outline/proxy/LinkQualityTest.kt
git commit -m "refactor(android): status via string resources; LinkQuality returns semantics"
```

---

### Task 5: Рефактор `LinkInfo.summary` — переводимые головы в UI — F1

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/LinkInfo.kt`
- Modify: `android/app/src/main/java/com/outline/proxy/HomeScreen.kt:251-258` (сборка summary-строки)
- Modify: `android/app/src/main/res/values/strings.xml`, `values-ru/strings.xml` (+`net_cellular`, `net_network`)
- Modify: `android/app/src/test/java/com/outline/proxy/LinkInfoTest.kt`

**Interfaces:**
- Produces: `LinkInfo.head(link): LinkHead` где `sealed`/enum различает `Wifi`/`Ethernet`/`Ran(label)`/`Cellular`/`Network`/`None`; `LinkInfo.latencyLabel(...)` без изменений.

- [ ] **Step 1: Обновить `LinkInfoTest`** — проверять `head(...)` и `latencyLabel(...)` вместо готовой фразы `summary`. Пример:

```kotlin
@Test fun headCellularWithRan() {
    val l = LinkReadout(LinkTransport.CELLULAR, null, "LTE", 120)
    assertEquals(LinkInfo.Head.Ran("LTE"), LinkInfo.head(l))
}
@Test fun headCellularNoRan() {
    val l = LinkReadout(LinkTransport.CELLULAR, null, null, 120)
    assertEquals(LinkInfo.Head.Cellular, LinkInfo.head(l))
}
@Test fun latencyMsUnderSecond() {
    assertEquals("180 ms", LinkInfo.latencyLabel(180, 10))
}
```

- [ ] **Step 2: Запустить — убедиться, что падает**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests "com.outline.proxy.LinkInfoTest"`
Expected: FAIL — `head`/`Head` не определены.

- [ ] **Step 3: Ввести `Head` и `head(...)` в `LinkInfo`**, оставить `ranLabel`/`latencyLabel`, удалить строкосборку голов из `summary` (сам `summary` заменяется UI-сборкой):

```kotlin
sealed interface Head {
    data object Wifi : Head          // "Wi-Fi" — not translated
    data object Ethernet : Head      // "Ethernet" — not translated
    data class Ran(val label: String) : Head  // "2G/3G/LTE/5G" — not translated
    data object Cellular : Head      // R.string.net_cellular
    data object Network : Head       // R.string.net_network
    data object None : Head
}

fun head(link: LinkReadout?): Head {
    if (link == null || link.transport == LinkTransport.NONE) return Head.None
    return when (link.transport) {
        LinkTransport.WIFI -> Head.Wifi
        LinkTransport.ETHERNET -> Head.Ethernet
        LinkTransport.CELLULAR -> link.ranLabel?.let { Head.Ran(it) } ?: Head.Cellular
        LinkTransport.OTHER -> Head.Network
        LinkTransport.NONE -> Head.None
    }
}
```

- [ ] **Step 4: Сборка summary в `HomeScreen`** — заменить `LinkInfo.summary(link)?.let { summary -> … }` на резолвинг головы через `stringResource` и склейку с `latencyLabel`:

```kotlin
val head = when (val h = LinkInfo.head(link)) {
    LinkInfo.Head.Wifi -> "Wi-Fi"
    LinkInfo.Head.Ethernet -> "Ethernet"
    is LinkInfo.Head.Ran -> h.label
    LinkInfo.Head.Cellular -> stringResource(R.string.net_cellular)
    LinkInfo.Head.Network -> stringResource(R.string.net_network)
    LinkInfo.Head.None -> null
}
val summary = head?.let {
    listOfNotNull(it, LinkInfo.latencyLabel(link?.latencyMs, link?.dialBudgetSecs))
        .joinToString(" · ")
}
summary?.let { /* тот же Text(...) */ }
```

- [ ] **Step 5: Добавить ключи** в оба strings.xml: EN `net_cellular=Cellular`, `net_network=Network`; RU `net_cellular=Сотовая`, `net_network=Сеть`.

- [ ] **Step 6: Тесты + сборка + lint**

Run: `cd android && ./gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug`
Expected: PASS/SUCCESSFUL.

- [ ] **Step 7: Зафиксировать** (по разрешению владельца)

```bash
git add -A android/app/src/main/java/com/outline/proxy android/app/src/test/java/com/outline/proxy/LinkInfoTest.kt android/app/src/main/res
git commit -m "refactor(android): LinkInfo returns Head; localizable link summary in UI"
```

---

### Task 6: Локализация `HomeScreen` (не-статусные строки) — F1

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/HomeScreen.kt`
- Modify: оба `strings.xml`

**Строки → ключи** (EN — из кода; RU по глоссарию + `ru-check`):

| ключ | EN | примечание |
|---|---|---|
| `home_no_server` | No server | |
| `home_add_a_server` | Add a server to begin | |
| `home_subscription` | Subscription | глоссарий: Подписка |
| `home_badge_active` | Active | Активна |
| `home_sub_updated_every` | Updated %1$s · Every %2$dh | format-args |
| `home_transport_none` | (—) | не нужен, `carrierLabel` даёт «—» |
| `btn_add_server` | Add Server | Добавить сервер |
| `btn_connect` | Connect | Подключить |
| `btn_disconnect` | Disconnect | Отключить |
| `home_link_split` | Split Tunneling | Раздельный туннель |
| `home_link_external` | External Control | Внешнее управление |
| `home_link_keepalive` | Keeping Alive | Поддержание связи |
| `stat_duration` | DURATION | Длительность (капс убрать — Compose `letterSpacing` уже задаёт вид; RU без капса) |
| `stat_traffic` | TRAFFIC | Трафик |
| `stat_protocol` | PROTOCOL | Протокол |
| `stat_hhmmss` | hh:mm:ss | НЕ переводить (формат) — оставить литералом |
| `a11y_servers` | Servers | contentDescription |
| `a11y_uploaded` | Uploaded | |
| `a11y_downloaded` | Downloaded | |
| `age_just_now` | just now | только что |
| `age_never` | never | никогда |
| `age_minutes` | %1$dm ago | «%1$d мин назад» |
| `age_hours` | %1$dh ago | «%1$d ч назад» |
| `age_days` | %1$dd ago | «%1$d дн назад» |

- Header `contentDescription = "outline-proxy"` — **бренд, не переводить.**
- `stat_hhmmss` и единицы байт (`B/KB/MB/GB`) — **не переводить**, оставить литералами.

- [ ] **Step 1:** Добавить перечисленные ключи (кроме не-переводимых) в `values/strings.xml` и `values-ru/strings.xml`; RU согласовать с `ru-text:ru-check`.
- [ ] **Step 2:** Заменить литералы в `HomeScreen.kt` на `stringResource(R.string.key)` / `stringResource(R.string.key, arg)`. `ageShort(...)` возвращает готовую строку без Context — переписать так, чтобы Composable-вызыватель передавал `stringResource` (сделать `ageShort` возвращающим тип/пару или принять `Resources`; проще — вынести выбор ключа в Composable и звать `stringResource(id, number)`).
- [ ] **Step 3:** `./gradlew :app:assembleDebug :app:lintDebug` → SUCCESSFUL, паритет держится.
- [ ] **Step 4:** Зафиксировать (по разрешению владельца): `feat(android): localize home screen strings`.

---

### Task 7: Локализация `MainActivity` — список серверов, подписка, меню — F1

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/MainActivity.kt` (экран списка/`ServerRow`/подписка/toast обновления)
- Modify: оба `strings.xml`

**Строки → ключи** (EN из инвентаря строк ~287–606):

| ключ | EN |
|---|---|
| `srv_title` | Servers |
| `srv_add` | Add server |
| `a11y_refresh` | Refresh |
| `a11y_edit` | Edit |
| `a11y_delete` | Delete |
| `srv_toast_config_updated` | Config updated |
| `srv_refresh_failed` | Refresh failed: %1$s |
| `srv_sub_summary` | subscription · %1$s · every %2$dh |
| `srv_no_config_yet` | No config yet — refresh the subscription first. |
| `age_never_updated` | never updated |
| `age_updated_just_now` | updated just now |
| `age_updated_minutes` | updated %1$dm ago |
| `age_updated_hours` | updated %1$dh ago |
| `age_updated_days` | updated %1$dd ago |

- `formatAge`-строки — тот же приём, что в Task 6 (выбор ключа + `getString`/`stringResource`).
- Значения `"vless"`/`"ss"`, `${...REFRESH_PERIOD_HOURS}` — **не переводить**.

- [ ] **Step 1:** Ключи в оба strings.xml (RU + `ru-check`).
- [ ] **Step 2:** Замена литералов на ресурсы (Compose — `stringResource`; тосты — `context.getString`).
- [ ] **Step 3:** `./gradlew :app:assembleDebug :app:lintDebug` → SUCCESSFUL.
- [ ] **Step 4:** Зафиксировать (по разрешению): `feat(android): localize server list & subscription strings`.

---

### Task 8: Локализация `ProfileEditorDialog` — F1

**Files:** `MainActivity.kt:666-734`; оба `strings.xml`.

| ключ | EN |
|---|---|
| `dlg_server_title` | Server |
| `dlg_name` | Name |
| `dlg_config_url` | Config URL (subscription) |
| `dlg_config_url_help` | HTTPS link to a ready client config; fetched and refreshed automatically. |
| `dlg_transport_vless` | VLESS |
| `dlg_transport_ss` | Shadowsocks |
| `dlg_vless_link` | vless:// share link |
| `dlg_ss_link` | ss:// share link |
| `dlg_padding` | Padding |
| `dlg_raw_toml` | Raw TOML override (optional) |
| `dlg_fetching` | Fetching… |
| `btn_save` | Save |
| `btn_cancel` | Cancel |
| `dlg_could_not_fetch` | Could not fetch: %1$s |

- `"vless"`/`"ss"` (значения `transport`), `vless://`/`ss://` в лейблах — префиксы схем оставить как есть внутри строки (переводится обрамление, схема — литерал внутри значения).

- [ ] Ключи → замена → `assembleDebug`/`lintDebug` → commit `feat(android): localize server editor dialog` (по разрешению).

---

### Task 9: Локализация диалога обновления + reason-строки `UpdateChecker` — F1

**Files:** `MainActivity.kt:341-421`; `UpdateChecker.kt` (человекочитаемые reason'ы); оба `strings.xml`.

| ключ | EN |
|---|---|
| `upd_available` | Update available |
| `upd_apk_note` | The APK downloads to your Downloads folder; open it to install — the app does not install it for you. |
| `upd_download` | Download |
| `upd_later` | Later |
| `upd_checking` | checking… |
| `upd_up_to_date` | up to date |
| `upd_check_failed` | check failed: %1$s |
| `upd_downloading_pct` | downloading %1$d%% |
| `upd_downloaded_tap` | downloaded — tap to install |
| `upd_download_failed` | download failed: %1$s |

- **Не переводить** в `UpdateChecker.kt`: URL, `tag_name`/JSON-поля, `HTTP $code`, log-tags, `nightly · $sha`, MIME-типы, диагностические строки, которые не доходят до пользователя. Перевести только человекочитаемые reason'ы, реально показываемые как `%1$s` выше (напр. `update check failed`→«не удалось проверить обновление», `no APK in the nightly release`→«в сборке нет APK»). Пограничные — оставить EN, если это чисто диагностика.

- [ ] Ключи → замена → `assembleDebug`/`lintDebug` → commit `feat(android): localize update dialog & checker reasons` (по разрешению).

---

### Task 10: Локализация Split-tunnel screen + кнопка очистки поиска — F1 + F3

**Files:** `MainActivity.kt:770-926` (`SplitTunnelScreen`); оба `strings.xml`. Иконка: `androidx.compose.material.icons.filled.Clear`.

**F3 — clear-кнопка.** В `OutlinedTextField` поиска (строки 807-815) добавить `trailingIcon`, видимую только при непустом запросе:

```kotlin
OutlinedTextField(
    value = query,
    onValueChange = { query = it },
    singleLine = true,
    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
    trailingIcon = {
        if (query.isNotEmpty()) {
            IconButton(onClick = { query = "" }) {
                Icon(Icons.Filled.Clear, contentDescription = stringResource(R.string.a11y_clear_search))
            }
        }
    },
    placeholder = { Text(stringResource(R.string.split_search)) },
    shape = RoundedCornerShape(16.dp),
    modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
)
```

Добавить импорты: `androidx.compose.material.icons.filled.Clear`, `androidx.compose.material3.IconButton` (проверить наличие — `IconButton` уже используется).

**Строки → ключи:**

| ключ | EN |
|---|---|
| `split_title` | Split Tunneling |
| `split_mode_all` | All apps |
| `split_mode_only` | Only selected apps |
| `split_mode_except` | All apps except selected |
| `split_desc_all` | Every app's traffic goes through the tunnel. |
| `split_desc_allow` | Only the checked apps are tunneled; everything else uses the direct connection. |
| `split_desc_deny` | The checked apps bypass the tunnel; everything else is tunneled. |
| `split_loading_apps` | Loading apps… |
| `split_search` | Search apps |
| `a11y_clear_search` | Clear |

- [ ] **Step 1:** Ключи в оба strings.xml (RU: `a11y_clear_search`=Очистить, `split_search`=Поиск приложений, и т.д. + `ru-check`).
- [ ] **Step 2:** Внести `trailingIcon` (F3) + заменить литералы на ресурсы.
- [ ] **Step 3:** `./gradlew :app:assembleDebug :app:lintDebug` → SUCCESSFUL.
- [ ] **Step 4:** Ручная проверка: ввести текст в поиск → появляется крестик → тап очищает поле и сбрасывает фильтр.
- [ ] **Step 5:** Зафиксировать (по разрешению): `feat(android): localize split tunnel & add search clear button`.

---

### Task 11: Локализация External Control screen — F1

**Files:** `MainActivity.kt:879-926`; оба `strings.xml`.

| ключ | EN |
|---|---|
| `ext_title` | External Control |
| `ext_allow_commands` | Allow outline:// commands |
| `ext_token` | Token (optional) |
| `ext_token_help` | When set, commands without a matching ?token= are ignored. |
| `ext_supported_commands` | Supported commands |
| `ext_must_exist` | must already exist in the list. |

- `outline://`, `?token=` внутри строк — оставить как есть (часть значения).

- [ ] Ключи → замена → `assembleDebug`/`lintDebug` → commit `feat(android): localize external control screen` (по разрешению).

---

### Task 12: Локализация `KeepAliveScreen` — F1

**Files:** `android/app/src/main/java/com/outline/proxy/KeepAliveScreen.kt`; оба `strings.xml`.

**Строки → ключи** (EN из инвентаря 64–310; длинные описания перевести по `ru-text`):

| ключ | EN |
|---|---|
| `ka_title` | Keeping Alive |
| `ka_persistent_notif` | Persistent notification |
| `ka_persistent_notif_desc` | Keep a notification with a Connect/Disconnect button in the status bar, even when the VPN is off. |
| `ka_qs_tile` | Quick Settings tile |
| `ka_qs_tile_desc` | Toggle the tunnel straight from the Quick Settings panel. |
| `ka_add_tile` | Add tile |
| `ka_intro` | Android and the phone vendor may stop background apps. These switches are what keeps the tunnel up. |
| `ka_always_on` | Always-on VPN |
| `ka_always_on_desc` | The strongest option: the system itself keeps the tunnel up and restarts it. Turn on “Always-on VPN”. |
| `ka_open_vpn_settings` | Open VPN settings |
| `ka_ignore_batt` | Ignore battery optimisation |
| `ka_ignore_batt_desc` | Without it Android may stop the tunnel in the background and refuse to let the watchdog restart it. |
| `ka_exact_alarms` | Exact alarms |
| `ka_exact_alarms_desc` | The watchdog checks the tunnel through Doze. Without this permission the checks are delayed by the system. |
| `ka_notifications` | Notifications |
| `ka_notifications_desc` | The tunnel runs as a foreground service. A hidden notification makes some firmware more eager to kill it. |
| `ka_network_type` | Network type |
| `ka_network_type_desc` | Optional. Lets the home screen name the radio technology … the dial timeouts are sized from the speed estimate either way. |
| `ka_vendor_autostart_desc` | …background. There is no API to read it — open the screen and allow Outline Proxy there. |
| `ka_open_vendor_settings` | Open %1$s settings |
| `ka_status_allowed` | Allowed |
| `ka_status_needs_action` | Needs action |
| `ka_status_check_manually` | Check manually |
| `btn_allow` | Allow |
| `ka_add_tile_hint` | Open Quick Settings, tap edit (pencil), and add the Outline tile. |

- `"Outline"`/`"Outline Proxy"` внутри строк и `$vendor` — **бренд/подстановка, не переводить** (в `ka_open_vendor_settings` — `%1$s`).

- [ ] Ключи → замена → `assembleDebug`/`lintDebug` → `ru-check` длинных описаний → commit `feat(android): localize keep-alive screen` (по разрешению).

---

### Task 13: Локализация Toast-сообщений (`ControlActivity`, `QuickConnectActivity`) — F1

**Files:** `ControlActivity.kt`, `QuickConnectActivity.kt`; оба `strings.xml`. Контекст есть → `context.getString`.

| ключ | EN |
|---|---|
| `ctl_vpn_denied` | VPN permission denied |
| `ctl_no_server` | No server configured |
| `ctl_unknown_server` | Unknown server: %1$s |
| `ctl_refused` | external control refused: %1$s |
| `ctl_not_command` | Not an outline:// command |
| `ctl_unknown_command` | Unknown outline:// command |
| `ctl_disabled` | External control is disabled in Outline Proxy |
| `ctl_wrong_token` | External control: wrong token |
| `ctl_no_config_yet` | No config yet — refresh the subscription first. |

- Log-tags (`"OutlineControl"`), `"false"`, `outline://` — **не переводить**. `ctl_no_config_yet` совпадает с `srv_no_config_yet` — переиспользовать один ключ (DRY): оставить `srv_no_config_yet`.

- [ ] Ключи → замена → `assembleDebug`/`lintDebug` → commit `feat(android): localize control/quick-connect toasts` (по разрешению).

---

### Task 14: Локализация нотификаций и QS-tile — F1

**Files:** `OutlineVpnService.kt` (каналы, `alert(...)`, action-labels, body), `OutlineTileService.kt`; оба `strings.xml`. Контекст есть → `getString`.

| ключ | EN |
|---|---|
| `notif_channel_status` | VPN status |
| `notif_channel_alerts` | VPN alerts |
| `notif_alert_cannot_start_title` | Tunnel cannot start |
| `notif_alert_cannot_start_text` | Open Outline Proxy and connect again. |
| `notif_action_connect` | Connect |
| `notif_action_disconnect` | Disconnect |
| `notif_body_subscription` | Subscription |

- Статусы в title (`status_*`) уже локализованы в Task 4. `notif_action_connect/disconnect` можно объединить с `btn_connect/btn_disconnect` (DRY) — если формулировка совпадает, переиспользовать `btn_connect`/`btn_disconnect`.
- `OutlineTileService`: `tile.label = "Outline"` — **бренд, не переводить**; subtitle-статусы уже сделаны в Task 4.
- `.setSession("Outline Proxy")` — **бренд, не переводить.** «Outline Proxy» в `notif_alert_cannot_start_text` — оставить брендом внутри строки.

- [ ] Ключи → замена → `assembleDebug`/`lintDebug` → commit `feat(android): localize service notifications & tile` (по разрешению).

---

### Task 15: Финальная верификация, документация, качество русского

**Files:**
- Modify: `android/CHANGELOG.md`, `android/CHANGELOG.ru.md`
- Возможные мелкие правки переводов по итогам `ru-check`.

- [ ] **Step 1: Полная сборка/тесты/lint**

Run: `cd android && ./gradlew :app:testDebugUnitTest :app:assembleDebug :app:lintDebug`
Expected: всё зелёное; `MissingTranslation`/`ExtraTranslation` — ноль (паритет EN/RU).

- [ ] **Step 2: Гейт `android/rust`** (Rust не меняли, должен остаться зелёным)

Run: `cd android/rust && cargo fmt --check && cargo clippy --no-deps -- -D warnings`
Expected: чисто.

- [ ] **Step 3: `ru-check`** — прогнать `ru-text:ru-check` по содержимому `values-ru/strings.xml`; исправить типографику/формулировки; повторить `lintDebug`.

- [ ] **Step 4: Ручная проверка в эмуляторе (JDK 17 liberica)** — Settings → System → Languages: поставить **Русский**, запустить приложение → главный экран, диалоги сервера, Split Tunnel (в т.ч. крестик очистки), External Control, Keep Alive, шторка-нотификация, QS-tile — всё по-русски; переключить на **English** → всё по-английски; локаль вне RU/EN (напр. Deutsch) → английский. Проверить автоимя сервера (Task 2) в обеих локалях.

- [ ] **Step 5: CHANGELOG (EN + RU параллельно).**
  - `android/CHANGELOG.md`: `Localization: UI follows the phone language (English/Russian).`, `Server name auto-fills from the link's remark or hostname when left blank.`, `Split Tunnel search has a clear button.`
  - `android/CHANGELOG.ru.md`: «Локализация: язык интерфейса следует за языком телефона (английский/русский).», «Имя сервера подставляется из метки или хоста ссылки, если оставить поле пустым.», «В поиске раздельного туннеля появилась кнопка очистки.»

- [ ] **Step 6: Зафиксировать** (по разрешению владельца)

```bash
git add android/CHANGELOG.md android/CHANGELOG.ru.md android/app/src/main/res
git commit -m "docs(android): changelog for localization and UX tweaks"
```

---

## Self-Review (выполнено при написании плана)

- **Покрытие спек:** локализация — все поверхности из спеки (Home, MainActivity-диалоги/список/update/split/external, KeepAlive, нотификации, tile, toasts, UpdateChecker) в Task 4–14; рефакторы `LinkQuality`/`LinkInfo` — Task 4–5; инфраструктура/lint-паритет — Task 3; plurals-политика (сокращённые единицы без склонений) — Task 6/7. Автоимя (`deriveName`=remark→host) — Task 1–2. Clear-кнопка — Task 10. CHANGELOG EN/RU + `ru-check` — Task 15.
- **Плейсхолдеры:** переводы RU для длинных описаний создаёт исполнитель по глоссарию + `ru-text:ru-check` (контент, не код) — EN-исходники и ключи заданы явно; весь код (хелперы, save, trailingIcon, рефакторы, lint-блок) приведён полностью.
- **Согласованность типов:** `deriveName/remarkOf/hostOf` (Task 1) — единые сигнатуры; `LinkQuality.isSlow` (Task 4) и `LinkInfo.Head`/`head` (Task 5) согласованы с потребителями; общие ключи (`btn_connect`/`btn_disconnect`, `srv_no_config_yet`) переиспользуются (DRY).
