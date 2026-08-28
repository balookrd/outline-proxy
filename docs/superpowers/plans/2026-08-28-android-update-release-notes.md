# Release notes in the Android update dialog — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** При найденном обновлении диалог «Доступно обновление» показывает блок «Что нового» — описание изменений предлагаемой версии, взятое из тела GitHub-релиза как есть.

**Architecture:** Тело релиза (`body`) уже приходит в ответе GitHub API, который парсит `UpdateChecker`, — доносим его через `Result.Available.notes`. Чистый Kotlin-хелпер `ReleaseNotes.format()` превращает Markdown-тело в плоский `List<NoteLine>` (тестируется на JVM, без Compose); диалог рендерит его со скроллом, а на пустом/мусорном теле блок отсутствует и диалог выглядит как прежде.

**Tech Stack:** Kotlin, Jetpack Compose (Material3), JUnit4, `org.json`, AGP 9 built-in Kotlin.

**Design doc:** `docs/superpowers/specs/2026-08-28-android-update-release-notes-design.md`

## Global Constraints

- Комментарии в коде, commit-сообщения и PR — на английском; чат и рассуждения — на русском.
- Никогда не добавлять трейлер `Co-Authored-By: Claude` и футер «Generated with Claude Code» ни к чему.
- Коммитить каждую задачу, когда её гейт зелёный, сообщением из последнего шага задачи. **Никогда не `git push`** — это отдельная явная команда владельца каждый раз.
- Работать прямо в `main`. Не создавать feature-ветки.
- **CI/git-cliff в этой задаче не трогаем.** Тело релиза берём как есть; на сегодняшнем теле срабатывает фоллбэк (блока «Что нового» нет).
- **Без Markdown-библиотек** — своя лёгкая чистка (в проекте строгий R8).
- **Содержимое release notes не переводим** — английское; локализуем только заголовок секции.
- **EN/RU-паритет строк обязателен**: `:app:lintDebug` включает `MissingTranslation`/`ExtraTranslation` как `fatal` — любой новый ключ добавляется в оба `strings.xml` в одном изменении.
- Android-приложение — отдельный Gradle-проект в `android/`; команды гейта гоняются из `android/`. **JDK 17 обязателен** — этот хост несёт liberica-17 (Android Studio JBR здесь = openjdk 25, а он ломает Gradle):
  ```bash
  export JAVA_HOME="$HOME/Library/Java/JavaVirtualMachines/liberica-17.0.20.1"
  ```
  `:app:testDebugUnitTest` и `:app:lintDebug` не требуют собранного `.so`.

---

## File Structure

- `android/app/src/main/java/com/outline/proxy/ReleaseNotes.kt` (**создать**) — `NoteLine` (Header/Bullet/Text) + `ReleaseNotes.format(raw): List<NoteLine>`. Единственное место с логикой чистки Markdown; не зависит от Compose/Android.
- `android/app/src/test/java/com/outline/proxy/ReleaseNotesTest.kt` (**создать**) — JVM unit-тест хелпера.
- `android/app/src/main/java/com/outline/proxy/UpdateChecker.kt` (**изменить**) — `+notes` в `Result.Available`; чтение `release.optString("body")` в двух ветках.
- `android/app/src/main/res/values/strings.xml` (**изменить**) — `upd_whats_new` (EN).
- `android/app/src/main/res/values-ru/strings.xml` (**изменить**) — `upd_whats_new` (RU).
- `android/app/src/main/java/com/outline/proxy/MainActivity.kt` (**изменить**) — блок «Что нового» в `AlertDialog` + фоллбэк.
- `android/CHANGELOG.md` / `android/CHANGELOG.ru.md` (**изменить**) — запись в `[Unreleased]`.

---

### Task 1: `ReleaseNotes` — чистка Markdown-тела (TDD, чистый JVM)

**Files:**
- Create: `android/app/src/main/java/com/outline/proxy/ReleaseNotes.kt`
- Test: `android/app/src/test/java/com/outline/proxy/ReleaseNotesTest.kt`

**Interfaces:**
- Produces:
  - `sealed interface NoteLine` с `data class Header(val text: String)`, `data class Bullet(val text: String)`, `data class Text(val text: String)`.
  - `object ReleaseNotes { fun format(raw: String): List<NoteLine> }` — пустой список, когда показывать нечего (нет ни одного `Header`/`Bullet`).

- [ ] **Step 1: Написать падающий тест**

Create `android/app/src/test/java/com/outline/proxy/ReleaseNotesTest.kt`:
```kotlin
package com.outline.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ReleaseNotesTest {
    @Test
    fun `git-cliff body yields clean headers and bullets`() {
        val body = """
            ## What's Changed in android-v1.3.0

            ### ⭐ Features
            - **android**: Localize UI by system locale
            - **android**: Persistent notification you can keep

            ### 🐛 Bug Fixes
            - **android**: Keep the session traffic counter

            **Full Changelog**: https://github.com/balookrd/outline-proxy/compare/android-v1.2.0...android-v1.3.0
        """.trimIndent()

        val out = ReleaseNotes.format(body)

        assertEquals(
            listOf(
                NoteLine.Header("⭐ Features"),
                NoteLine.Bullet("android: Localize UI by system locale"),
                NoteLine.Bullet("android: Persistent notification you can keep"),
                NoteLine.Header("🐛 Bug Fixes"),
                NoteLine.Bullet("android: Keep the session traffic counter"),
            ),
            out,
        )
        assertTrue(out.none { lineText(it).contains("**") })
        assertTrue(out.none { lineText(it).contains("#") })
    }

    @Test
    fun `breaking section is preserved`() {
        val body = """
            ## What's Changed in ss-v2.0.0

            ### ⚠️ BREAKING CHANGES
            - **config**: Remove per-user carrier paths
        """.trimIndent()

        val out = ReleaseNotes.format(body)

        assertEquals(NoteLine.Header("⚠️ BREAKING CHANGES"), out.first())
        assertTrue(out.contains(NoteLine.Bullet("config: Remove per-user carrier paths")))
    }

    @Test
    fun `body with only the compare link falls back to empty`() {
        val body =
            "**Full Changelog**: https://github.com/balookrd/outline-proxy/compare/ui-nightly...android-v1.2.0"
        assertEquals(emptyList<NoteLine>(), ReleaseNotes.format(body))
    }

    @Test
    fun `empty body is empty`() {
        assertEquals(emptyList<NoteLine>(), ReleaseNotes.format(""))
    }

    @Test
    fun `scope bold is stripped from a bullet`() {
        assertEquals(
            listOf(NoteLine.Bullet("uplink: Base status latency on round-trip")),
            ReleaseNotes.format("- **uplink**: Base status latency on round-trip"),
        )
    }

    private fun lineText(line: NoteLine): String = when (line) {
        is NoteLine.Header -> line.text
        is NoteLine.Bullet -> line.text
        is NoteLine.Text -> line.text
    }
}
```

- [ ] **Step 2: Прогнать тест — убедиться, что падает**

Run:
```bash
export JAVA_HOME="$HOME/Library/Java/JavaVirtualMachines/liberica-17.0.20.1"
cd android && ./gradlew :app:testDebugUnitTest --tests "com.outline.proxy.ReleaseNotesTest"
```
Expected: FAIL — компиляция не проходит, `unresolved reference: ReleaseNotes` / `NoteLine`.

- [ ] **Step 3: Реализовать `ReleaseNotes.kt`**

Create `android/app/src/main/java/com/outline/proxy/ReleaseNotes.kt`:
```kotlin
package com.outline.proxy

/** One rendered line of cleaned-up release notes. */
sealed interface NoteLine {
    /** A section heading, rendered bold (e.g. "⭐ Features"). */
    data class Header(val text: String) : NoteLine

    /** A list item, rendered with a "•" marker. */
    data class Bullet(val text: String) : NoteLine

    /** A plain paragraph line. */
    data class Text(val text: String) : NoteLine
}

/**
 * Turns a GitHub release body (Markdown, as produced by git-cliff) into a flat
 * list of displayable lines for the update dialog.
 *
 * Deliberately a tiny, forgiving cleaner rather than a Markdown parser: the
 * dialog only ever shows a short changelog, and a real Markdown dependency would
 * cost R8 keep-rules the app does not want. Anything it does not recognise falls
 * through to [NoteLine.Text] unharmed.
 *
 * Returns an empty list when there is nothing user-facing to show — an empty
 * body, a nightly with no notes, or a body that is only the "Full Changelog"
 * link — so the caller can fall back to the plain dialog.
 */
object ReleaseNotes {
    fun format(raw: String): List<NoteLine> {
        val lines = mutableListOf<NoteLine>()
        for (rawLine in raw.lineSequence()) {
            val line = rawLine.trim()
            when {
                line.isEmpty() -> continue
                // "### ⭐ Features" -> Header("⭐ Features"). Checked before the
                // level-2 rule so a level-3 heading is never mistaken for it.
                line.startsWith("### ") ->
                    lines += NoteLine.Header(stripInline(line.removePrefix("### ")))
                // "## What's Changed in <tag>" duplicates the dialog title; drop
                // any level-2 heading.
                line.startsWith("## ") -> continue
                // Technical compare link, not a user-facing change.
                line.startsWith("**Full Changelog**") -> continue
                // "- **scope**: msg" / "* msg" -> Bullet.
                line.startsWith("- ") || line.startsWith("* ") ->
                    lines += NoteLine.Bullet(stripInline(line.drop(2)))
                else -> lines += NoteLine.Text(stripInline(line))
            }
        }
        // Nothing structured survived: signal the caller to fall back.
        return if (lines.any { it is NoteLine.Header || it is NoteLine.Bullet }) lines else emptyList()
    }

    /** Strip the only inline markup git-cliff emits: bold `**…**`. */
    private fun stripInline(s: String): String = s.replace("**", "").trim()
}
```

- [ ] **Step 4: Прогнать тест — убедиться, что зелёный**

Run:
```bash
export JAVA_HOME="$HOME/Library/Java/JavaVirtualMachines/liberica-17.0.20.1"
cd android && ./gradlew :app:testDebugUnitTest --tests "com.outline.proxy.ReleaseNotesTest"
```
Expected: PASS — все пять тестов зелёные.

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/java/com/outline/proxy/ReleaseNotes.kt \
        android/app/src/test/java/com/outline/proxy/ReleaseNotesTest.kt
git commit -m "feat(android): add a release-notes markdown cleaner"
```

---

### Task 2: Пронести `body` в диалог обновления

**Files:**
- Modify: `android/app/src/main/java/com/outline/proxy/UpdateChecker.kt` (`Result.Available` line 49; `checkNightly` line 83; `checkRelease` lines 112-116)
- Modify: `android/app/src/main/res/values/strings.xml` (after line 97)
- Modify: `android/app/src/main/res/values-ru/strings.xml` (after line 82)
- Modify: `android/app/src/main/java/com/outline/proxy/MainActivity.kt` (dialog `text` block lines 402-408; imports near line 22)
- Modify: `android/CHANGELOG.md` / `android/CHANGELOG.ru.md` (`[Unreleased]` → `### Added`)

**Interfaces:**
- Consumes: `ReleaseNotes.format(raw): List<NoteLine>` and `NoteLine.{Header,Bullet,Text}` from Task 1.
- Produces: `Result.Available(label, assetName, url, notes)` — a fourth `notes: String` field.

> Нет TDD-цикла: логика чистки уже покрыта Task 1. Здесь — проводка данных (сеть) и Compose-UI, которые в этом проекте юнит-тестами не покрываются (`org.json`/`HttpURLConnection` и Compose). Гейт задачи — компиляция Kotlin, зелёные существующие тесты и `lintDebug`-паритет; визуальная проверка диалога — опциональна (см. Step 6).

- [ ] **Step 1: `UpdateChecker` — добавить поле и читать `body`**

In `UpdateChecker.kt`, replace the `Available` declaration (line 49):
```kotlin
        /** A newer build exists; [label] names it the way its channel does. */
        data class Available(
            val label: String,
            val assetName: String,
            val url: String,
            /** Raw GitHub release body (Markdown); "" when the release has none. */
            val notes: String,
        ) : Result
```

In `checkNightly()`, replace the `Available` return (line 83):
```kotlin
            Result.Available(
                "nightly · $sha",
                name,
                asset.getString("browser_download_url"),
                release.optString("body"),
            )
```

In `checkRelease()`, replace the `Available` return (lines 112-116):
```kotlin
        return Result.Available(
            "v${release.optString("tag_name").removePrefix(RELEASE_TAG_PREFIX)}",
            asset.getString("name"),
            asset.getString("browser_download_url"),
            release.optString("body"),
        )
```
`optString` returns `""` when `body` is absent or JSON `null`, so nightly-without-notes is a plain empty string — no null-handling needed downstream.

- [ ] **Step 2: Добавить строку `upd_whats_new` (EN + RU)**

In `android/app/src/main/res/values/strings.xml`, after `upd_apk_note` (line 97):
```xml
    <string name="upd_whats_new">What\'s new</string>
```

In `android/app/src/main/res/values-ru/strings.xml`, after `upd_apk_note` (line 82):
```xml
    <string name="upd_whats_new">Что нового</string>
```
(Apostrophe in the EN value must be escaped as `\'` — an unescaped `'` is an Android resource error.)

- [ ] **Step 3: Добавить импорты в `MainActivity.kt`**

Add these five imports (the dialog uses them; the rest — `Column`, `padding`, `remember`, `Modifier`, `FontWeight`, `dp` — are already imported). Place them in alphabetical position among the existing `androidx.compose.foundation.*` imports (around lines 12-27):
```kotlin
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
```

- [ ] **Step 4: Отрендерить блок «Что нового» в диалоге**

In `MainActivity.kt`, replace the dialog `text` block (lines 402-408):
```kotlin
                        text = {
                            val notes = remember(available) { ReleaseNotes.format(available.notes) }
                            Column {
                                Text(stringResource(R.string.upd_published_for_channel, available.label))
                                if (notes.isNotEmpty()) {
                                    Spacer(Modifier.height(12.dp))
                                    Text(
                                        stringResource(R.string.upd_whats_new),
                                        fontWeight = FontWeight.Bold,
                                    )
                                    Spacer(Modifier.height(4.dp))
                                    // A long body scrolls inside the dialog instead of
                                    // pushing the buttons off-screen.
                                    Column(
                                        Modifier
                                            .heightIn(max = 260.dp)
                                            .verticalScroll(rememberScrollState()),
                                    ) {
                                        notes.forEach { line ->
                                            when (line) {
                                                is NoteLine.Header -> Text(
                                                    line.text,
                                                    fontWeight = FontWeight.Bold,
                                                    modifier = Modifier.padding(top = 8.dp, bottom = 2.dp),
                                                )
                                                is NoteLine.Bullet -> Text("•  ${line.text}")
                                                is NoteLine.Text -> Text(line.text)
                                            }
                                        }
                                    }
                                }
                                Spacer(Modifier.height(12.dp))
                                Text(stringResource(R.string.upd_apk_note))
                            }
                        },
```

- [ ] **Step 5: Прогнать гейт — компиляция, тесты, паритет строк**

Run:
```bash
export JAVA_HOME="$HOME/Library/Java/JavaVirtualMachines/liberica-17.0.20.1"
cd android && ./gradlew :app:compileDebugKotlin :app:testDebugUnitTest :app:lintDebug
```
Expected: BUILD SUCCESSFUL — Kotlin компилируется (сигнатура `Available` сошлась во всех вызовах), все unit-тесты зелёные, `lintDebug` без `MissingTranslation`/`ExtraTranslation` (обе стороны `upd_whats_new` на месте).

- [ ] **Step 6: (опционально) Визуальная проверка диалога**

Требует собранного `.so` (`./build-rust.sh`, нужен NDK) и устройства/эмулятора. Если среда готова: `./gradlew :app:assembleDebug`, установить, временно указать `UpdateChecker` на реальный релиз с git-cliff-телом (или подставить тестовый `body`), открыть диалог обновления и глазами проверить критерии приёмки §1-4 из спеки (секции ⭐/🐛/⚠️, скролл, отсутствие `#`/`*`, заголовок по локали). Не блокирует задачу — основной гейт автоматический (Step 5).

- [ ] **Step 7: Запись в CHANGELOG (EN + RU)**

In `android/CHANGELOG.md`, under `## [Unreleased]` → `### Added`, add:
```markdown
- **The update dialog now shows what changed.** When a newer build is found, the dialog lists the release's changes — features, fixes and any breaking changes — above the download note, taken from the published release's notes and shown as a scrollable "What's new" section. A release without notes (or a build channel that publishes none) shows the dialog exactly as before.
```

In `android/CHANGELOG.ru.md`, under `## [Unreleased]` → `### Added` (mirror the EN entry):
```markdown
- **Диалог обновления теперь показывает, что изменилось.** При найденном обновлении диалог перечисляет изменения релиза — новые возможности, исправления и несовместимые изменения — над строкой о загрузке, беря их из заметок опубликованного релиза и показывая прокручиваемым блоком «Что нового». Релиз без заметок (или канал, который их не публикует) показывает диалог как прежде.
```
(Если в `[Unreleased]` ещё нет секции `### Added` — создать её первой строкой под `## [Unreleased]`, как в предыдущих версиях лога.)

- [ ] **Step 8: Commit**

```bash
git add android/app/src/main/java/com/outline/proxy/UpdateChecker.kt \
        android/app/src/main/java/com/outline/proxy/MainActivity.kt \
        android/app/src/main/res/values/strings.xml \
        android/app/src/main/res/values-ru/strings.xml \
        android/CHANGELOG.md android/CHANGELOG.ru.md
git commit -m "feat(android): show release notes in the update dialog"
```

---

## Self-Review

**1. Покрытие спеки:**
- Источник = тело релиза как есть → Task 2 Step 1 (`release.optString("body")`), CI не тронут. ✓
- Лёгкая чистка Markdown, без библиотек → Task 1 (`ReleaseNotes`, `stripInline`). ✓
- `## What's Changed` и `**Full Changelog**` выбрасываются → Task 1 (правила `##`/`**Full Changelog**`) + тест «only compare link → empty». ✓
- Фоллбэк на пустое/мусорное тело → Task 1 (пустой список без Header/Bullet) + Task 2 Step 4 (`if (notes.isNotEmpty())`) + тесты empty/compare-link. ✓
- Заголовок локализован, содержимое английское → Task 2 Step 2 (`upd_whats_new` EN/RU), содержимое из `body` не переводится. ✓
- EN/RU-паритет → Task 2 Step 2 + Step 5 (`lintDebug`). ✓
- Скролл длинного тела → Task 2 Step 4 (`heightIn(max=260.dp).verticalScroll`). ✓
- Breaking сохранён → Task 1 (правило `### `) + тест «breaking section is preserved». ✓
- Тесты хелпера на JVM → Task 1 Steps 1-4. ✓
- CHANGELOG EN+RU → Task 2 Step 7. ✓

**2. Плейсхолдеры:** нет TBD/TODO; весь код приведён целиком (реализация, тесты, диалог, строки, записи лога). Step 6 помечен опциональным и не содержит заглушек кода.

**3. Согласованность типов/имён:** `ReleaseNotes.format(raw: String): List<NoteLine>` и `NoteLine.{Header,Bullet,Text}(text: String)` определены в Task 1 и используются идентично в тесте (Task 1) и диалоге (Task 2 Step 4). Поле `Result.Available.notes: String` определено в Task 2 Step 1 и читается в Task 2 Step 4 (`available.notes`). Ключ `upd_whats_new` одинаков в обоих `strings.xml` и в `stringResource` диалога.
