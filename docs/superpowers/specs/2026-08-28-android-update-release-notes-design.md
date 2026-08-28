# Описание изменений в диалоге обновления Android (дизайн)

Дата: 2026-08-28
Статус: согласовано в чате

## Проблема

У Android-приложения есть собственный in-app updater
([`android/app/src/main/java/com/outline/proxy/UpdateChecker.kt`](../../../android/app/src/main/java/com/outline/proxy/UpdateChecker.kt)):
тап по футеру версии на домашнем экране спрашивает GitHub Releases API, что
опубликовано для канала сборки (`release` / `nightly`), сравнивает версии и
предлагает скачать APK.

При найденном обновлении диалог «Доступно обновление»
([`MainActivity.kt:398`](../../../android/app/src/main/java/com/outline/proxy/MainActivity.kt))
показывает только две вещи: `upd_published_for_channel` («v1.2.0 опубликовано
для этого канала») и `upd_apk_note` (куда скачается APK). **Пользователь не
видит, что именно меняется в новой версии.**

При этом тело GitHub-релиза (`body` — где и живут release notes) **уже приходит
в ответе API**, который парсит `UpdateChecker`, но код его не читает:
`checkRelease()` и `checkNightly()` строят `Result.Available` из полей `label` /
`assetName` / `url`, а поле `body` того же JSON-объекта игнорируется.

## Цель и границы

Показать в существующем диалоге обновления блок **«Что нового»** — описание
изменений предлагаемой версии, взятое из тела релиза **как есть**.

Границы (согласованы):

- **Только приложение.** Релиз-пайплайн (CI, git-cliff) в этой задаче **не
  трогаем**. Тело релиза берём таким, какое GitHub отдаёт сегодня.
- **Грациозный фоллбэк.** Сегодня тело android-релиза — это автоген GitHub со
  сломанной базой сравнения (`**Full Changelog**: …/compare/ui-nightly...android-v1.2.0`),
  а у `nightly` тела нет вовсе. Значит на текущих релизах показывать нечего —
  и тогда диалог обязан выглядеть **ровно как сейчас**, без пустых секций.
  Осмысленный текст появится сам, когда отдельно раскатают git-cliff-план
  ([`2026-08-28-release-notes-git-cliff-design.md`](2026-08-28-release-notes-git-cliff-design.md)),
  который уже android-aware.
- **Без тяжёлого Markdown.** Никакой Markdown-библиотеки (в проекте строгий R8,
  каждая рефлексивная зависимость требует keep-правил). Своя лёгкая чистка.
- **Содержимое не переводим.** Changelog собирается из английских коммитов и
  остаётся английским; локализуем только заголовок секции.

## Принятые решения (сводка развилок)

| Развилка | Решение |
|---|---|
| Источник описания | тело GitHub-релиза как есть (не бандл CHANGELOG, не git-cliff в этой задаче) |
| Формат отображения | лёгкая чистка Markdown → читаемый текст, без библиотек |
| Строка `**Full Changelog**: …` | выбрасываем (техническая ссылка, не «что нового») |
| Заголовок `## What's Changed in <tag>` | выбрасываем (дублирует заголовок диалога) |
| Пустое / мусорное тело | фоллбэк: секции «Что нового» нет, диалог как сейчас |
| Локализация | переводим заголовок секции; содержимое остаётся английским |

## Архитектура

Три небольших единицы с раздельными обязанностями: (1) `UpdateChecker` доносит
сырой текст, (2) чистый хелпер превращает Markdown в структуру строк
(тестируется на JVM, без Compose), (3) диалог её рендерит.

### 1. `UpdateChecker.Result.Available` += `notes`

```kotlin
data class Available(
    val label: String,
    val assetName: String,
    val url: String,
    val notes: String,   // raw GitHub release body; "" when the release has none
) : Result
```

- `checkRelease()` ([`UpdateChecker.kt:112`](../../../android/app/src/main/java/com/outline/proxy/UpdateChecker.kt)):
  добавить `release.optString("body")` в конструктор `Available`.
- `checkNightly()` ([`UpdateChecker.kt:83`](../../../android/app/src/main/java/com/outline/proxy/UpdateChecker.kt)):
  то же — `release` там уже `JSONObject`.

Сеть, скачивание, `openForInstall`, выбор версии/канала — не меняются. Это
единственная правка в `UpdateChecker`.

### 2. Хелпер чистки: `ReleaseNotes` (чистый Kotlin, тестируемый)

Новый файл `android/app/src/main/java/com/outline/proxy/ReleaseNotes.kt`. Не
зависит от Compose/Android — чтобы покрыть JVM unit-тестом.

```kotlin
/** One rendered line of cleaned-up release notes. */
sealed interface NoteLine {
    data class Header(val text: String) : NoteLine   // section heading, bold
    data class Bullet(val text: String) : NoteLine   // list item, "• …"
    data class Text(val text: String) : NoteLine     // plain paragraph line
}

object ReleaseNotes {
    /** Clean a GitHub release body into displayable lines; empty when there is
     *  nothing user-facing to show (caller then falls back to the plain dialog). */
    fun format(raw: String): List<NoteLine>
}
```

Правила «лёгкой чистки» (построчно):

| Вход (Markdown) | Выход |
|---|---|
| `## What's Changed in <tag>` (H2) | отбрасывается |
| `### ⭐ Features` / `🐛 Bug Fixes` / `⚠️ BREAKING CHANGES` (H3) | `Header("⭐ Features")` — снят `### ` |
| `- **scope**: message` | `Bullet("scope: message")` — снят `-`, снят `**…**` |
| `- message` | `Bullet("message")` |
| `**Full Changelog**: <url>` | отбрасывается |
| пустая строка | схлопывается (разделитель между секциями сохраняется структурой) |
| прочая непустая строка | `Text(строка)` с убранными inline `**` |

Инвариант фоллбэка: если после чистки **не осталось ни одного `Header` или
`Bullet`** (тело пустое, только Full-Changelog, или nightly без тела) —
`format` возвращает **пустой список**. Вызывающий это трактует как «показывать
нечего».

Снятие inline-разметки минимально и предсказуемо: убрать `**` (bold) и
ведущие `#`/`-`/пробелы у строки. Никакого разбора ссылок, кода, вложенных
списков — git-cliff даёт плоскую структуру (H2 → H3 → буллеты), а на чужом
формате худший исход — строка уедет в `Text` как есть, что безопасно.

### 3. Диалог `MainActivity`

В `text`-блоке `AlertDialog`
([`MainActivity.kt:402`](../../../android/app/src/main/java/com/outline/proxy/MainActivity.kt)):

```kotlin
val notes = remember(available) { ReleaseNotes.format(available.notes) }
Column {
    Text(stringResource(R.string.upd_published_for_channel, available.label))
    if (notes.isNotEmpty()) {
        Spacer(Modifier.height(12.dp))
        Text(stringResource(R.string.upd_whats_new), fontWeight = FontWeight.Bold)
        Column(
            Modifier
                .heightIn(max = 260.dp)          // long bodies scroll, dialog stays sane
                .verticalScroll(rememberScrollState()),
        ) {
            notes.forEach { line -> /* render Header/Bullet/Text */ }
        }
    }
    Spacer(Modifier.height(12.dp))
    Text(stringResource(R.string.upd_apk_note))
}
```

- **Скролл + `heightIn(max)`** — тело релиза бывает длинным; диалог не должен
  распирать экран.
- **Фоллбэк**: `notes.isEmpty()` ⇒ блок «Что нового» отсутствует, остаётся
  прежняя пара строк (версия + apk_note). Поведение на сегодняшних релизах не
  деградирует.
- Кнопки (Скачать / Позже) и логика скачивания — без изменений.

### 4. Строки EN/RU

Один новый ключ в блоке `<!-- Update dialog … -->` обоих `strings.xml`:

- `res/values/strings.xml`: `<string name="upd_whats_new">What's new</string>`
- `res/values-ru/strings.xml`: `<string name="upd_whats_new">Что нового</string>`

Lint-гейт паритета ключей EN/RU
([`build.gradle.kts`](../../../android/app/build.gradle.kts)) требует обе
стороны — добавляем в одном изменении. Содержимое release notes при этом
остаётся английским (см. границы).

### 5. Тесты

`android/app/src/test/java/com/outline/proxy/ReleaseNotesTest.kt` — рядом с
существующими JVM-тестами (`ExternalControlTest`, `KeepAlivePolicyTest`).
Покрыть:

1. git-cliff-подобное тело (H2 + `### ⭐ Features` + буллеты `- **android**: …`
   + `### ⚠️ BREAKING CHANGES`) → правильные `Header`/`Bullet`, без `#`/`*` в
   тексте, breaking-секция сохранена и её заголовок присутствует.
2. Тело только из `**Full Changelog**: …` → **пустой** список (фоллбэк).
3. Пустая строка `""` → пустой список.
4. Строка `- **scope**: msg` → `Bullet("scope: msg")` (проверка снятия `**`).

## Что НЕ меняется

- Релиз-пайплайн: `.github/workflows/_android-release-build.yml`,
  `gen-release-notes.sh`, `cliff.toml` — вне этой задачи.
- Логика проверки версий/каналов, скачивание APK, `openForInstall`,
  MediaStore-путь, permissions (`REQUEST_INSTALL_PACKAGES` по-прежнему нет).
- Кнопки диалога, футер версии, любой другой экран.

## Проверка (критерии приёмки)

1. На теле в формате git-cliff диалог показывает «Что нового» с секциями
   ⭐/🐛/⚠️ и буллетами; символы `#`, `*` в тексте не видны.
2. На сегодняшнем реальном теле `android-v1.2.0` (только Full-Changelog-ссылка)
   и на пустом теле `nightly` диалог выглядит как до изменения — без пустой
   секции.
3. Длинное тело скроллится внутри диалога; диалог не выходит за экран.
4. Русская локаль: заголовок «Что нового»; английская: «What's new».
   Содержимое изменений — английское в обеих.
5. `./gradlew :app:testDebugUnitTest` зелёный (включая новый `ReleaseNotesTest`);
   `:app:assembleDebug` собирается; lint-гейт EN/RU-паритета проходит.

## Риски и пограничные случаи

- **Формат тела не от git-cliff.** Худший исход чистки — строка попадает в
  `Text` без разметки; ничего не ломается. Осмысленные секции появятся с
  раскаткой git-cliff.
- **Очень длинный или странный `body`.** Ограничение высоты + скролл; парсинг
  построчный, без рекурсии — линейный и дешёвый.
- **HTML/ссылки в теле.** Не рендерим как разметку — показываем текст. Для
  release notes этого достаточно; экзотику осознанно не поддерживаем (YAGNI).
- **Recreate Activity во время открытого диалога** (смена mcc/mnc и т.п.):
  `update`/notes — transient UI-state, диалог закроется, как и сегодня. Вне
  scope — durable-состоянием апдейт-диалог не был и не становится.

## Файлы, затронутые реализацией

- `android/app/src/main/java/com/outline/proxy/UpdateChecker.kt` — `+notes` в
  `Result.Available`, чтение `body` в двух ветках.
- `android/app/src/main/java/com/outline/proxy/ReleaseNotes.kt` — **новый**,
  чистка Markdown → `List<NoteLine>`.
- `android/app/src/main/java/com/outline/proxy/MainActivity.kt` — блок «Что
  нового» в диалоге + фоллбэк.
- `android/app/src/main/res/values/strings.xml` — `upd_whats_new` (EN).
- `android/app/src/main/res/values-ru/strings.xml` — `upd_whats_new` (RU).
- `android/app/src/test/java/com/outline/proxy/ReleaseNotesTest.kt` — **новый**,
  JVM unit-тест.
- `android/CHANGELOG.md` / `android/CHANGELOG.ru.md` — запись в `[Unreleased]`.
