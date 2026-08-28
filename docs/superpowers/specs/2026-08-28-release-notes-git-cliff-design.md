# Автосборка release notes через git-cliff (дизайн)

Дата: 2026-08-28
Статус: согласовано в чате

## Проблема

Тело GitHub Release для всех четырёх компонентов (`ss` / `ws` / `ui` /
`android`) формируется одной строкой в reusable-workflow'ах
(`.github/workflows/_ss-release-build.yml` и три его близнеца):

```yaml
generate_release_notes: true
```

Это встроенный автоген GitHub. Он даёт бесполезный результат по двум причинам:

1. **Сломанная база сравнения.** В репозитории смешаны теги четырёх
   компонентов (`ss-v*` / `ws-v*` / `ui-v*` / `android-v*`) и роллинг-теги
   nightly (`ss-nightly`, `ui-nightly`, …). GitHub выбирает «предыдущий релиз»
   по дате последнего тега, без учёта префикса. Для `ss-v1.9.0` он взял базой
   `ui-nightly` — тег другого компонента. Итоговое тело релиза `ss-v1.9.0`:

   > **Full Changelog**: `.../compare/ui-nightly...ss-v1.9.0`

   Diff между разными компонентами бессмыслен; список изменений — мусорный.

2. **Рукописные changelog'и игнорируются.** У проекта есть выверенные
   `bins/*/CHANGELOG.md` (структура `## 1.9.0 - 2026-08-24` → `### Added /
   Changed / Fixed`) и их RU-версии. В тело релиза этот текст не попадает —
   его заменяет сломанный автоген.

Nightly/rolling-релизы страдают тем же: `_ss/_ws/_ui-release-build.yml`
безусловно ставят `generate_release_notes: true` даже для роллинг-тега.

## Цель

При выпуске тега компонента тело GitHub Release **собирается автоматически**
из истории коммитов диапазона этого компонента, сгруппированное по типам
изменений, без чужих (другой компонент) строк и без мусора служебных коммитов.
Инструмент — **git-cliff** (Rust-native, читает Conventional Commits).

Границы решения (согласованы):

- **Только тело релиза.** git-cliff генерит release notes на лету в CI и
  отдаёт их в тело GitHub Release. Файлы `CHANGELOG.md` / `CHANGELOG.ru.md`
  **не трогаются** — они по-прежнему ведутся вручную. Нулевой риск для
  существующего текста и RU-версий.
- **Разграничение компонентов — по путям** (`--include-path`). Scope'ы
  коммитов в репозитории не компонентные (`feat(config)`, `fix(control)`,
  `feat(uplink)`), поэтому фильтровать по scope нельзя.
- **Диапазон — явный `PREV..TAG` того же префикса.** Не полагаемся на
  эвристику «последнего тега».

## Принятые решения (сводка развилок)

| Развилка | Решение |
|---|---|
| Источник тела релиза | git-cliff (автоген из Conventional Commits) |
| Разграничение компонентов | по путям, `--include-path` |
| Что «собирается» | только тело GitHub Release; файлы changelog не трогаем |
| include-path для android | только `android/**` |
| Тело nightly/rolling | коммиты с последнего стабильного (`<last-stable>..HEAD`) |

## Архитектура

### 1. include-path на компонент

Пути выведены из фактических зависимостей манифестов:

| Компонент | Тег-префикс | include-path |
|---|---|---|
| **ss** (server) | `ss-v*` | `bins/outline-ss-rust/**`, `crates/outline-net/**`, `crates/outline-wire/**`, `crates/outline-transport/**`, `vendor/**` |
| **ws** (client) | `ws-v*` | `bins/outline-ws-rust/**`, `crates/**`, `vendor/**` |
| **ui** | `ui-v*` | `bins/outline-ui/**` |
| **android** | `android-v*` | `android/**` |

Замечания:

- Общие крейты (`outline-wire`, `outline-net`, `outline-transport`) попадают и
  в `ss`, и в `ws` — это **корректно**: изменение там реально затрагивает обе
  стороны.
- `ui` не имеет локальных крейт-зависимостей, поэтому только `bins/outline-ui/**`.
- `android` намеренно ограничен `android/**`: клиентский стек, который APK
  перевозит транзитивно, отражается в `ws`-релизе. Глубокие изменения крейтов в
  android-notes не дублируются.

### 2. Диапазон коммитов

Текущий тег известен в workflow как `inputs.tag`. Предыдущий тег того же
префикса выбирается по semver среди тегов компонента (роллинг-теги
`*-nightly` не матчат `*-v*` и отсекаются):

```bash
PREV=$(git tag -l "${PREFIX}-v*" --sort=-v:refname | awk -v cur="$TAG" '$0!=cur' | head -1)
RANGE="${PREV}..${TAG}"      # если PREV пуст (первый релиз) — весь диапазон до TAG
```

Для **nightly/rolling**: `PREV` = последний стабильный тег компонента,
`RANGE="${PREV}..HEAD"`.

Явный `PREV..TAG` детерминированнее, чем `--latest` / `--tag-pattern` git-cliff,
и не зависит от того, какие ещё теги видит инструмент.

### 3. Единый `cliff.toml` в корне

Один конфиг на весь репозиторий; per-component отличия (include-path, диапазон)
передаются флагами CLI, а не отдельными конфигами. Черновик релевантной части:

```toml
[git]
conventional_commits  = true
filter_unconventional = true    # release:/Merge/прочее — отсекаются
protect_breaking_commits = true # feat/refactor с "!" не теряются даже если тип скрыт
filter_commits        = true    # коммиты вне групп исключаются
commit_parsers = [
  { message = "^feat", group = "<!-- 1 -->⭐ Features" },
  { message = "^fix",  group = "<!-- 2 -->🐛 Bug Fixes" },
  { message = "^perf", group = "<!-- 3 -->⚡ Performance" },
  { message = "^refactor", skip = true },
  { message = "^docs",  skip = true },
  { message = "^test",  skip = true },
  { message = "^chore", skip = true },
  { message = "^ci",    skip = true },
  { message = "^build", skip = true },
  { message = "^style", skip = true },
  { message = "^ops",   skip = true },
  { message = "^Merge", skip = true },
  { message = ".*",     skip = true },
]
```

Секции тела релиза:

| Тип коммита | Секция |
|---|---|
| любой с `!` / `BREAKING CHANGE` | ⚠️ **BREAKING CHANGES** (первой, за счёт `protect_breaking_commits`) |
| `feat` | ⭐ Features |
| `fix` | 🐛 Bug Fixes |
| `perf` | ⚡ Performance |
| `docs`, `test`, `chore`, `ci`, `build`, `style`, `refactor`, `ops`, `Merge`, прочее | *скрыто* |

Ключевой инвариант: `refactor(config)!: remove per-user paths` — тип `refactor`
скрыт, но `!` защищён `protect_breaking_commits`, поэтому коммит попадёт в
**BREAKING CHANGES**, а не потеряется. Это проверяемо на реальной истории.

`body`-шаблон (Tera) выводит: заголовок `## What's Changed in {{ TAG }}`,
затем блок BREAKING (по `commit.breaking`), затем группы по порядку. Footer со
ссылкой на полное сравнение формируется скриптом из известных `PREV`/`TAG`
(не через переменные git-cliff — надёжнее):

```
**Full Changelog**: https://github.com/<owner>/<repo>/compare/<PREV>...<TAG>
```

### 4. Скрипт `.github/scripts/gen-release-notes.sh`

Чтобы не дублировать логику в четырёх workflow'ах, вынести её в скрипт в стиле
существующих `.github/scripts/check-*.sh`.

Контракт:

```
gen-release-notes.sh <component> <tag> <output-file>
  component ∈ { ss | ws | ui | android }
  tag       — например ss-v1.9.0, либо *-nightly для rolling
  выход     — markdown-файл с телом релиза
```

Обязанности скрипта:

1. По `component` определить `PREFIX` и набор `--include-path`.
2. Вычислить `PREV` и `RANGE` (см. §2); для `*-nightly` — от последнего
   стабильного до `HEAD`.
3. Запустить `git cliff "$RANGE" <include-path-флаги> --tag "$TAG"
   --config cliff.toml --strip all -o "$OUT"`.
4. Дописать footer со ссылкой `compare/PREV...TAG`.
5. **Fallback**: если после фильтрации тело пустое (нет user-facing коммитов) —
   записать `_No user-facing changes in this release; see full changelog below._`
   плюс footer, чтобы release не остался с пустым описанием.

### 5. Интеграция в workflow'ы

Правки в четырёх `_<comp>-release-build.yml`, job `publish`:

- Добавить `actions/checkout` c `fetch-depth: 0` и `fetch-tags: true` (сейчас в
  `publish` checkout есть только для `rolling_tag`; git-cliff нужна полная
  история и теги).
- Установить git-cliff официальным action'ом `orhun/git-cliff-action@<sha>`
  (пиннинг по SHA — как все прочие actions в репо).
- Шаг **«Generate release notes»**: вызвать
  `.github/scripts/gen-release-notes.sh <comp> <tag> release-notes.md`.
- В шаге `softprops/action-gh-release` заменить
  `generate_release_notes: true` → `body_path: release-notes.md`.

Никаких изменений в «оркестрирующих» workflow'ах (`ss-release.yml`,
`ss-tag-release.yml` и их близнецах) — они лишь передают `tag` в reusable.

### 6. Что НЕ меняется

- Рукописные `CHANGELOG.md` / `CHANGELOG.ru.md` (корневой и per-bin) — как есть.
- Схема тегов и подпись релизных тегов (`git tag -s`) — как есть.
- Матрица сборки, упаковка артефактов, checksums, роллинг-логика тегов.
- Wire, конфиги, код бинарей.

## Проверка (evidence before assertions)

Локально, без CI, на реальной истории:

```bash
# server, реальный прошлый релиз
git cliff ss-v1.8.0..ss-v1.9.0 \
  --include-path 'bins/outline-ss-rust/**' \
  --include-path 'crates/outline-net/**' \
  --include-path 'crates/outline-wire/**' \
  --include-path 'crates/outline-transport/**' \
  --include-path 'vendor/**' \
  --tag ss-v1.9.0 --config cliff.toml --strip all
```

Критерии приёмки:

1. В выводе для `ss-v1.9.0` нет строк, относящихся только к `android/**` или
   `bins/outline-ui/**`.
2. `refactor(config)!` (и любой `feat(...)!`) присутствует в секции BREAKING.
3. `docs:`, `test:`, `chore:`, `ops(k3s):`, merge-коммиты `Merge branch …` и
   `release: cut …` — отсутствуют.
4. Footer ведёт на `compare/ss-v1.8.0...ss-v1.9.0` (правильный префикс, не
   `ui-nightly`).
5. Пустой диапазон (искусственный) даёт fallback-текст, а не пустое тело.

## Риски и пограничные случаи

- **Первый релиз компонента** (нет `PREV`): скрипт берёт весь диапазон до
  `TAG`; footer-ссылку `compare` формировать от корня истории либо опустить.
- **git-cliff версия/флаги.** Зафиксировать версию action по SHA; при
  реализации свериться, что имена флагов (`--include-path`, `--strip`, `--tag`)
  соответствуют выбранной версии.
- **Vendored-пути в include-path (`vendor/**`).** Изменения vendored-крейтов
  редки и обычно несут conventional-тип; при нежелательном шуме — сузить до
  конкретных подпутей. Пока оставляем широко: корректнее показать, чем скрыть.
- **Коммит бампа версии `release: cut <tag>`** попадает в диапазон — отсекается
  как unconventional (`filter_unconventional`).

## Файлы, затронутые реализацией

- `cliff.toml` — новый, корень репозитория.
- `.github/scripts/gen-release-notes.sh` — новый.
- `.github/workflows/_ss-release-build.yml` — правка job `publish`.
- `.github/workflows/_ws-release-build.yml` — правка job `publish`.
- `.github/workflows/_ui-release-build.yml` — правка job `publish`.
- `.github/workflows/_android-release-build.yml` — правка job `publish`.
