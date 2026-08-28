# Release notes via git-cliff — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** При выпуске тега компонента (`ss-v*` / `ws-v*` / `ui-v*` / `android-v*`) тело GitHub Release собирается автоматически git-cliff'ом из коммитов диапазона этого компонента — сгруппированное по типам, без чужих компонентов и без служебного шума.

**Architecture:** Единый корневой `cliff.toml` задаёт секции и фильтры. Скрипт `.github/scripts/gen-release-notes.sh <component> <tag> <out>` держит всю per-component логику: выбор include-path, вычисление предыдущего тега того же префикса, диапазон `PREV..TAG` (для rolling — `<последний стабильный>..HEAD`), вызов `git cliff` с `--tag-pattern` (чтобы чужие теги внутри диапазона не дробили вывод), footer со ссылкой compare и fallback на пустое тело. Четыре reusable-workflow'а `_<comp>-release-build.yml` в job `publish` ставят git-cliff, зовут скрипт и отдают результат в `softprops/action-gh-release` через `body_path` вместо сломанного `generate_release_notes: true`.

**Tech Stack:** git-cliff (Rust CLI, Conventional Commits), bash, GitHub Actions YAML. Rust-код и конфиги бинарей не затрагиваются.

**Design doc:** `docs/superpowers/specs/2026-08-28-release-notes-git-cliff-design.md`

## Global Constraints

- Комментарии в коде, commit-сообщения и PR — на английском; чат и рассуждения — на русском.
- Никогда не добавлять трейлер `Co-Authored-By: Claude` и футер «Generated with Claude Code» ни к чему.
- Коммитить каждую задачу, когда её гейт зелёный, сообщением из последнего шага задачи. **Никогда не `git push`** — это отдельная явная команда владельца каждый раз.
- Работать прямо в `main`. Не создавать feature-ветки.
- Это **не** Rust-изменение: `cargo fmt/clippy/test` не применяются (ни один `.rs` не тронут). Гейт задачи — фактический прогон git-cliff/скрипта на реальной истории репозитория и проверка критериев приёмки, плюс валидация YAML для workflow'ов.
- Тип коммитов для всех задач — `ci:` (изменения релиз-пайплайна). Эти пути (`.github/**`, `cliff.toml`) не входят ни в один include-path компонента, поэтому в release notes бинарей не попадут — это ожидаемо.
- `owner/repo` репозитория = `balookrd/outline-proxy` (из `origin`). В CI берётся из `GITHUB_SERVER_URL` / `GITHUB_REPOSITORY`; локально — парсится из `git remote get-url origin`.
- Соответствие компонент → префикс тега → include-path (используется в Задачах 2 и 3):
  | component | prefix | include-path (globs) |
  |---|---|---|
  | `ss` | `ss` | `bins/outline-ss-rust/**`, `crates/outline-net/**`, `crates/outline-wire/**`, `crates/outline-transport/**`, `vendor/**` |
  | `ws` | `ws` | `bins/outline-ws-rust/**`, `crates/**`, `vendor/**` |
  | `ui` | `ui` | `bins/outline-ui/**` |
  | `android` | `android` | `android/**` |

## File Structure

- `cliff.toml` (**создать**, корень) — конфигурация git-cliff: секции, `commit_parsers`, breaking-защита, Tera-шаблон тела релиза. Одна на весь репозиторий.
- `.github/scripts/gen-release-notes.sh` (**создать**) — вся per-component логика генерации тела релиза. Единственная точка, где живут include-path и вычисление диапазона.
- `.github/workflows/_ss-release-build.yml` (**изменить**, job `publish`) — установка git-cliff, вызов скрипта, `body_path`.
- `.github/workflows/_ws-release-build.yml` (**изменить**, job `publish`) — то же для клиента.
- `.github/workflows/_ui-release-build.yml` (**изменить**, job `publish`) — то же для UI.
- `.github/workflows/_android-release-build.yml` (**изменить**, job `publish`) — то же для Android.

---

### Task 1: `cliff.toml` — конфигурация секций и фильтров

**Files:**
- Create: `cliff.toml`

**Interfaces:**
- Produces: корневой `cliff.toml`, потребляемый `git cliff --config cliff.toml`. Ожидаемое поведение: `feat`→Features, `fix`→Bug Fixes, `perf`→Performance; любой `!`/`BREAKING CHANGE` → секция «⚠️ BREAKING CHANGES» (не теряется, даже если тип скрыт); `docs`/`test`/`chore`/`ci`/`build`/`style`/`refactor`/`ops`/`Merge`/`release:`/прочее — скрыто.

- [ ] **Step 1: Установить git-cliff локально**

На macOS (у владельца mac). Если нет Homebrew — вторая строка ставит из cargo.

Run:
```bash
brew install git-cliff || cargo install git-cliff --locked
git-cliff --version
```
Expected: печатается версия, например `git-cliff 2.x.y`.

- [ ] **Step 2: Определить критерии приёмки (это и есть «тест»)**

Тело для `ss-v1.9.0`, диапазон `ss-v1.8.0..ss-v1.9.0`, ss-пути, должно удовлетворять ВСЕМ пунктам:
1. Присутствует секция `### ⭐ Features` c `feat(transport): make the carrier-dial budget configurable` (общий крейт `outline-transport` входит в ss-пути).
2. Присутствует секция `### ⚡ Performance` c `perf(ss): …` и/или `perf(h3): …`.
3. **Отсутствуют** строки `fix(tun): …` и `fix(uplink): …` (client-only крейты — не в ss-путях).
4. **Отсутствуют** строки `feat(android): …`, `feat(provision): …`, `fix(dns): …` (чужие пути).
5. **Отсутствуют** `docs(...)`, `test(...)`, `ops(...)`, `Merge …`, `release: cut …`.
6. Вывод — ОДНА секция версии (не разбит на несколько по чужим тегам `ws-v1.9.0`/`ui-v1.2.0`, попавшим в тот же период).

- [ ] **Step 3: Создать `cliff.toml`**

```toml
# git-cliff configuration for outline-proxy.
# One config for the whole repo; per-component filtering (include-path, tag
# pattern, commit range) is passed on the CLI by
# .github/scripts/gen-release-notes.sh. This file only decides how commits map
# to release-notes sections and how each line is rendered.

[changelog]
# No global title/footer: the output is a GitHub release body, not a CHANGELOG
# file. The compare-link footer is appended by the script, from the exact
# PREV/TAG it computed — more reliable than git-cliff's tag resolution.
header = ""
body = """
{% if version %}## What's Changed in {{ version }}{% else %}## Unreleased{% endif %}
{% set breaking = commits | filter(attribute="breaking", value=true) -%}
{% if breaking | length > 0 %}

### ⚠️ BREAKING CHANGES
{% for commit in breaking %}
- {% if commit.scope %}**{{ commit.scope }}**: {% endif %}{{ commit.breaking_description | default(value=commit.message) | upper_first }}
{%- endfor %}
{% endif %}
{% for group, group_commits in commits | filter(attribute="breaking", value=false) | group_by(attribute="group") %}

### {{ group | striptags | trim }}
{% for commit in group_commits %}
- {% if commit.scope %}**{{ commit.scope }}**: {% endif %}{{ commit.message | upper_first }}
{%- endfor %}
{% endfor %}
"""
trim = true
footer = ""

[git]
conventional_commits  = true
filter_unconventional = true   # release:/Merge/non-conventional subjects are dropped
protect_breaking_commits = true # feat!/refactor! survive even when the type is skipped
filter_commits        = true   # commits not matched into a kept group are dropped
topo_order            = false
sort_commits          = "oldest"
# Sort keys "<!-- N -->" order the sections; `striptags` strips them in the body.
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

- [ ] **Step 4: Прогнать на реальном диапазоне и проверить критерии**

Run:
```bash
git cliff ss-v1.8.0..ss-v1.9.0 \
  --tag-pattern '^ss-v' \
  --include-path 'bins/outline-ss-rust/**' \
  --include-path 'crates/outline-net/**' \
  --include-path 'crates/outline-wire/**' \
  --include-path 'crates/outline-transport/**' \
  --include-path 'vendor/**' \
  --tag ss-v1.9.0 --config cliff.toml --strip all
```
Expected: вывод удовлетворяет всем 6 критериям из Step 2. Автопроверка ключевых пунктов:
```bash
out=$(git cliff ss-v1.8.0..ss-v1.9.0 --tag-pattern '^ss-v' \
  --include-path 'bins/outline-ss-rust/**' --include-path 'crates/outline-net/**' \
  --include-path 'crates/outline-wire/**' --include-path 'crates/outline-transport/**' \
  --include-path 'vendor/**' --tag ss-v1.9.0 --config cliff.toml --strip all)
echo "$out" | grep -q 'feat(transport)' && echo "OK: transport present" || echo "FAIL: transport missing"
echo "$out" | grep -Eq 'fix\(tun\)|fix\(uplink\)|feat\(android\)|feat\(provision\)' && echo "FAIL: foreign leaked" || echo "OK: no foreign"
echo "$out" | grep -Eq '^- .*Merge|release: cut|docs\(|test\(|ops\(' && echo "FAIL: noise leaked" || echo "OK: no noise"
echo "$out" | grep -c '## What'"'"'s Changed'   # expect exactly 1
```
Если Tera-шаблон падает или секции пусты — поправить `body`/`commit_parsers` в `cliff.toml` и повторить, пока критерии не сойдутся.

- [ ] **Step 5: Commit**

```bash
git add cliff.toml
git commit -m "ci: add git-cliff config for release notes"
```

---

### Task 2: `.github/scripts/gen-release-notes.sh` — per-component генератор

**Files:**
- Create: `.github/scripts/gen-release-notes.sh`

**Interfaces:**
- Consumes: `cliff.toml` из Task 1; бинарь `git-cliff` в `PATH`.
- Produces: исполняемый скрипт с контрактом
  `gen-release-notes.sh <component> <tag> <output-file>`, где
  `component ∈ {ss,ws,ui,android}`, `tag` — `*-vX.Y.Z` (release) или `*-nightly`
  (rolling). Пишет markdown-тело релиза в `<output-file>`; всегда завершается
  успехом и всегда оставляет непустой файл (fallback).

- [ ] **Step 1: Создать `.github/scripts/gen-release-notes.sh`**

```bash
#!/usr/bin/env bash
# Generate a GitHub release body for one component from Conventional Commits.
#
#   gen-release-notes.sh <component> <tag> <output-file>
#     component : ss | ws | ui | android
#     tag       : ss-v1.9.0 (release) or ss-nightly (rolling)
#     output    : path to write the markdown body to
#
# All per-component knowledge (include-path, tag prefix) lives here so the four
# reusable workflows stay identical. Requires git-cliff on PATH and a checkout
# with full history + tags (fetch-depth: 0, fetch-tags: true).
set -euo pipefail

component="${1:?usage: gen-release-notes.sh <component> <tag> <output-file>}"
tag="${2:?missing tag}"
out="${3:?missing output file}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
config="${repo_root}/cliff.toml"

case "$component" in
  ss)
    prefix="ss"
    paths=(bins/outline-ss-rust crates/outline-net crates/outline-wire crates/outline-transport vendor)
    ;;
  ws)
    prefix="ws"
    paths=(bins/outline-ws-rust crates vendor)
    ;;
  ui)
    prefix="ui"
    paths=(bins/outline-ui)
    ;;
  android)
    prefix="android"
    paths=(android)
    ;;
  *)
    echo "unknown component: $component" >&2
    exit 2
    ;;
esac

# Rolling tag (e.g. ss-nightly) is anything not shaped like <prefix>-vX.Y.Z.
rolling=false
if [[ ! "$tag" =~ ^${prefix}-v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  rolling=true
fi

# Previous stable tag of THIS component, by semver, excluding the current one.
prev="$(git tag -l "${prefix}-v*" --sort=-v:refname | awk -v cur="$tag" '$0 != cur' | head -n1)"

if [[ "$rolling" == "true" ]]; then
  head_ref="$(git rev-parse HEAD)"
  range="${prev:+${prev}..}HEAD"
  compare_to="$head_ref"
else
  range="${prev:+${prev}..}${tag}"
  compare_to="$tag"
fi

# Assemble --include-path flags.
include_args=()
for p in "${paths[@]}"; do
  include_args+=(--include-path "${p}/**")
done

# git-cliff exits non-zero when the range has no releasable commits; capture and
# fall through to the fallback body instead of failing the release.
body=""
if body="$(git cliff "$range" \
      --tag-pattern "^${prefix}-v" \
      "${include_args[@]}" \
      --tag "$tag" \
      --config "$config" \
      --strip all 2>/dev/null)"; then
  :
else
  body=""
fi

# Compose the compare-link footer from the exact prev/ref we computed.
server_url="${GITHUB_SERVER_URL:-https://github.com}"
repo="${GITHUB_REPOSITORY:-}"
if [[ -z "$repo" ]]; then
  origin="$(git -C "$repo_root" remote get-url origin 2>/dev/null || echo '')"
  repo="$(printf '%s' "$origin" | sed -E 's#^.*[:/]([^/]+/[^/]+)$#\1#; s#\.git$##')"
fi
footer=""
if [[ -n "$prev" && -n "$repo" ]]; then
  footer="**Full Changelog**: ${server_url}/${repo}/compare/${prev}...${compare_to}"
fi

# Fallback when nothing survived filtering.
if [[ -z "$(printf '%s' "$body" | tr -d '[:space:]')" ]]; then
  body="## What's Changed in ${tag}

_No user-facing changes in this release; see the full changelog below._"
fi

{
  printf '%s\n' "$body"
  if [[ -n "$footer" ]]; then
    printf '\n%s\n' "$footer"
  fi
} > "$out"

echo "Wrote release notes to $out ($(wc -l < "$out") lines)"
```

- [ ] **Step 2: Сделать исполняемым**

Run:
```bash
chmod +x .github/scripts/gen-release-notes.sh
```

- [ ] **Step 3: Прогнать на всех четырёх компонентах (реальные прошлые теги)**

Run:
```bash
for spec in "ss ss-v1.9.0" "ws ws-v1.9.0" "ui ui-v1.2.0" "android android-v1.2.0"; do
  set -- $spec
  echo "===== $1 / $2 ====="
  .github/scripts/gen-release-notes.sh "$1" "$2" "/tmp/notes-$1.md" && sed -n '1,40p' "/tmp/notes-$1.md"
  echo
done
```
Expected: для каждого — непустое тело; в `ss` нет android/ui-строк; в `ui` только UI-изменения; каждый заканчивается корректной строкой `**Full Changelog**: …/compare/<prefix>-vПРЕДЫДУЩИЙ...<prefix>-vТЕКУЩИЙ` (префикс совпадает — например `ss-v1.8.0...ss-v1.9.0`, НЕ `ui-nightly`).

- [ ] **Step 4: Проверить fallback (пустой после фильтрации диапазон)**

Диапазон, где нет user-facing коммитов по путям ui, должен дать fallback, а не пустой файл. Проверяем на «тег сам с собой» (пустой range):
```bash
.github/scripts/gen-release-notes.sh ui ui-v1.2.0 /tmp/notes-empty.md
# Искусственно пустой: подменяем range на пустой прогоном на несуществующей дельте
git cliff ui-v1.2.0..ui-v1.2.0 --tag-pattern '^ui-v' --include-path 'bins/outline-ui/**' \
  --tag ui-v1.2.0 --config cliff.toml --strip all 2>/dev/null || echo "(git-cliff empty range → non-zero, expected)"
grep -q "No user-facing changes" /tmp/notes-empty.md && echo "NOTE: fallback path reachable" || echo "OK: real content for ui-v1.2.0"
```
Expected: скрипт для реального `ui-v1.2.0` даёт контент; при действительно пустом диапазоне (первый прогон покрывает логику) — файл содержит строку «No user-facing changes», не пуст.

- [ ] **Step 5: Проверить первый релиз компонента (нет PREV)**

`ui-v1.1.0` — первый `ui-v*` тег (до него ui-тегов нет), значит `prev` пуст, footer опускается, тело строится от корня истории до тега.
```bash
.github/scripts/gen-release-notes.sh ui ui-v1.1.0 /tmp/notes-first.md
tail -n5 /tmp/notes-first.md
```
Expected: скрипт завершается успешно, файл непустой, строки `**Full Changelog**` нет (PREV отсутствует) — либо есть корректная секция изменений.

- [ ] **Step 6: Commit**

```bash
git add .github/scripts/gen-release-notes.sh
git commit -m "ci: add per-component release-notes generator script"
```

---

### Task 3: Встроить в четыре reusable-workflow'а

**Files:**
- Modify: `.github/workflows/_ss-release-build.yml` (job `publish`)
- Modify: `.github/workflows/_ws-release-build.yml` (job `publish`)
- Modify: `.github/workflows/_ui-release-build.yml` (job `publish`)
- Modify: `.github/workflows/_android-release-build.yml` (job `publish`)

**Interfaces:**
- Consumes: `.github/scripts/gen-release-notes.sh` (Task 2), `cliff.toml` (Task 1).
- Produces: каждый `publish` job генерит `release-notes.md` и передаёт его в `softprops/action-gh-release` через `body_path`.

- [ ] **Step 1: Зафиксировать версию git-cliff и её sha256 (pin, без выдумок)**

Определить последнюю стабильную версию и хэш Linux-архива — подставить в workflow'ы на Step 3.
```bash
VER="$(gh release view --repo orhun/git-cliff --json tagName -q .tagName | sed 's/^v//')"
echo "git-cliff version: $VER"
url="https://github.com/orhun/git-cliff/releases/download/v${VER}/git-cliff-${VER}-x86_64-unknown-linux-gnu.tar.gz"
curl -fsSL "$url" -o /tmp/gc.tgz
echo "sha256: $(sha256sum /tmp/gc.tgz | cut -d' ' -f1)"
```
Записать полученные `VER` и `sha256` — они пойдут в шаг «Install git-cliff» ниже.

- [ ] **Step 2: Определить критерий приёмки для workflow-правок**

В каждом из четырёх файлов job `publish` после правок должен:
1. делать `actions/checkout` с `fetch-depth: 0` и `fetch-tags: true` **безусловно** (сейчас checkout только `if: rolling_tag`);
2. ставить git-cliff (pinned версия + sha256-проверка);
3. иметь шаг «Generate release notes», зовущий `gen-release-notes.sh <component> <inputs.tag> release-notes.md`;
4. в шаге `softprops/action-gh-release` иметь `body_path: release-notes.md` и **не** иметь `generate_release_notes:`.

- [ ] **Step 3: Правка `_ss-release-build.yml`**

Заменить в job `publish` первый шаг checkout. Было:
```yaml
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        if: ${{ inputs.rolling_tag }}
        with:
          fetch-depth: 0
```
Стало (checkout безусловный, с тегами):
```yaml
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          fetch-tags: true
```
Сразу после блока `- uses: actions/download-artifact@… path: dist` и шага «Generate checksums» добавить (перед «Publish GitHub release») два шага. Вставить:
```yaml
      - name: Install git-cliff
        env:
          GIT_CLIFF_VERSION: "PIN_VER"      # from Task 3 Step 1
          GIT_CLIFF_SHA256: "PIN_SHA256"    # from Task 3 Step 1
        run: |
          set -euo pipefail
          url="https://github.com/orhun/git-cliff/releases/download/v${GIT_CLIFF_VERSION}/git-cliff-${GIT_CLIFF_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
          curl -fsSL "$url" -o /tmp/git-cliff.tar.gz
          echo "${GIT_CLIFF_SHA256}  /tmp/git-cliff.tar.gz" | sha256sum -c -
          tar -xzf /tmp/git-cliff.tar.gz -C /tmp
          sudo install "/tmp/git-cliff-${GIT_CLIFF_VERSION}/git-cliff" /usr/local/bin/git-cliff
          git-cliff --version

      - name: Generate release notes
        run: .github/scripts/gen-release-notes.sh ss "${{ inputs.tag }}" release-notes.md
```
В шаге «Publish GitHub release» удалить строку `generate_release_notes: true` и добавить `body_path`:
```yaml
      - name: Publish GitHub release
        uses: softprops/action-gh-release@3d0d9888cb7fd7b750713d6e236d1fcb99157228 # v3.0.2
        with:
          tag_name: ${{ inputs.tag }}
          name: ${{ inputs.release_name != '' && inputs.release_name || format('Server {0}', inputs.tag) }}
          prerelease: ${{ inputs.prerelease }}
          make_latest: ${{ inputs.make_latest }}
          body_path: release-notes.md
          files: |
            dist/*.tar.gz
            dist/SHA256SUMS.txt
```

- [ ] **Step 4: Правка `_ws-release-build.yml`**

Тот же безусловный checkout, тот же «Install git-cliff» (идентичный блок), и «Generate release notes» с компонентом `ws`:
```yaml
      - name: Generate release notes
        run: .github/scripts/gen-release-notes.sh ws "${{ inputs.tag }}" release-notes.md
```
В «Publish GitHub release» — удалить `generate_release_notes: true`, добавить `body_path: release-notes.md` (остальные ключи `name`/`prerelease`/`make_latest`/`files` не трогать).

- [ ] **Step 5: Правка `_ui-release-build.yml`**

То же, компонент `ui`:
```yaml
      - name: Generate release notes
        run: .github/scripts/gen-release-notes.sh ui "${{ inputs.tag }}" release-notes.md
```
В «Publish GitHub release» — удалить `generate_release_notes: true`, добавить `body_path: release-notes.md`.

- [ ] **Step 6: Правка `_android-release-build.yml`**

Здесь есть особенности. Checkout в `publish` тоже сделать безусловным (`fetch-depth: 0`, `fetch-tags: true`). Добавить тот же «Install git-cliff» и:
```yaml
      - name: Generate release notes
        run: .github/scripts/gen-release-notes.sh android "${{ inputs.tag }}" release-notes.md
```
В шаге «Publish GitHub release» заменить `generate_release_notes: ${{ !inputs.rolling_tag }}` на `body_path: release-notes.md` (теперь и rolling получает notes «с последнего стабильного», как решено в дизайне). Итог:
```yaml
      - name: Publish GitHub release
        uses: softprops/action-gh-release@3d0d9888cb7fd7b750713d6e236d1fcb99157228 # v3.0.2
        with:
          tag_name: ${{ inputs.tag }}
          name: ${{ inputs.release_name != '' && inputs.release_name || format('Android {0}', inputs.tag) }}
          prerelease: ${{ inputs.prerelease }}
          make_latest: ${{ inputs.make_latest }}
          body_path: release-notes.md
          files: |
            dist/*.apk
            dist/SHA256SUMS.txt
```

- [ ] **Step 7: Валидировать YAML всех четырёх файлов**

Установить actionlint (ловит и синтаксис YAML, и ошибки схемы GitHub Actions), затем прогнать:
```bash
brew install actionlint 2>/dev/null || true
if command -v actionlint >/dev/null; then
  actionlint .github/workflows/_ss-release-build.yml .github/workflows/_ws-release-build.yml \
             .github/workflows/_ui-release-build.yml .github/workflows/_android-release-build.yml
else
  for f in _ss _ws _ui _android; do
    python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/${f}-release-build.yml')); print('OK ${f}')"
  done
fi
```
Expected: actionlint без ошибок (или `OK` по каждому файлу от python-фолбэка).

- [ ] **Step 8: Проверить shell-шаг скрипта в контексте (shellcheck, опционально)**

```bash
brew install shellcheck 2>/dev/null || true
command -v shellcheck >/dev/null && shellcheck .github/scripts/gen-release-notes.sh || echo "shellcheck not available — skip"
```
Expected: без ошибок уровня error (варнинги стиля допустимы).

- [ ] **Step 9: Commit**

```bash
git add .github/workflows/_ss-release-build.yml .github/workflows/_ws-release-build.yml \
        .github/workflows/_ui-release-build.yml .github/workflows/_android-release-build.yml
git commit -m "ci: build release notes with git-cliff instead of GitHub autogen"
```

- [ ] **Step 10: Пострелизная проверка (документировать, не выполнять сейчас)**

Первый реальный тег после мержа (`git tag -s <comp>-vX.Y.Z … && git push origin <tag>`) должен дать GitHub Release с телом из секций git-cliff и корректной ссылкой compare того же префикса. Это подтверждается на первом же плановом релизе; отдельного действия сейчас не требует. `git push` — только по явной команде владельца.

---

## Self-Review

**1. Покрытие спеки:**
- Источник = git-cliff, только тело релиза → Task 1 (`cliff.toml`) + Task 3 (`body_path`, файлы CHANGELOG не тронуты). ✓
- Разграничение по путям → Task 2 (include-path на компонент). ✓
- Явный диапазон `PREV..TAG`, чинит базу `ui-nightly` → Task 2 (вычисление `prev`, `--tag-pattern`) + критерий Task 2 Step 3 (footer правильного префикса). ✓
- android = только `android/**` → таблица в Global Constraints + Task 2 `case android`. ✓
- nightly = с последнего стабильного → Task 2 (ветка `rolling`), Task 3 Step 6 (android body_path и для rolling). ✓
- BREAKING защищён → Task 1 `protect_breaking_commits` + шаблон + критерий Task 1 Step 2. ✓
- Fallback пустого тела → Task 2 Step 1 (блок fallback) + Step 4. ✓
- Скрипт вместо дублирования → Task 2. ✓

**2. Плейсхолдеры:** `PIN_VER`/`PIN_SHA256` — не заглушки: их конкретные значения добываются командой в Task 3 Step 1 и подставляются в Step 3. `paths=(…)`, `case` — реальный код. Прочих TODO/TBD нет.

**3. Согласованность типов/имён:** контракт `gen-release-notes.sh <component> <tag> <out>` одинаков в Task 2 (определение) и во всех вызовах Task 3 (Steps 3–6). Имя файла тела — везде `release-notes.md`. Префиксы тегов (`ss`/`ws`/`ui`/`android`) совпадают между таблицей Global Constraints, `case` в скрипте и `--tag-pattern`.
