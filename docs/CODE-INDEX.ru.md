# Индекс кода

`scripts/code-index.py` строит локальный структурный индекс Rust workspace для
навигации с малым расходом токенов. Он записывает Cargo-пакеты, target'ы,
исходные файлы, верхнеуровневые Rust items и заголовки `impl`. Нужны `python3` и
`cargo` в `PATH` (список пакетов берётся из `cargo metadata --no-deps`);
дополнительных Python-пакетов не нужно.

Индекс — карта, а не замена исходникам: по нему найдите нужный модуль и символ,
а затем откройте только те диапазоны исходного кода, которые нужны для правки.

## Генерация

Запускайте из корня репозитория:

```bash
python3 scripts/code-index.py
```

Результаты:

- `target/code-index/repo-map.md` — компактная Markdown-карта для человека и
  агента.
- `target/code-index/symbols.json` — машинно-читаемые данные по пакетам, файлам
  и символам.

`target/` игнорируется git'ом, поэтому сгенерированный индекс остаётся
локальным.

## Параметры

| Флаг | По умолчанию | Что делает |
|---|---|---|
| `--package <name>` | все пакеты | ограничить индекс одним пакетом; для нескольких повторить флаг |
| `--skip-detached` | выключен | пропустить отдельные (detached) workspace (`android/rust`) |
| `--include-vendor` | выключен | включить vendored Rust-исходники (`vendor/`) |
| `--output-dir <dir>` | `target/code-index` | куда писать `repo-map.md` и `symbols.json`; относительный путь считается от `--repo-root` |
| `--repo-root <dir>` | `.` (текущий каталог) | корень репозитория |

Ограничьте индекс пакетами, которые затрагивает задача:

```bash
python3 scripts/code-index.py --package outline-transport
python3 scripts/code-index.py --package outline-ss-rust --package outline-wire
```

Пропустите detached workspace Android, если он не относится к задаче:

```bash
python3 scripts/code-index.py --skip-detached
```

Vendored-исходники включайте только при работе над пропатченными копиями:

```bash
python3 scripts/code-index.py --include-vendor
```

## Примеры запросов

Найти, где объявлен символ:

```bash
rg 'poll_shutdown|H3DatagramChannel|Resume' target/code-index/repo-map.md
```

Посмотреть JSON через `jq`:

```bash
jq '.packages[] | select(.name == "outline-transport") | .source_files[] | select(.path | contains("/h3/")) | {path, module, symbols: [.symbols[].name]}' target/code-index/symbols.json
```

У каждого символа в `symbols.json` есть поля `kind`, `name`, `line`,
`visibility`, `module` и `signature`. Для типов, ссылок и диагностики
используйте `rust-analyzer`: индекс имена не резолвит.
