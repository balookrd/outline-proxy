# Индекс кода

`scripts/code-index.py` строит локальный структурный индекс для навигации по
Rust workspace с меньшим расходом токенов. Он записывает Cargo-пакеты, target'ы,
исходные файлы, верхнеуровневые Rust items и заголовки `impl` без новых
зависимостей.

Сгенерированный индекс — это карта, а не замена исходникам: по нему удобно найти
нужный модуль и символ, а затем открыть только точечные диапазоны исходного
кода для конкретной правки.

## Генерация

```bash
python3 scripts/code-index.py
```

Результаты:

- `target/code-index/repo-map.md` — компактная Markdown-карта для человека и
  агента.
- `target/code-index/symbols.json` — машинно-читаемые данные по пакетам, файлам
  и символам.

`target/` игнорируется git'ом, поэтому сгенерированные индексы остаются
локальными.

## Узкие срезы

Если задача локализована, ограничивай индекс одним или несколькими пакетами:

```bash
python3 scripts/code-index.py --package outline-transport
python3 scripts/code-index.py --package outline-ss-rust --package outline-wire
```

Detached workspace Android можно пропустить, если он не относится к задаче:

```bash
python3 scripts/code-index.py --skip-detached
```

Vendored Rust sources по умолчанию исключены. Включай их только при работе над
пропатченными копиями:

```bash
python3 scripts/code-index.py --include-vendor
```

## Примеры запросов

Найти, где объявлен символ:

```bash
rg 'poll_shutdown|H3TransportStream|Resume' target/code-index/repo-map.md
```

Посмотреть JSON через `jq`:

```bash
jq '.packages[] | select(.name == "outline-transport") | .source_files[] | select(.path | contains("/h3/")) | {path, module, symbols: [.symbols[].name]}' target/code-index/symbols.json
```

Для более глубоких семантических вопросов этот структурный индекс лучше
совмещать с возможностями `rust-analyzer`: go-to-definition, find-references,
hover/type info и diagnostics.
