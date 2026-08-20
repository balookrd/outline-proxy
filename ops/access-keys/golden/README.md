# Golden corpus

Побайтовый снимок артефактов, которые генератор на Python (`generate_keys.py`)
выдаёт на синтетическом `config.toml` из этого каталога. Все креды фейковые.

Генерация access-key раньше жила в бинаре `outline-ss-rust`; теперь она удалена,
и эталон снят с **Python**-генератора. Он больше не доказательство
эквивалентности Rust↔Python, а regression-anchor самого Python-генератора:
тесты собирают артефакты питоном и сверяют с этим каталогом побайтово. Эталон —
источник истины, код — нет. Если golden-тест упал, неправ Python (либо это
осознанная смена формата — тогда diff эталона обязан быть в том же коммите, что
и правка генератора).

## Что покрывает конфиг

6 включённых юзеров (`disabled` не попадает никуда, `needs sanitising/1`
превращается в `needs_sanitising_1`):

| Юзер | Зачем |
|---|---|
| `ss-only` | только `password` — VLESS-артефактов (`.json`) быть не должно |
| `vless-only` | только `vless_id` — нет ни Outline-конфига (`.conf`), ни `ss://` |
| `both` | обе половины — все четыре файла |
| `own-paths` | per-user пути бьют глобальные |
| `own-method` | per-user `method` бьёт `[shadowsocks].method` |
| `disabled` | `enabled = false` исключает юзера целиком |
| `needs sanitising/1` | санитизация имени файла |

## Раскладка

- `expected/` — полный вывод генератора (то, что он пишет в `--out-dir`): до
  четырёх файлов на юзера — `<user>.conf` (Outline), `<user>.json`
  (Xray-подписка, балансируется по cloud-нодам), `<user>.toml` (конфиг
  outline-ws-rust для Android) и `<user>.txt` (все ссылки, по одной на строку).
  Файл не пишется, если у юзера нет соответствующей половины: у `ss-only` нет
  `.json`, у `vless-only` нет `.conf`. Весь набор сверяется побайтово в
  `test_generate_keys.py::GoldenCorpusTest`, а по типам файлов — в
  `test_outline_yaml.py` (`.conf`), `test_xray_json.py` (`.json`),
  `test_ws_toml.py` (`.toml`) и `test_artifacts.py` (`.conf` + `.txt`).
- `expected-ws/` — `both.toml` и `ss-only.toml`, побайтовые копии тех же файлов
  из `expected/`. Служат фикстурой для `test_ws_toml.py::FixtureTest`, а
  `both.toml` вдобавок грузится **настоящим** загрузчиком конфига ws-rust в
  `generated_android_config_fixture_loads`
  (`bins/outline-ws-rust/src/config/tests/mod.rs`): его схема
  `deny_unknown_fields` ловит дрейф формата, из-за которого один лишний ключ
  ронял бы бинарь на старте.
- `expected-users.txt` — отчёт генератора со stdout (блок на юзера). Никакой
  тест его не читает — это справка; пути в нём относительны корня репозитория и
  зависят от каталога, из которого снимали.

Per-carrier `.conf` (`*-ss-ws.conf`, `*-vless-xhttp-stream-one.conf` и т.п.),
которые писал старый бинарь, генератор больше не выдаёт — вместо файла на носитель
теперь одна строка на носитель в `<user>.txt`. Эти URI по-прежнему покрыты
побайтово через `<user>.txt`.

## Переснять

Из корня репозитория:

```bash
rm -rf ops/access-keys/golden/expected
python3 ops/access-keys/generate_keys.py \
  --config ops/access-keys/golden/config.toml \
  --out-dir ops/access-keys/golden/expected \
  > ops/access-keys/golden/expected-users.txt

mkdir -p ops/access-keys/golden/expected-ws
cp ops/access-keys/golden/expected/both.toml \
   ops/access-keys/golden/expected/ss-only.toml \
   ops/access-keys/golden/expected-ws/
```

Вне ноды генератор пишет на stderr предупреждение, что не смог выставить группу
`www-data` (на маке её нет) — это нормально: в stdout-отчёт (то есть в
`expected-users.txt`) оно не попадает. После перегенерации прогнать
`python3 -m unittest discover -p 'test_*.py'` из `ops/access-keys`.
