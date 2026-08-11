# `link` в `[[outline.uplinks.fallbacks]]` (дизайн)

Дата: 2026-08-11
Статус: согласован в чате; ждёт ревью владельца

## Задача

Клиентский конфиг `outline-ws-rust` описывает каждый wire раздельными полями:
URL, режим носителя, `vless_id` либо `method` + `password`. Share-link
(`vless://…`, `ss://…`) сворачивает всё это в одну строку, но принимается
только на уровне uplink'а — `[[outline.uplinks]]`, inline-`[outline]`, CLI
и `/control/uplinks`. У `[[outline.uplinks.fallbacks]]` поля `link` нет.

На боевых узлах это ровно наоборот пропорции: конфиг каждого узла — 3 uplink'а
по (primary + 3 fallback), то есть 12 wire, из которых **9 живут во
fallback-блоках**. Без `link` во fallback на ссылки переводится 3 wire из 12,
и смысл миграции теряется.

Цель — свести описание любого wire к одной строке, включая fallback'и.

## Что есть сейчас (проверено 2026-08-11)

Парсеры ссылок готовы и покрыты тестами:

| Файл | Что разбирает |
|---|---|
| `crates/outline-uplink/src/share_link.rs` | `vless://UUID@HOST:PORT?…#NAME` → `vless_id`, `vless_ws_url` \| `vless_xhttp_url`, `vless_mode` |
| `crates/outline-uplink/src/ss_share_link.rs` | `ss://BASE64(method:password)@HOST:PORT?…#NAME` (SIP002) → `ss_ws_url` \| `ss_xhttp_url`, `ss_mode`, `method`, `password` |

Режим носителя кодируется парой `type` + `alpn`: `type=ws&alpn=h3` → `ws_h3`,
`type=xhttp&alpn=h3` → `xhttp_h3`. XHTTP-submode едет отдельным параметром
`mode=packet-up|stream-one` и пробрасывается в query дайл-URL.

Разворачивание ссылки живёт в `resolve_primary_wire_shape`
(`bins/outline-ws-rust/src/config/load/uplinks/wire_shape.rs`): по схеме
выбирается парсер, проверяется взаимоисключение с явными полями, выводится
транспорт.

`FallbackSection` (`bins/outline-ws-rust/src/config/schema.rs`) поля `link` не
имеет, а `transport` у неё обязательный (`UplinkTransport`, не `Option`).
Симметрично в control-API: `FallbackPayload`
(`bins/outline-ws-rust/src/http/control/uplinks_crud/payload.rs`) — без `link`,
с обязательным `transport: String`.

Форма боевых конфигов (`.102`, `.104`, `cloud1`, `cloud2` — идентичны):

| wire | поля сейчас |
|---|---|
| primary | `transport=vless`, `vless_xhttp_url` (`?mode=stream-one`), `vless_mode="xhttp_h3"`, `vless_id` |
| fallbacks[0] | `transport=vless`, `vless_ws_url`, `vless_mode="ws_h3"`, `vless_id` |
| fallbacks[1] | `transport=ss`, `ss_xhttp_url` (`?mode=stream-one`), `ss_mode="xhttp_h3"`, `method`, `password` |
| fallbacks[2] | `transport=ss`, `ss_ws_url`, `ss_mode="ws_h3"`, `method`, `password` |

Все четыре формы выразимы ссылкой. Split-раскладка `tcp_*` / `udp_*` —
единственная, у которой URL-формы нет, — на парке не используется нигде.

## Решение

### Схема TOML

`FallbackSection` получает `link: Option<String>`, а `transport` становится
`Option<UplinkTransport>`. Обязательность транспорта переезжает из типа в
валидацию: без `link` он по-прежнему требуется, с `link` — выводится из схемы
ссылки, как это уже работает у primary.

```toml
[[outline.uplinks]]
name = "cloud1"
group = "main"
weight = 1.0
link = "vless://UUID@host:443?type=xhttp&security=tls&path=%2F…&alpn=h3&mode=stream-one"

[[outline.uplinks.fallbacks]]
link = "vless://UUID@host:443?type=ws&security=tls&path=%2F…&alpn=h3"

[[outline.uplinks.fallbacks]]
link = "ss://BASE64@host:443?type=xhttp&security=tls&path=%2F…&alpn=h3&mode=stream-one"

[[outline.uplinks.fallbacks]]
link = "ss://BASE64@host:443?type=ws&security=tls&path=%2F…&alpn=h3"
```

### Правила

1. **Взаимоисключение.** `link` несовместим с `tcp_ws_url`, `tcp_xhttp_url`,
   `tcp_mode`, `udp_ws_url`, `udp_xhttp_url`, `udp_mode`, `vless_ws_url`,
   `vless_xhttp_url`, `vless_mode`, `ss_ws_url`, `ss_xhttp_url`, `ss_mode`,
   `vless_id`. `method` и `password` конфликтуют только с `ss://`-ссылкой,
   которая их несёт; рядом с `vless://`-ссылкой они допустимы и, как сегодня,
   в VLESS-wire не участвуют — на uplink'е они стоят ради наследования
   SS-fallback'ами, и запрет сломал бы такие конфиги. Правило общее для
   primary и fallback; формулировки ошибок повторяют primary-ветку, с
   префиксом `uplink {parent}: fallbacks[{idx}]`.
2. **Совместимость.** `link` совместим с `fwmark`, `ipv6_first`,
   `fingerprint_profile`: это не описание wire-формы, а свойства дайла, и их
   наследование от родителя не меняется.
3. **Транспорт.** Явно заданный `transport`, совпавший со схемой ссылки,
   допустим (избыточен, но не ошибка); не совпавший — ошибка загрузки
   (`ss://` при `transport = "vless"` и наоборот).
4. **Креды.** Ссылка полностью определяет свой wire: `ss://` даёт `method` и
   `password`, `vless://` даёт `vless_id`. Наследование `cipher`/`password` от
   родителя к этому wire не применяется — наследовать было бы нечего, ссылка
   уже несёт всё. Побочный эффект, ради которого это и делается: SS-fallback
   под VLESS-родителем перестаёт требовать явных `method`/`password`. Для
   `vless://`-fallback'а унаследованные SS-креды остаются неиспользованными —
   ровно как сегодня у рукописного VLESS-fallback'а.
5. **Фрагмент.** `#NAME` во fallback-ссылке игнорируется — у fallback нет
   собственной идентичности, имя/вес/группа принадлежат родительскому uplink'у.
   Это уже поведение primary, где имя берётся из `name`, а не из ссылки.

### Реализация

Подход — общий чистый хелпер плюс pre-pass над секцией. Разворачивание ссылки
переезжает из тела `resolve_primary_wire_shape` в отдельную функцию рядом с ним,
а fallback получает шаг, который этим хелпером заполняет поля своей секции; вся
существующая валидация fallback'а после этого работает без изменений.

Отвергнутые варианты: скопировать логику в `fallback_resolution.rs`
(дублирование правил взаимоисключения и текстов ошибок — ровно тот класс
расхождений между поверхностями, который здесь уже ловили) и переписать
`resolve_fallback` под готовый `LinkExpansion` (лишнее касание самой нагруженной
валидации — carrier↔URL, h3-gate, наследование — ради фичи, которая её не
меняет).

| Файл | Правка |
|---|---|
| `config/schema.rs` | `FallbackSection`: `+ link: Option<String>`, `transport: Option<UplinkTransport>` |
| `config/load/uplinks/wire_shape.rs` | вынести разворачивание ссылки в `expand_share_link(name, link, declared_transport) -> Result<LinkExpansion>`; `resolve_primary_wire_shape` начинает звать её, поведение и тексты сохраняются |
| `config/load/uplinks/fallback_resolution.rs` | pre-pass `apply_link(section, idx, parent_name) -> Result<(FallbackSection, UplinkTransport)>` перед `resolve_fallback`; сам `resolve_fallback` получает разрешённый транспорт аргументом |
| `http/control/uplinks_crud/payload.rs` | `FallbackPayload`: `+ link: Option<String>` (алиас `share_link`, как у родителя), `transport: Option<String>`; `fallbacks_to_array` пишет `transport` только когда он задан и пишет `link` |

`LinkExpansion` несёт то же, что сейчас выставляется в primary-ветке: транспорт,
одну из пар URL (`ss_ws_url` \| `ss_xhttp_url` \| `vless_ws_url` \|
`vless_xhttp_url`), режим носителя и креды (`vless_id` либо `cipher` +
`password`).

Порядок в pre-pass: проверить конфликты → развернуть ссылку → заполнить поля
секции → вернуть транспорт. После этого ветвление в `resolve_fallback`
(`UplinkTransport::Ss if section.ss_xhttp_url.is_some() || …`) выбирает нужную
ветку само, а проверки carrier↔URL, `#[cfg(not(feature = "h3"))]` и наследование
не-wire полей отрабатывают ровно как для рукописного TOML.

Round-trip: control-API сохраняет в конфиг именно `link`, в раздельные поля он
не разворачивается — иначе первая же правка через API превращала бы ссылочный
конфиг обратно в длинную форму.

### Видимые изменения поведения

- Конфиг с `[[outline.uplinks.fallbacks]]` без `transport` и без `link` теперь
  падает с нашей ошибкой валидации вместо serde-шного `missing field
  transport`. Текст ошибки — часть контракта, закрывается тестом.
- В JSON control-API `transport` у fallback становится необязательным. Старые
  клиенты, которые его шлют, продолжают работать без изменений.
- Добавление поля в структуру с `deny_unknown_fields` обратно совместимо:
  существующие конфиги остаются валидными.

### Ловушки миграции (для будущей задачи, не для этой)

- В ссылке порт обязателен, а в боевых конфигах URL записаны без `:443` — при
  конвертации порт надо дописывать явно.
- `?mode=stream-one` переносится параметром `mode` и только для `type=xhttp`.
- `phase_uplinks` в `ops/provision-node/install.sh` подменяет `vless_id` и
  `password` построчным awk внутри uplink-блоков. Со ссылками оба секрета
  уезжают внутрь URI (у SS — ещё и в base64 вместе с `method`), и этот проход
  придётся переписывать URI-aware.

## Тесты

Раскладка по конвенции репозитория — `<dir>/tests/<basename>.rs`.

`bins/outline-ws-rust/src/config/load/tests/uplinks.rs`, рядом с существующими
`ss_share_link_*`:

- `ss://` во fallback разворачивается в combined-SS (`ws_h3` и `xhttp_h3`,
  включая `?mode=stream-one` в дайл-URL);
- `vless://` во fallback разворачивается в `vless_ws_url` / `vless_xhttp_url`
  с нужным режимом;
- `ss://`-fallback под VLESS-родителем не требует `method`/`password`;
- `link` вместе с любым явным wire-полем — ошибка;
- `link` вместе с несовпадающим `transport` — ошибка;
- fallback без `transport` и без `link` — ошибка с нашим текстом;
- `fwmark` / `ipv6_first` / `fingerprint_profile` продолжают наследоваться от
  родителя при заданном `link`;
- `#NAME` в ссылке не влияет на идентичность uplink'а.

`bins/outline-ws-rust/src/http/control/uplinks_crud/tests/uplinks_crud.rs`:

- create и patch с `link` во fallback проходят валидацию;
- в записанном TOML остаётся `link`, а не развёрнутые поля;
- fallback без `transport` в JSON принимается, когда есть `link`.

Гейт перед коммитом — команды из корневого `AGENTS.md` (`fmt --check`, `clippy
--all-targets -D warnings`, `test --workspace --exclude sockudo-ws`).

## Документация

- `bins/outline-ws-rust/config.toml` — пример uplink'а, у которого primary и все
  fallback'и заданы ссылками.
- `bins/outline-ws-rust/docs/UPLINK-CONFIGURATIONS.md` и `.ru.md` — раздел про
  `link` во fallback: правила взаимоисключения, наследование, вывод транспорта,
  и явная оговорка, что split `tcp_*` / `udp_*` URL-формы по-прежнему не имеет.
  Обе стороны правятся одним изменением.

## Вне объёма

- Параметр вида `carrier=ws_h3` для явной записи режима в ссылке (сейчас режим
  выводится из `type` + `alpn`).
- Миграция боевых конфигов парка на ссылки и URI-aware переписывание
  `phase_uplinks` в `ops/provision-node/install.sh`.
- Split-раскладка `tcp_*` / `udp_*` в форме ссылки.
