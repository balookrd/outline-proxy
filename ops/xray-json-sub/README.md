# JSON-подписка с балансером cloud1+cloud2

Генератор Xray-JSON подписок для клиентов xray-семейства (Happ, hiddify,
v2rayN). На каждого VLESS-юзера пишет `<user>.json` — один полный конфиг Xray,
который балансирует трафик между `cloud1` и `cloud2` и сам уводит его с
упавшего или деградировавшего узла.

Дизайн: [`docs/superpowers/specs/2026-08-11-happ-xray-json-subscription-design.md`](../../docs/superpowers/specs/2026-08-11-happ-xray-json-subscription-design.md).

## Зачем не обычные ссылки

Обычные `vless://` раздаются на `cloud.beerloga.su`, у которого две A-записи —
клиент попадает на случайный узел и остаётся на нём. Своей балансировки у Happ
нет: `subscription-autoconnect-type: lowestdelay` выбирает сервер в момент
запуска приложения, а не следит за ним, а `fallback-url` — резерв URL подписки,
то есть про доставку конфига, а не про трафик.

JSON-подписка обходит это: Happ отдаёт такой конфиг ядру Xray как есть, а у
ядра есть `routing.balancers` и `burstObservatory`.

Цена — в JSON-режиме routing-профили и geo-настройки самого Happ к конфигу
**не применяются**. Вся маршрутизация теперь живёт внутри JSON.

## Шесть ног: две оси отказа

| tag | узел | транспорт | ALPN |
|---|---|---|---|
| `cloud1-xhttp-h3` | cloud1.beerloga.su:443 | xhttp, `stream-one` | `["h3"]` → QUIC/UDP |
| `cloud2-xhttp-h3` | cloud2.beerloga.su:443 | xhttp, `stream-one` | `["h3"]` → QUIC/UDP |
| `cloud1-xhttp-h2` | cloud1.beerloga.su:443 | xhttp, `stream-one` | `["h2"]` → TCP |
| `cloud2-xhttp-h2` | cloud2.beerloga.su:443 | xhttp, `stream-one` | `["h2"]` → TCP |
| `cloud1-ws` | cloud1.beerloga.su:443 | ws | `["http/1.1"]` → TCP |
| `cloud2-ws` | cloud2.beerloga.su:443 | ws | `["http/1.1"]` → TCP |

Отказ раскладывается по двум независимым осям — узел и транспорт. Режут UDP —
остаются четыре TCP-ноги. Ломается XHTTP-совместимость — остаются WS. Умирает
узел — остаются три ноги соседа.

Адресация **поимённая**, а не через `cloud.beerloga.su`: иначе round-robin DNS
сам решит, куда пойдёт «cloud1-нога», и observatory будет мерить не тот узел, за
который отчитывается. Сертификаты на обоих узлах покрывают и `cloudN`, и общий
`cloud`, так что SNI совпадает с адресом.

Балансировка — `leastPing` поверх `burstObservatory` (проба
`https://www.gstatic.com/generate_204`, интервал 30 с, таймаут 5 с, sampling 3).
Проба идёт **через** ногу, то есть меряет весь путь вход → exit → интернет, а не
только живость входного узла.

## ⚠️ Порядок outbounds — инвариант

**Шесть прокси-ног идут первыми, `direct` и `block` — последними.**

Балансер `leastPing` до первой пробы отправляет трафик в `outbounds[0]`. Если в
этом слоте окажется `direct`, весь трафик первые ~30 секунд после старта потечёт
мимо туннеля, и отказ будет молчаливым. Не переставляйте `direct` вверх «для
читаемости».

Побочный эффект того же механизма, проверенный на живом ядре: если мертва именно
нога №1, **первое** соединение после старта отобьётся (`Connection reset`), а со
второй попытки балансер уже опирается на пробы и уходит на живую ногу. Это
ожидаемое поведение, а не дефект конфига.

## ⚠️ ALPN — селектор, а не список предпочтений

У xray-клиента `alpn` выбирает ровно одну версию HTTP, а не задаёт порядок
предпочтений: при `["h3","h2"]` ядро возьмёт h2. Поэтому каждая нога несёт
одно значение, а h3 и h2 разведены по разным ногам. Строка `alpn=h3,h2` из наших
access-key URI сюда не переносится.

WS-ноги остаются на `http/1.1`, и это ограничение **клиента**, а не сервера.
`outline-ss-rust` умеет WebSocket поверх h2 (RFC 8441 Extended CONNECT) и h3
(RFC 9220), но у xray этого нет — его `wsSettings` делает классический
HTTP/1.1 Upgrade. Поставить на WS-ногу `["h2"]` значит договориться по TLS на h2
и следом полезть с h1-Upgrade; дил отобьётся. Само ядро при старте это
подтверждает строкой `The feature WebSocket transport (with ALPN http/1.1, etc.)
is deprecated`.

## Маршрутизация внутри конфига

`domainStrategy: AsIs` — домены уезжают на сервер доменами, локального резолва
и утечки DNS нет. Правила: приватные диапазоны → `direct`, всё остальное → в
балансер.

Приватные диапазоны прописаны **явными CIDR**, а не `geoip:private`: в
JSON-режиме Happ сам решает, какие фрагменты geo-баз отдать ядру, и зависеть от
этого не хочется. По той же причине в конфиге нет ни одного `geosite:`.

Блока `dns` нет: при `AsIs` резолвить нечего, а системный туннельный DNS Happ
настраивает сам (в JSON-режиме поля Remote DNS переименованы в Tunnel DNS и в
конфиг не инжектятся).

На `socks-in` включён sniffing (`destOverride: ["http","tls","quic"]`) — без
него из TUN приезжает локально разрезолвленный IP и на сервер уходит адрес
вместо домена.

## Запуск

На узле, со значениями по умолчанию:

```bash
sudo /opt/outline/outline-ss-rust/generate_xray_json.py
```

Читает `/opt/outline/outline-ss-rust/config.toml` и пишет `<user>.json` в
`/var/www/html/<keys-prefix>/` — тот же каталог, что и `.conf`-артефакты
`save-keys.sh`. Пути VLESS берутся из `[websocket]` того же конфига, а не
зашиваются. Юзеры без `vless_id` (только Shadowsocks) пропускаются с
предупреждением в stderr.

Флаги:

| Флаг | Значение по умолчанию |
|---|---|
| `--config` | `/opt/outline/outline-ss-rust/config.toml` |
| `--out-dir` | `/var/www/html/<keys-prefix>` |
| `--node` | `cloud1.beerloga.su`, `cloud2.beerloga.su`; повторяется на каждый узел |

Запись атомарная (временный файл + `os.replace`, права `0644`) — клиент не
поймает полуфайл на обновлении подписки.

Проверить результат, не светя креды в терминал:

```bash
sudo jq -r '.[0].outbounds[].tag' /var/www/html/<keys-prefix>/<user>.json
```

`cat` сгенерированного файла выводит `vless_id` — не делайте этого.

## Ссылка для клиента

```
https://cloud.beerloga.su/<keys-prefix>/<user>.json
```

Раздаётся уже работающей статикой: nginx `:80` ← `[http_fallback]` ←
TLS-терминация `outline-ss-rust`. Новых location в nginx не требуется. Сегмент
пути — тот же секретный каталог, что и у `.conf`.

В Happ добавляется как подписка; профиль называется `<user> cloud-balancer`.

## Раскатка

```bash
rsync -a ops/xray-json-sub/generate_xray_json.py \
  sysadm@cloud2.beerloga.su:/tmp/generate_xray_json.py
ssh sysadm@cloud2.beerloga.su \
  'sudo -n install -o root -g root -m 0755 /tmp/generate_xray_json.py \
     /opt/outline/outline-ss-rust/generate_xray_json.py && rm /tmp/generate_xray_json.py'
```

Ставится на **оба** узла: файлы выходят побайтово одинаковыми (топология в них
общая), зато подписка переживает падение любого из узлов. По одному узлу за раз,
`cloud2` первым — на него из-за round-robin приходит меньше клиентов. Рестарт
сервисов не нужен: скрипт только пишет файлы, которые nginx уже раздаёт с диска.

Вызов дописывается в `/opt/outline/outline-ss-rust/save-keys.sh` после
генерации `.conf`, чтобы артефакты не разъезжались. Строка с
`--write-access-keys-dir` должна остаться **первой** в файле: её оттуда
выпарсивает `ops/provision-node/collect-from-reference.sh`.

## Тесты

```bash
python3 ops/xray-json-sub/test_generate_xray_json.py -v
```

25 тестов, stdlib-only, ничего за пределами временного каталога не трогают и в
сеть не ходят. Отдельно закреплены оба инварианта выше — порядок outbounds и
значения ALPN.

Схему конфига юнит-тесты не проверяют: опечатка в имени поля внутри
`xhttpSettings` сериализуется в валидный JSON. Это ловится только живым ядром:

```bash
xray run -c <распакованный из массива конфиг>
curl --socks5-hostname 127.0.0.1:10808 https://ifconfig.me
```

## Известная слепая зона

Пробы observatory идут через ту же ногу, что и трафик, поэтому падение узла и
деградацию пути они ловят. А отказ вида «узел отвечает, трафик утёк мимо
туннеля» — как 2026-08-11, когда `systemd-networkd` снёс `ip rule` на `ws0` —
прошёл бы зелёными пробами. Балансер этот класс отказов не закрывает.
