# Генерация access-key артефактов

Генератор клиентских конфигов для узлов `outline-ss-rust`. Читает `config.toml`
узла и пишет **три файла на юзера** в тот же каталог, откуда их раздаёт nginx.

Дизайн: [`docs/superpowers/specs/2026-08-11-access-keys-to-python-design.md`](../../docs/superpowers/specs/2026-08-11-access-keys-to-python-design.md).

| Файл | Условие | Содержимое |
|---|---|---|
| `<user>.conf` | есть `password` | Outline YAML |
| `<user>.json` | есть `vless_id` и путь VLESS | Xray-подписка с балансером cloud1+cloud2 |
| `<user>.txt` | есть хоть один URL | все URL юзера, по одному в строке |

Первая строка `<user>.txt` — `ssconf://` на собственный `.conf` (ссылка для
Outline-клиента), дальше `ss://` и `vless://` по носителям в том же порядке, в
каком их генерировал бинарь.

## Откуда это взялось

Раньше `.conf` генерировал сам `outline-ss-rust` (режим `--write-access-keys-dir`),
и на юзера приходилось до семи файлов — по одному на носитель. Правка формата
ссылок требовала пересборки бинаря и выкладки на весь парк, а совместимость с
xray-клиентами правилась много раз подряд.

**URI при переносе не изменились ни на байт** — поменялась только раскладка по
файлам. Это закреплено golden-корпусом в [`golden/`](golden/): синтетический
конфиг плюс 32 артефакта, снятых с бинаря до переноса. Тесты собирают те же
артефакты питоном и сверяют побайтово. Эталон — источник истины; если тест упал,
неправ Python.

## Запуск

```bash
sudo /opt/outline/access-keys/generate_keys.py
```

| Флаг | Значение по умолчанию |
|---|---|
| `--config` | `/opt/outline/outline-ss-rust/config.toml` |
| `--out-dir` | `/var/www/html/<keys-prefix>` |
| `--file-extension` | из `[access_keys] file_extension`, иначе `.yaml` |
| `--node` | `cloud1.beerloga.su`, `cloud2.beerloga.su`; повторяется на каждый узел |
| `--dry-run` | всё отрендерить, ничего не писать |

**`--file-extension` на узлах обязателен.** В боевых `config.toml` ключа
`file_extension` нет — расширение `.conf` раньше передавалось бинарю флагом
`--access-key-file-extension`. Без флага генератор возьмёт дефолт `.yaml`, и
клиенты, ходящие за `<user>.conf`, получат 404.

**`--node` задаёт узлы балансера в `.json`.** На cloud-узлах это пара
cloud1+cloud2 (дефолт). На `nuxt` / `nuxt2` передаётся собственный хост: там
подписка должна вести на тот узел, который её и раздаёт, а не на cloud-пару.

Отчёт печатается в stdout — `save-keys.sh` перенаправляет его в `users.txt`.
Формат: блок на юзера (`user:`, `written_conf:`, `written_json:`,
`written_txt:`, `config_url:`, `access_key_url:`). Старый бинарь печатал блок на
**артефакт**; это единственное намеренное расхождение, отчёт никто не парсит.

Запись атомарная (временный файл + `os.replace`, права `0644`) — клиент не
поймает полуфайл.

Проверить результат, не светя креды:

```bash
sudo jq -r '.[0].outbounds[].tag' /var/www/html/<keys-prefix>/<user>.json
```

`cat` любого артефакта выводит пароль или `vless_id` — не делайте этого.

## Как разрешаются поля

Пути и `method` берутся **на юзера**: своё значение в `[[users]]` бьёт
глобальное из `[websocket]` / `[shadowsocks]`. Так же их разрешает сервер
(`UserEntry::effective_*`), и на проде это не теория — служебные учётки
межузловых аплинков несут свои пути.

`enabled = false` исключает юзера целиком. Юзер без `password` не получает
`.conf`, без `vless_id` — не получает `.json`. Дубликат `id` — ошибка.

## ⚠️ ALPN — селектор, а не список предпочтений

У xray-клиента `alpn` выбирает ровно одну версию HTTP. Поэтому списки зависят от
носителя:

| Носитель | `[server.h3]` поднят | иначе |
|---|---|---|
| WS | `h3,h2,http/1.1` | `h2,http/1.1` |
| XHTTP `packet-up` | `h3,h2,http/1.1` | `h2,http/1.1` |
| XHTTP `stream-one` | `h3,h2` | `h2` |

`stream-one` не получает `http/1.1`: поверх h1 он отбивается с 505 (hyper не
умеет full-duplex), и предлагать клиенту этот транспорт значит приглашать его в
дил, который сразу отвалится. При `public_scheme = ws` параметра нет вовсе —
ALPN это расширение TLS.

Признак «h3 поднят» считается как в Rust: h3 включён (своя пара сертов, иначе
унаследованная от `[server]`, либо непустой массив сертов — причём
`[server.h3].certs` наследует `[server].certs`, только если ключ опущен целиком;
явный `certs = []` от наследования отказывается) **и** у него задан `listen`.

## ⚠️ Порядок outbounds в `.json`

Шесть прокси-ног идут первыми, `direct` и `block` — последними. Балансер
`leastPing` до первой пробы отправляет трафик в `outbounds[0]`; окажись там
`direct`, весь трафик первые ~30 секунд потёк бы мимо туннеля молча.

Побочный эффект того же механизма, проверенный на живом ядре: если мертва
именно нога №1, первое соединение после старта отобьётся, а со второй попытки
балансер уже опирается на пробы. Это ожидаемо, не дефект.

WS-ноги остаются на `http/1.1`, и это ограничение клиента: `outline-ss-rust`
умеет WebSocket поверх h2 (RFC 8441) и h3 (RFC 9220), а xray — нет.

## Тесты

```bash
python3 -m unittest discover -s ops/access-keys -p "test_*.py"
```

99 тестов, stdlib-only, в сеть не ходят и за пределы временного каталога не
пишут. Главный из них — `test_artifacts.py`: собирает все 32 артефакта и
сверяет с golden побайтово.

Переснять эталон (только вместе с осознанным изменением формата ссылок, и diff
эталона обязан быть в том же коммите):

```bash
cargo build -p outline-ss-rust
./target/debug/outline-ss-rust \
  --config ops/access-keys/golden/config.toml \
  --write-access-keys-dir ops/access-keys/golden/expected \
  > ops/access-keys/golden/expected-users.txt
```

## Раскатка

```bash
ssh sysadm@<node> 'sudo -n install -d -o root -g root -m 0755 /opt/outline/access-keys'
rsync -a --delete --exclude '__pycache__' --exclude 'test_*.py' --exclude 'golden' \
  ops/access-keys/ sysadm@<node>:/tmp/access-keys/
ssh sysadm@<node> 'sudo -n cp -a /tmp/access-keys/. /opt/outline/access-keys/ \
  && rm -rf /tmp/access-keys && sudo -n chown -R root:root /opt/outline/access-keys \
  && sudo -n chmod 0755 /opt/outline/access-keys/generate_keys.py'
```

По одному узлу за раз. Рестарт сервисов не нужен: пишутся файлы, которые nginx
уже раздаёт с диска. Вызов прописывается в `save-keys.sh` вместо прежнего
`outline-ss-rust --write-access-keys-dir`.

Заголовки подписки (`profile-title`, `profile-update-interval`) добавляет nginx —
блок в [`nginx-subscription-headers.conf`](nginx-subscription-headers.conf),
вставляется в `server`-блок `sites-available/beerloga.su`. Покрывает и `.json`,
и `.txt`.

`ops/provision-node/collect-from-reference.sh` определяет каталог ключей,
выпарсивая его из `save-keys.sh`, и понимает обе формы: старую
(`--write-access-keys-dir`) и новую (`--out-dir`).

## Известная слепая зона

Пробы observatory в `.json` идут через ту же ногу, что и трафик, поэтому падение
узла и деградацию пути они ловят. А отказ вида «узел отвечает, а трафик утёк
мимо туннеля» — как 2026-08-11, когда `systemd-networkd` снёс `ip rule` на
`ws0` — прошёл бы зелёными пробами.
