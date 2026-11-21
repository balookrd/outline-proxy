# Выкладка бинаря на узел

`deploy-binary.sh` выкладывает один локально собранный бинарь
(`outline-server` или `outline-client`) на один узел: бэкап, ротация
бэкапов, рестарт, проверка `/metrics` и автооткат.

Реальные имена узлов, домены и адреса парка в этом документе заменены условными: `fleet.example` — домен парка; `exit-a`, `exit-b` — выходные узлы; `relay-a`…`relay-d` — промежуточные cloud-узлы; `198.51.100.0/24` — домашняя сеть (`.102`, `.104` и т. д. — последний октет). Соответствие — в локальном некоммитируемом `FLEET.local.md`.

Требования:

- на рабочей станции — `ssh`, `scp`, `file` и `sha256sum` либо `shasum`;
- на узле — вход по ключу (скрипт ходит с `BatchMode=yes`), `sudo` без пароля
  (`sudo -n`), `curl`, GNU `find` (`-printf`), бинарь в `/usr/local/bin/<unit>`,
  systemd-юнит с тем же именем.

## Отличие от `install-*.sh`

`install-client.sh` и `install-server.sh` ставят релиз из тарболла и тоже делают
бэкап `<bin>.bak.YYYYMMDDHHMMSS` с ротацией (оставляют 3). Рабочая выкладка
обычно идёт мимо них: собрали локально, скопировали на узел через `scp`,
подменили, перезапустили. При ручной выкладке бэкап, ротация и проверка
после рестарта не делались или делались через раз.

К 2026-07-23 на семи узлах накопилось 112 бэкапов общим объёмом 1.6 ГБ в трёх
схемах именования, включая июньские.

## Запуск

```bash
ops/deploy/deploy-binary.sh <host> <unit> <local-binary> [keep]
```

| Аргумент | Что это |
|---|---|
| `<host>` | ssh-цель, например `sysadm@relay-c.fleet.example` |
| `<unit>` | `outline-server` или `outline-client`; другое значение — ошибка |
| `<local-binary>` | путь к собранному бинарю |
| `[keep]` | сколько бэкапов оставить, по умолчанию 3 |

```bash
# клиент на x86_64-узел
ops/deploy/deploy-binary.sh sysadm@relay-c.fleet.example outline-client \
  target/x86_64-unknown-linux-musl/release/outline-client

# сервер на ARM-узел, оставить 5 бэкапов вместо 3
ops/deploy/deploy-binary.sh mmv@198.51.100.104 outline-server \
  target/aarch64-unknown-linux-musl/release/outline-server 5
```

Порт метрик скрипт берёт из имени юнита: `outline-client` → 9091,
`outline-server` → 9090. Если на узле `[metrics] listen` другой, проверка
`/metrics` не пройдёт и скрипт откатит бинарь.

## Шаги скрипта

1. Определяет архитектуру бинаря через `file -b` и сверяет с `uname -m` на
   узле. При несовпадении выходит с ошибкой, ничего не меняя. Парк смешанный:
   `.104` — aarch64, остальные — x86_64.
2. Копирует бинарь во временный `/tmp/<unit>.deploy.<pid>` и сверяет sha256
   с локальным.
3. Снимает бэкап `/usr/local/bin/<unit>.bak.YYYYMMDDHHMMSS` через `cp -a`:
   режим и владелец сохраняются, и откат возвращает файл с прежними правами.
4. Удаляет старые бэкапы `<unit>.bak.*`, оставляя `keep` самых свежих по
   mtime. Сортировка по имени здесь не годится: на парке рядом лежат
   `.bak.20260716125448` и `.bak.pre-catA`, и по алфавиту свежий `pre-catA`
   стоит перед старым `reno-remnant`, так что алфавитная ротация удалила бы
   актуальный откат. На реальном наборе имён старая логика удаляла самый
   свежий бэкап.
5. Ставит бинарь через `install -o root -g root -m 0755` и делает
   `systemctl restart <unit>`.
6. До 15 раз с паузой 2 с проверяет `systemctl is-active` и код ответа
   `http://127.0.0.1:<port>/metrics`; успех — 200. Одного `is-active` мало:
   systemd считает юнит активным и при зависшем рантайме (см. `ops/watchdog/`).
7. Если `/metrics` так и не ответил 200, возвращает только что снятый бэкап,
   перезапускает юнит и выходит с кодом 1.
8. Сверяет sha256 установленного бинаря с локальным и печатает число
   оставшихся бэкапов.

## Проверка на relay-d, 2026-07-23

Прогон на relay-d (резервный узел):

- ARM-бинарь на x86_64-узел — отказ, `exit=1`, на узле ничего не изменено;
- обычная выкладка — бэкап снят, `/metrics` 200, sha256 совпал;
- 7 бэкапов при `keep=3` — удалены 4, остались три самых свежих по mtime,
  включая `pre-catA`; удалён `zzz-old-but-late-alphabet`, который алфавитная
  сортировка оставила бы.

## Миграция узла со старых имён (`migrate-node-rename.sh`)

`migrate-node-rename.sh` выполняет чистый перевод одного узла парка со старых
имён (`outline-ss-rust` / `outline-ws-rust`, пользователь `outline-ws`) на
`outline-server` / `outline-client` без создания симлинков и `Alias=`, со
снимком состояния и полным автооткатом при сбое.

Узлы парка переводятся строго по одному за раз в порядке: `--audit` →
`--dry-run` → рабочий запуск.

### Запуск

```bash
ops/deploy/migrate-node-rename.sh <host> <server|client|all> [--audit | --dry-run]
```

| Аргумент / опция | Что это |
|---|---|
| `<host>` | ssh-цель, например `sysadm@exit-a.fleet.example` |
| `<role>` | `server` (`outline-server`), `client` (`outline-client`) или `all` (оба сервиса; если на узле запущены или установлены оба старых сервиса, по-ролевые `server`/`client` откажутся, чтобы не сломать watchdog соседа) |
| `--audit` | только чтение состояния узла: юниты, инстансы, drop-in, пользователи/группы (вкл. `certs`), `post-up.service`, `outline-ws0-routing.service`, `/opt/outline/outline-*`, ссылки в конфигах, `/opt/network/*.sh`, скриптах и `cron` |
| `--dry-run` | проверка локальных бинарей, архитектуры и SHA-256 + печать плана миграции на узле без изменений |

По умолчанию скрипт берёт бинари из `target/<arch>-unknown-linux-musl/release/outline-{server,client}`;
пути можно переопределить через переменные окружения `SERVER_BIN` и `CLIENT_BIN`.

```bash
# 1. Read-only аудит перед миграцией
ops/deploy/migrate-node-rename.sh sysadm@exit-a.fleet.example server --audit
ops/deploy/migrate-node-rename.sh sysadm@relay-a.fleet.example all --audit

# 2. Пробный прогон с проверкой архитектуры и контрольных сумм
ops/deploy/migrate-node-rename.sh sysadm@exit-a.fleet.example server --dry-run
ops/deploy/migrate-node-rename.sh sysadm@relay-c.fleet.example client --dry-run

# 3. Боевая миграция по ролям (строго по одному узлу за раз)
ops/deploy/migrate-node-rename.sh sysadm@exit-a.fleet.example server
ops/deploy/migrate-node-rename.sh sysadm@relay-c.fleet.example client
ops/deploy/migrate-node-rename.sh sysadm@relay-a.fleet.example all
ops/deploy/migrate-node-rename.sh mmv@198.51.100.104 all
ops/deploy/migrate-node-rename.sh mmv@198.51.100.102 all
```

### Что делает скрипт и гарантии отката

1. Работает через единое SSH-соединение (`ControlMaster=auto`, `ControlPersist=60`),
   чтобы серия команд не спровоцировала `sshguard`.
2. Сверяет `file -b` локальных бинарей с `uname -m` на узле, переносит бинари,
   `ops/watchdog/outline-watchdog` и unit-файлы во временный каталог на узле и
   проверяет SHA-256.
3. Сохраняет снимок текущего состояния (бинари, `/etc/outline-*`, юниты и
   drop-in'ы, `post-up.service`, `outline-ws0-routing.service`, `/opt/network`,
   `/opt/outline/outline-*`, `/opt/outline/access-keys/generate_keys.py`,
   `/opt/ddns/*/permission-certs.sh`, `/opt/beerloga/permission-certs.sh`,
   `/etc/default/nanopi104-backup`, цели симлинков, состояние юнитов/таймеров и
   записи `passwd`/`group`) в `/var/tmp/outline-rename-rollback.<timestamp>` (`0700`).
4. Перед изменениями проверяет, что запрошенная роль совместима с соседним
   сервисом на узле (на dual-role хосте допустима только роль `all`) и узел ещё
   не переведён на новые имена (после миграции для обновлений используйте
   `deploy-binary.sh`).
5. Останавливает старые таймеры и юниты (включая все инстансы `outline-ws-rust@*.service`).
6. Переименовывает группы и пользователей (`outline-ss-rust` → `outline-server` с
   сохранением членства в `certs`; `outline-ws` → `outline-client`), переносит
   каталоги `/etc`, `/var/lib`, `/var/log` и `/opt/outline/outline-{ss,ws}-rust`
   → `/opt/outline/outline-{server,client}`.
7. Обновляет пути внутри `config.toml` (и `instances/*.toml`), выставляя
   владельцев и права (`0750` на каталоги, `0640` на конфиги) строго после
   `sed -i`; обновляет drop-in'ы, `save-keys.sh`/`generate_keys.py`, права на
   `users.txt` (`root:outline-server`, `0640`), `permission-certs.sh`,
   `outline-ws0-routing.service`, `/opt/network/*.sh` (вкл. `outline-ws` и с
   сохранением `+x` на `init-ws0.sh` и исполняемых `*.sh`), `post-up.service` и
   `/etc/default/nanopi104-backup`.
8. Устанавливает новые бинари, `outline-watchdog` и unit-файлы, удаляет старые,
   выполняет `systemctl daemon-reload`, включает и перезапускает службы
   (разделяя `enabled` и ранее `active` инстансы `outline-client@*.service`, а
   таймеры `outline-watchdog@*.timer` — при наличии шаблона) и проверяет
   `http://127.0.0.1:<port>/metrics` (`9090` / `9091`, HTTP 200 до 15 попыток).
   При любом сбое автоматически откатывает все изменения из `$ROLLBACK`.
