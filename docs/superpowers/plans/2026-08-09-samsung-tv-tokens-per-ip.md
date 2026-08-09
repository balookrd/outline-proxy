# samsung_tv: токены по исходящему IP — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Научить `samsung_tv` хранить токен авторизации отдельно для каждого
исходящего IP, чтобы под мог переезжать между нодами кластера без повторной
авторизации на телевизорах.

**Architecture:** Вместо одного поля `token` у устройства — словарь
`tokens: {ip: token}`. Ключ вычисляется на лету: UDP-`connect()` к адресу
телевизора заставляет ядро выбрать маршрут, и `getsockname()` отдаёт адрес,
который телевизор увидит источником. Поддержки старого формата в коде нет —
единственный существующий токен переносится разовой правкой файла на NAS.

**Tech Stack:** Python 3.14, aiohttp (WebSocket к ТВ), pytest с
`asyncio_mode=auto`, сервисы — однофайловые скрипты, загружаемые в тестах через
`importlib` (см. `tests/conftest.py`).

Спека: [`docs/superpowers/specs/2026-08-09-samsung-tv-tokens-per-ip-design.md`](../specs/2026-08-09-samsung-tv-tokens-per-ip-design.md).

## Global Constraints

- Репозиторий кода: `~/Yandex.Disk.localized/IdeaProjects/smarthome`, работаем в
  `main`. Манифесты и спеки — в `outline-proxy`.
- Формат хранения: `device['tokens']` — словарь `{исходящий_ip: token}`.
  Поле `token` кодом **не читается и не пишется**.
- `local_ip_for(addr)` вычисляется **на каждый телевизор отдельно**, не один раз
  на процесс: у ноды два интерфейса, и `status.hostIP` (`10.10.10.5x`) — не тот
  адрес, что видят телевизоры (`198.18.1.5x` через `wan0`).
- `local_ip_for` при ошибке возвращает `None`; тогда токен считается пустым —
  поведение как при отсутствии токена сегодня.
- Автомиграции в коде нет. Существующий токен принадлежит `198.18.1.51` и
  переносится разовой правкой `devices.json` на NAS
  (`198.18.1.125:/mnt/HD/HD_a2/k8s/smarthome/samsung_tv/`).
- Тесты — в `tests/services/test_samsung_tv.py`, стиль существующих: фикстура
  `samsung_tv` из `conftest.py`, `monkeypatch` для подмены сетевых вызовов.
- Тег образа — короткий git-sha, сборка `./build-and-push.sh samsung_tv`
  (скрипт откажется работать на грязном дереве).
- WoL в этот план **не входит**: он не связан с токенами и остаётся открытым.
- Git: коммиты на английском, без Co-Authored-By и Claude-атрибуции.
  `git commit` — только по явной команде владельца.

---

### Task 1: `local_ip_for` — определение исходящего адреса

**Files:**
- Modify: `services/samsung_tv/samsung_tv.py` (добавить функцию после
  `wake_on_lan`, около строки 126)
- Test: `tests/services/test_samsung_tv.py`

**Interfaces:**
- Produces: `local_ip_for(addr: str) -> str | None` — адрес, с которого уйдёт
  трафик к `addr`, либо `None` при ошибке. Задача 2 использует его в `send_key`.

- [ ] **Step 1: Написать падающие тесты**

Добавить в конец `tests/services/test_samsung_tv.py`:

```python
def test_local_ip_for_returns_address(samsung_tv):
    # 8.8.8.8 не опрашивается: UDP-connect только выбирает маршрут,
    # ни одного пакета не отправляется.
    ip = samsung_tv.local_ip_for('8.8.8.8')
    assert ip is not None
    assert ip.count('.') == 3


def test_local_ip_for_loopback(samsung_tv):
    assert samsung_tv.local_ip_for('127.0.0.1') == '127.0.0.1'


def test_local_ip_for_bad_address_returns_none(samsung_tv):
    # Не-адрес: getaddrinfo падает, функция обязана вернуть None, а не бросить
    assert samsung_tv.local_ip_for('not-an-address.invalid') is None
```

- [ ] **Step 2: Убедиться, что тесты падают**

```bash
cd ~/Yandex.Disk.localized/IdeaProjects/smarthome
python3 -m pytest tests/services/test_samsung_tv.py -k local_ip_for -v
```

Ожидаемо: три FAIL с `AttributeError: module ... has no attribute 'local_ip_for'`.

- [ ] **Step 3: Реализовать функцию**

Вставить в `services/samsung_tv/samsung_tv.py` сразу после функции
`wake_on_lan` (перед `async def load_devices`):

```python
def local_ip_for(addr):
    """Адрес, который увидит источником устройство addr.

    Samsung привязывает токен авторизации к IP клиента, а в кластере это адрес
    ноды — он меняется при переезде пода. UDP-connect не отправляет пакетов, он
    лишь заставляет ядро выбрать маршрут; getsockname() после этого возвращает
    нужный локальный адрес.

    Считается на каждое устройство отдельно: у ноды несколько интерфейсов, и
    адрес хоста (10.10.10.x, интерконнект) — не тот, с которого уходит трафик к
    телевизорам (198.18.1.x).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as soc:
            soc.connect((addr, wol_port))
            return soc.getsockname()[0]
    except OSError as e:
        logger.warning(f"local_ip_for {addr}: {type(e).__name__}: {e}")
        return None
```

- [ ] **Step 4: Убедиться, что тесты проходят**

```bash
cd ~/Yandex.Disk.localized/IdeaProjects/smarthome
python3 -m pytest tests/services/test_samsung_tv.py -k local_ip_for -v
```

Ожидаемо: три PASS.

- [ ] **Step 5: Прогнать весь набор тестов сервиса**

```bash
python3 -m pytest tests/services/test_samsung_tv.py -v
```

Ожидаемо: все прежние 13 тестов плюс три новых — PASS.

- [ ] **Step 6: Commit**

```bash
cd ~/Yandex.Disk.localized/IdeaProjects/smarthome
git add services/samsung_tv/samsung_tv.py tests/services/test_samsung_tv.py
git commit -m "feat(samsung_tv): resolve the source address used to reach a TV"
```

---

### Task 2: Токен на пару «телевизор + исходящий IP»

**Files:**
- Modify: `services/samsung_tv/samsung_tv.py` (`send_key`, строки 63–91)
- Test: `tests/services/test_samsung_tv.py`

**Interfaces:**
- Consumes: `local_ip_for(addr) -> str | None` из Задачи 1.
- Produces: `send_key` читает `device['tokens'][src_ip]` и туда же пишет новый
  токен. Поле `token` не используется.

- [ ] **Step 1: Написать падающие тесты**

Добавить в конец `tests/services/test_samsung_tv.py`:

```python
def test_token_for_picks_by_source_ip(samsung_tv, monkeypatch):
    monkeypatch.setattr(samsung_tv, 'local_ip_for', lambda addr: '198.18.1.52')
    device = {'ip': '198.18.1.91',
              'tokens': {'198.18.1.51': 'first', '198.18.1.52': 'second'}}
    assert samsung_tv.token_for(device) == ('198.18.1.52', 'second')


def test_token_for_unknown_ip_gives_empty(samsung_tv, monkeypatch):
    monkeypatch.setattr(samsung_tv, 'local_ip_for', lambda addr: '198.18.1.53')
    device = {'ip': '198.18.1.91', 'tokens': {'198.18.1.51': 'first'}}
    assert samsung_tv.token_for(device) == ('198.18.1.53', '')


def test_token_for_ignores_legacy_field(samsung_tv, monkeypatch):
    # Старое поле token принадлежит другому клиенту (.102) и не должно
    # подставляться: телевизор ответит запросом авторизации, а код решил бы,
    # что токен есть.
    monkeypatch.setattr(samsung_tv, 'local_ip_for', lambda addr: '198.18.1.51')
    device = {'ip': '198.18.1.91', 'token': 'legacy'}
    assert samsung_tv.token_for(device) == ('198.18.1.51', '')


def test_remember_token_stores_under_source_ip(samsung_tv):
    device = {'ip': '198.18.1.91'}
    samsung_tv.remember_token(device, '198.18.1.53', 'fresh')
    assert device['tokens'] == {'198.18.1.53': 'fresh'}


def test_remember_token_keeps_other_ips(samsung_tv):
    device = {'ip': '198.18.1.91', 'tokens': {'198.18.1.51': 'first'}}
    samsung_tv.remember_token(device, '198.18.1.52', 'second')
    assert device['tokens'] == {'198.18.1.51': 'first', '198.18.1.52': 'second'}


def test_remember_token_without_source_ip_is_noop(samsung_tv):
    device = {'ip': '198.18.1.91'}
    samsung_tv.remember_token(device, None, 'fresh')
    assert 'tokens' not in device
```

- [ ] **Step 2: Убедиться, что тесты падают**

```bash
cd ~/Yandex.Disk.localized/IdeaProjects/smarthome
python3 -m pytest tests/services/test_samsung_tv.py -k "token_for or remember_token" -v
```

Ожидаемо: шесть FAIL с `AttributeError` — функций ещё нет.

- [ ] **Step 3: Добавить хелперы**

Вставить в `services/samsung_tv/samsung_tv.py` сразу после `local_ip_for`:

```python
def token_for(device):
    """(исходящий_ip, токен) для устройства. Токен пуст, если его ещё нет.

    Старое поле device['token'] сознательно игнорируется: оно принадлежит тому
    клиенту, который авторизовался последним, и на другом IP телевизор его не
    примет — а код считал бы, что токен есть, и ошибка выглядела бы как
    молчаливый ms.channel.timeOut.
    """
    src_ip = local_ip_for(device.get('ip'))
    tokens = device.get('tokens') or {}
    return src_ip, tokens.get(src_ip, '')


def remember_token(device, src_ip, token):
    """Запомнить токен для этого исходящего адреса, не трогая остальные."""
    if not src_ip:
        return
    device.setdefault('tokens', {})[src_ip] = token
```

- [ ] **Step 4: Убедиться, что тесты проходят**

```bash
python3 -m pytest tests/services/test_samsung_tv.py -k "token_for or remember_token" -v
```

Ожидаемо: шесть PASS.

- [ ] **Step 5: Переключить `send_key` на новые хелперы**

Заменить в `services/samsung_tv/samsung_tv.py` начало `send_key` — строки с
`addr = device.get('ip')` по `token = device.get('token', '')`:

```python
    addr = device.get('ip')
    src_ip, token = token_for(device)
```

и блок сохранения токена внутри `if event == 'ms.channel.connect':`:

```python
                if event == 'ms.channel.connect':
                    if data.get('token'):
                        remember_token(device, src_ip, data['token'])
                        await store.save(json.dumps(devices))
                    await ws.send_str(get_command(key))
```

- [ ] **Step 6: Добавить диагностику в лог ошибки авторизации**

Заменить строку с `logger.error(f"send_key {addr}: unexpected event {event}...")`:

```python
                else:
                    logger.error(
                        f"send_key {addr}: unexpected event {event} "
                        f"(src={src_ip}, token={'есть' if token else 'нет'}): {response}"
                    )
```

Без этого `ms.channel.timeOut` не отличить от «токена не было» — ровно та
неопределённость, из-за которой пришлось лезть в код при разборе.

- [ ] **Step 7: Прогнать все тесты**

```bash
cd ~/Yandex.Disk.localized/IdeaProjects/smarthome
python3 -m pytest tests/ -v 2>&1 | tail -20
```

Ожидаемо: весь набор PASS. Тест `test_load_devices_loads_valid` использует
устройство с полем `token` — он должен продолжать проходить: `load_devices`
формат не проверяет.

- [ ] **Step 8: Проверить, что поле `token` больше нигде не читается**

```bash
grep -n "\['token'\]\|get('token'" services/samsung_tv/samsung_tv.py
```

Ожидаемо: единственное совпадение — `data.get('token')`, это токен из ответа
телевизора, а не из конфига.

- [ ] **Step 9: Commit**

```bash
cd ~/Yandex.Disk.localized/IdeaProjects/smarthome
git add services/samsung_tv/samsung_tv.py tests/services/test_samsung_tv.py
git commit -m "fix(samsung_tv): keep one auth token per source address

Samsung binds the token to the client's IP, and in the cluster that is the node
address, which changes when the pod moves. With a single token field each new
authorisation overwrote the previous one, so returning to a node asked for
confirmation on the TV screen again.

The legacy token field is deliberately not read: it belongs to whoever
authorised last, and replaying it elsewhere yields ms.channel.timeOut with no
hint as to why."
```

---

### Task 3: Разовая конвертация devices.json на NAS

Делается **до** выката нового образа: пока работает старый код, файл в старом
формате, и его можно править спокойно.

**Files:** изменений в git нет; правится
`198.18.1.125:/mnt/HD/HD_a2/k8s/smarthome/samsung_tv/devices.json`.

**Interfaces:**
- Consumes: знание, что текущий токен принадлежит `198.18.1.51`.
- Produces: `devices.json` в новом формате — его читает код из Задачи 2.

- [ ] **Step 1: Убедиться, что под на k3s-1**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome get pod -l app=samsung-tv -o jsonpath='{.items[0].spec.nodeName}{"\n"}'
```

Ожидаемо: `k3s-1`. Если другая нода — токен принадлежит не `.51`, и ключ в
следующем шаге надо взять соответствующий (`k3s-2` → `198.18.1.52`,
`k3s-3` → `198.18.1.53`).

- [ ] **Step 2: Сохранить копию файла**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome exec deploy/samsung-tv -- cat /app/conf/devices.json > /tmp/samsung-devices.bak.json
python3 -c "import json;d=json.load(open('/tmp/samsung-devices.bak.json'));print([x['name'] for x in d])"
```

Ожидаемо: `['hall', 'bedroom']`. Файл сохранён — к нему можно вернуться.

- [ ] **Step 3: Сконвертировать формат**

```bash
python3 - <<'PY' > /tmp/samsung-devices.new.json
import json
src = json.load(open('/tmp/samsung-devices.bak.json'))
for d in src:
    tok = d.pop('token', None)
    if tok:
        d['tokens'] = {'198.18.1.51': tok}
print(json.dumps(src, ensure_ascii=False, indent=2))
PY
python3 -c "
import json
d=json.load(open('/tmp/samsung-devices.new.json'))
for x in d: print(x['name'], '->', 'tokens:', list((x.get('tokens') or {}).keys()), '| legacy token:', 'token' in x)
"
```

Ожидаемо: у обоих устройств `tokens: ['198.18.1.51']` и `legacy token: False`.

- [ ] **Step 4: Записать файл на NAS**

Под держит файл открытым только на чтение при старте, поэтому запись безопасна;
но чтобы сервис не перезаписал его своим состоянием, сначала гасим под:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome scale deploy/samsung-tv --replicas=0
kubectl -n smarthome wait --for=delete pod -l app=samsung-tv --timeout=180s
kubectl -n default run nas-loader --image=busybox:1.36 --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"nas-loader","image":"busybox:1.36","command":["sleep","900"],"volumeMounts":[{"name":"nas","mountPath":"/nas"}]}],"volumes":[{"name":"nas","nfs":{"server":"198.18.1.125","path":"/mnt/HD/HD_a2/k8s"}}]}}'
kubectl -n default wait --for=condition=Ready pod/nas-loader --timeout=240s
kubectl -n default cp /tmp/samsung-devices.new.json nas-loader:/nas/smarthome/samsung_tv/devices.json
kubectl -n default exec nas-loader -- sh -c 'chmod 777 /nas/smarthome/samsung_tv/devices.json; cat /nas/smarthome/samsung_tv/devices.json | head -12'
kubectl -n default delete pod nas-loader
```

Ожидаемо: в выводе видно поле `tokens`.

- [ ] **Step 5: Убрать временные файлы**

```bash
rm -f /tmp/samsung-devices.new.json
```

`/tmp/samsung-devices.bak.json` оставить до конца Задачи 4 — это путь отката.

---

### Task 4: Сборка, выкат и проверка переезда

**Files:** изменений в git нет, кроме тега образа в манифесте.

**Interfaces:**
- Consumes: код из Задач 1–2, файл из Задачи 3.
- Modify: `ops/nanopi-r5c-k3s/apps/smarthome/samsung-tv.yaml` (тег образа)

- [ ] **Step 1: Собрать и опубликовать образ**

```bash
cd ~/Yandex.Disk.localized/IdeaProjects/smarthome
./build-and-push.sh samsung_tv
```

Ожидаемо: сборка, push и строка `image: registry.k3s.beerloga.su/samsung_tv:<sha>`.
Записать `<sha>`.

- [ ] **Step 2: Прописать тег в манифесте**

В `ops/nanopi-r5c-k3s/apps/smarthome/samsung-tv.yaml` заменить строку `image:`
на новый тег из предыдущего шага.

- [ ] **Step 3: Поднять под на k3s-1 и проверить токен**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome scale deploy/samsung-tv --replicas=1
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/smarthome
kubectl apply -f samsung-tv.yaml
kubectl -n smarthome rollout status deploy/samsung-tv --timeout=300s
kubectl -n smarthome get pod -l app=samsung-tv -o jsonpath='{.items[0].spec.nodeName}{"\n"}'
```

Ожидаемо: под `Running` на `k3s-1`.

- [ ] **Step 4: Проверить команду на телевизоре — без запроса авторизации**

Владелец шлёт команду телевизору `hall` обычным способом. Одновременно:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome logs deploy/samsung-tv --tail=20 | grep -iE "send_key|timeOut|connect"
```

Ожидаемо: **нет** строки `ms.channel.timeOut`, команда отработала молча. Это и
есть подтверждение, что перенесённый токен подошёл.

Если `timeOut` всё же есть — в логе теперь видно `src=` и `token=есть/нет`:
`token=нет` означает, что ключ в файле не совпал с фактическим исходящим
адресом, `token=есть` — что телевизор отверг перенесённый токен.

- [ ] **Step 5: Переехать на k3s-2 и авторизоваться**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome patch deploy samsung-tv --type=merge \
  -p '{"spec":{"template":{"spec":{"nodeSelector":{"kubernetes.io/hostname":"k3s-2"}}}}}'
kubectl -n smarthome rollout status deploy/samsung-tv --timeout=300s
```

Владелец шлёт команду и подтверждает запрос на экране телевизора. Затем:

```bash
kubectl -n smarthome exec deploy/samsung-tv -- sh -c 'cat /app/conf/devices.json' | python3 -c "
import json,sys
for d in json.load(sys.stdin): print(d['name'], '->', list((d.get('tokens') or {}).keys()))
"
```

Ожидаемо: у телевизора, которому слали команду, в `tokens` **два** ключа —
`198.18.1.51` и `198.18.1.52`. Это и есть проверка, ради которой всё делалось:
новый токен добавился, старый не затёрся.

- [ ] **Step 6: Вернуться на k3s-1 — авторизация не должна потребоваться**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome patch deploy samsung-tv --type=merge \
  -p '{"spec":{"template":{"spec":{"nodeSelector":{"kubernetes.io/hostname":"k3s-1"}}}}}'
kubectl -n smarthome rollout status deploy/samsung-tv --timeout=300s
```

Владелец снова шлёт команду телевизору. Ожидаемо: команда проходит **без**
запроса на экране — токен для `.51` сохранился.

- [ ] **Step 7: Снять привязку**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n smarthome patch deploy samsung-tv --type=json \
  -p '[{"op":"remove","path":"/spec/template/spec/nodeSelector"}]'
kubectl -n smarthome rollout status deploy/samsung-tv --timeout=300s
rm -f /tmp/samsung-devices.bak.json
```

- [ ] **Step 8: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/smarthome/samsung-tv.yaml
git commit -m "ops(k3s): bump samsung-tv to the per-source-IP token build"
```

---

### Task 5: Документация

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/smarthome/README.md`

- [ ] **Step 1: Заменить раздел про samsung-tv**

Заменить абзац «**Авторизация на телевизорах**» (пункт 2 в разделе
«samsung-tv — отдельно») на:

```markdown
2. **Авторизация привязана к IP.** Samsung выдаёт токен на пару «телевизор +
   клиент», а клиент различает по адресу — в кластере это адрес ноды. Сервис
   поэтому хранит токены словарём `tokens: {ip: token}` в `devices.json` и
   выбирает нужный по фактическому исходящему адресу (`local_ip_for`, UDP-connect
   к телевизору). При первом появлении пода на новой ноде телевизор один раз
   попросит подтверждение на экране; дальше возвраты на эту ноду проходят молча.

   Раньше токен был один на устройство, и авторизация на второй ноде затирала
   первую — переезд туда-обратно требовал подтверждения каждый раз.
```

- [ ] **Step 2: Проверить, что README не противоречит коду**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
grep -n "token" ops/nanopi-r5c-k3s/apps/smarthome/README.md
```

Ожидаемо: упоминания только про `tokens: {ip: token}` и переезды; нет
утверждений про единственный токен.

- [ ] **Step 3: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/smarthome/README.md
git commit -m "docs(k3s): explain per-source-IP tokens for samsung-tv"
```

---

## Известные ограничения

- **WoL не затрагивается.** Он не требует авторизации и ломается по другой
  причине: magic-пакет с ноды `k3s-1` не долетел до `.102`, хотя оба в
  `198.18.1.0/24`. Отдельная задача.
- **Мёртвые ключи.** Если у ноды сменится адрес, токен для старого осядет в
  файле навсегда. Безвредно, но словарь будет расти.
- **Три авторизации на телевизор.** По одной на ноду; после этого переезды
  бесшовны. Уменьшить это число можно только прибив под к одной ноде.
- **Откат** — вернуть `/tmp/samsung-devices.bak.json` на NAS и прежний тег
  образа в манифесте.
