# План реализации: Вынос управления парком и деплоем в `infra-repo`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Создать локальный Git-репозиторий `infra-repo` для полного управления боевым парком, кластером k3s, деплоем и слепками узлов; полностью очистить `outline-proxy` и `ambar` от каталогов `ops/` и инфраструктурных файлов.

**Architecture:** Кодовые репозитории `outline-proxy` и `ambar` освобождаются от специфики физических хостов и становятся чистыми кодовыми проектами. Вся эксплуатация, топология, сетевые бэкапы, мониторинг, тюнинг и генераторы ключей переносятся в `/home/user/IdeaProjects/infra-repo` с локальным версионированием через Git.

**Tech Stack:** Bash, Python 3, Git, Kubernetes / k3s YAML, systemd, SSH.

## Global Constraints
- Все рассуждения, диалоги, коммиты документации и отчёты вести на русском языке.
- Запрещён автоматический деплой и рестарт боевых сервисов на хостах в процессе миграции.
- В репозиториях `outline-proxy` и `ambar` не должно остаться ни одного файла из каталога `ops/` и ни одного локального инвентаря `FLEET.local.md`.
- Все скрипты и тесты в `infra-repo` должны сохранять полную работоспособность.
- В Rust-проектах после проверок подчищать артефакты компиляции.

---

### Task 1: Инициализация репозитория `infra-repo` и базовая структура

**Files:**
- Create: `/home/user/IdeaProjects/infra-repo/.gitignore`
- Create: `/home/user/IdeaProjects/infra-repo/AGENTS.md`
- Create: `/home/user/IdeaProjects/infra-repo/README.ru.md`

- [ ] **Step 1: Инициализировать git и создать .gitignore**

```bash
cd /home/user/IdeaProjects/infra-repo
git init -b main
cat << 'EOF' > .gitignore
# Локальные временные файлы и дампы
*.tmp
*.log
.DS_Store
.idea/
__pycache__/
*.pyc
EOF
```

- [ ] **Step 2: Создать AGENTS.md для infra-repo**

```bash
cat << 'EOF' > /home/user/IdeaProjects/infra-repo/AGENTS.md
# AGENTS.md — infra-repo Fleet Operations

## Что это
Центральный проект управления боевым парком серверов, k3s-кластером NanoPi R5C, сетевой инфраструктурой, мониторингом и деплоем Outline и Ambar.

## SSH-доступ к узлам парка
На рабочей станции настроен `~/.ssh/config`. Подключение выполняется только по коротким алиасам:
- `ssh cloud1` — Cloud relay 1 (Ubuntu 24.04 x86_64)
- `ssh cloud2` — Cloud relay 2 (Ubuntu 24.04 x86_64)
- `ssh nuxt`   — Exit node 1 (Helsinki / Nuremberg, Германия)
- `ssh nuxt2`  — Exit node 2 (Нидерланды)
- `ssh 104`    — NanoPi R5C .104 (aarch64 Rockchip, домашний ingress)
- `ssh 102`    — Beelink-T4-Pro .102 (x86_64, домашний ingress)
- `ssh 105`    — NAS Synology/UGREEN .105

## Структура
- `fleet/`: топология (`FLEET.md`, `fleet.tsv`), сетевые конфиги (`network/`), скрипты настройки узлов (`provision/`), слепки узлов (`snapshots/`).
- `deploy/`: скрипты деплоя бинарников (`bin/deploy-binary.sh`) и k3s-манифесты сервисов (`k8s/`).
- `nodes/`: специфика физических хостов (`nanopi-r5c-k3s`, `nanopi104-backup`, `memory-tuning`, `watchdog`, `windows-bench`).
- `ops/`: мониторинг и сервисы (`alerting`, `grafana`, `heartbeat`, `hostacct`, `nas-monitoring`, `nas-jellyfin-backup`).
- `access-keys/`: генератор клиентских конфигов и подписок.

## Регламент деплоя
- Выкатка бинарников выполняется строго через `deploy/bin/deploy-binary.sh <alias> <unit> <path-to-binary>`.
- Раскатка строго по одному узлу за раз.
- Всегда проверять статус сервиса и метрики после выкатки.
EOF
```

- [ ] **Step 3: Создать README.ru.md**

```bash
cat << 'EOF' > /home/user/IdeaProjects/infra-repo/README.ru.md
# infra-repo — Управление боевым парком и кластером k3s

Единый репозиторий эксплуатации инфраструктуры:
1. **Кластер k3s**: 3 ноды NanoPi R5C, VIP-шлюзы, CSI-хранилище Ambar, CoreDNS, мониторинг.
2. **Боевой парк**: облачные релеи (`cloud1`, `cloud2`), точки выхода (`nuxt`, `nuxt2`), домашние шлюзы (`104`, `102`), NAS (`105`).
3. **Деплой**: инструменты доставки бинарников `outline-server`, `outline-client`, `outline-ui`.
4. **Слепки**: актуальные архивные снимки конфигураций операционных систем узлов.
EOF
```

---

### Task 2: Перенос инвентаря, топологии и сетевых слепков парка

**Files:**
- Create: `/home/user/IdeaProjects/infra-repo/fleet/FLEET.md`
- Create: `/home/user/IdeaProjects/infra-repo/fleet/fleet.tsv`
- Copy: `/home/user/IdeaProjects/ambar/ops/hosts-network/` $\to$ `/home/user/IdeaProjects/infra-repo/fleet/network/`
- Copy: `/home/user/IdeaProjects/ambar/ops/fleet-provision/` $\to$ `/home/user/IdeaProjects/infra-repo/fleet/provision/`
- Create: `/home/user/IdeaProjects/infra-repo/fleet/snapshots/`

- [ ] **Step 1: Перенести FLEET.local.md и боевой fleet.local.tsv**

```bash
mkdir -p /home/user/IdeaProjects/infra-repo/fleet/snapshots
cp ./FLEET.local.md /home/user/IdeaProjects/infra-repo/fleet/FLEET.md
cp ./ops/memory-tuning/fleet.local.tsv /home/user/IdeaProjects/infra-repo/fleet/fleet.tsv
```

- [ ] **Step 2: Перенести network и provision из ambar**

```bash
cp -R /home/user/IdeaProjects/ambar/ops/hosts-network/ /home/user/IdeaProjects/infra-repo/fleet/network/
cp -R /home/user/IdeaProjects/ambar/ops/fleet-provision/ /home/user/IdeaProjects/infra-repo/fleet/provision/
```

- [ ] **Step 3: Скопировать имеющиеся слепки узлов в snapshots**

```bash
# Скопировать конфигурационные срезы beelink102 и nanopi104 в snapshots
cp -R /home/user/IdeaProjects/ambar/ops/hosts-network/beelink102 /home/user/IdeaProjects/infra-repo/fleet/snapshots/
cp -R /home/user/IdeaProjects/ambar/ops/hosts-network/nanopi104 /home/user/IdeaProjects/infra-repo/fleet/snapshots/
# Скопировать профили узлов из fleet-provision в snapshots
cp -R /home/user/IdeaProjects/ambar/ops/fleet-provision/profiles /home/user/IdeaProjects/infra-repo/fleet/snapshots/
```

---

### Task 3: Перенос скриптов деплоя и k3s-манифестов

**Files:**
- Copy: `./ops/deploy/` $\to$ `/home/user/IdeaProjects/infra-repo/deploy/bin/`
- Copy: `/home/user/IdeaProjects/ambar/ops/k3s/` $\to$ `/home/user/IdeaProjects/infra-repo/deploy/k8s/`

- [ ] **Step 1: Скопировать скрипты деплоя**

```bash
mkdir -p /home/user/IdeaProjects/infra-repo/deploy/bin
cp -R ./ops/deploy/* /home/user/IdeaProjects/infra-repo/deploy/bin/
chmod +x /home/user/IdeaProjects/infra-repo/deploy/bin/*.sh
```

- [ ] **Step 2: Скопировать манифесты k3s**

```bash
mkdir -p /home/user/IdeaProjects/infra-repo/deploy/k8s
cp -R /home/user/IdeaProjects/ambar/ops/k3s/* /home/user/IdeaProjects/infra-repo/deploy/k8s/
```

---

### Task 4: Перенос нод и специфики хостов

**Files:**
- Copy: `/home/user/IdeaProjects/ambar/ops/nanopi-r5c-k3s/` $\to$ `/home/user/IdeaProjects/infra-repo/nodes/nanopi-r5c-k3s/`
- Copy: `./ops/nanopi104-backup/` $\to$ `/home/user/IdeaProjects/infra-repo/nodes/nanopi104-backup/`
- Copy: `./ops/memory-tuning/` $\to$ `/home/user/IdeaProjects/infra-repo/nodes/memory-tuning/`
- Copy: `./ops/watchdog/` $\to$ `/home/user/IdeaProjects/infra-repo/nodes/watchdog/`
- Copy: `/home/user/IdeaProjects/ambar/ops/windows-bench/` $\to$ `/home/user/IdeaProjects/infra-repo/nodes/windows-bench/`

- [ ] **Step 1: Скопировать каталоги в nodes**

```bash
mkdir -p /home/user/IdeaProjects/infra-repo/nodes
cp -R /home/user/IdeaProjects/ambar/ops/nanopi-r5c-k3s /home/user/IdeaProjects/infra-repo/nodes/
cp -R ./ops/nanopi104-backup /home/user/IdeaProjects/infra-repo/nodes/
cp -R ./ops/memory-tuning /home/user/IdeaProjects/infra-repo/nodes/
cp -R ./ops/watchdog /home/user/IdeaProjects/infra-repo/nodes/
cp -R /home/user/IdeaProjects/ambar/ops/windows-bench /home/user/IdeaProjects/infra-repo/nodes/
```

- [ ] **Step 2: Связать `memory-tuning/apply.sh` с `fleet/fleet.tsv`**

Проверить пути в `apply.sh`: скрипт ищет `fleet.tsv` / `fleet.local.tsv`. Убедиться, что скрипт корректно подхватывает файл из `../../fleet/fleet.tsv` или текущей директории.

---

### Task 5: Перенос мониторинга, алертинга и сервисов парка

**Files:**
- Copy: `/home/user/IdeaProjects/ambar/ops/alerting/` $\to$ `/home/user/IdeaProjects/infra-repo/ops/alerting/`
- Copy: `/home/user/IdeaProjects/ambar/ops/grafana/` $\to$ `/home/user/IdeaProjects/infra-repo/ops/grafana/`
- Copy: `/home/user/IdeaProjects/ambar/ops/heartbeat/` $\to$ `/home/user/IdeaProjects/infra-repo/ops/heartbeat/`
- Copy: `/home/user/IdeaProjects/ambar/ops/hostacct/` $\to$ `/home/user/IdeaProjects/infra-repo/ops/hostacct/`
- Copy: `/home/user/IdeaProjects/ambar/ops/nas-monitoring/` $\to$ `/home/user/IdeaProjects/infra-repo/ops/nas-monitoring/`
- Copy: `/home/user/IdeaProjects/ambar/ops/nas-jellyfin-backup/` $\to$ `/home/user/IdeaProjects/infra-repo/ops/nas-jellyfin-backup/`

- [ ] **Step 1: Скопировать каталоги мониторинга в `infra-repo/ops/`**

```bash
mkdir -p /home/user/IdeaProjects/infra-repo/ops
cp -R /home/user/IdeaProjects/ambar/ops/alerting /home/user/IdeaProjects/infra-repo/ops/
cp -R /home/user/IdeaProjects/ambar/ops/grafana /home/user/IdeaProjects/infra-repo/ops/
cp -R /home/user/IdeaProjects/ambar/ops/heartbeat /home/user/IdeaProjects/infra-repo/ops/
cp -R /home/user/IdeaProjects/ambar/ops/hostacct /home/user/IdeaProjects/infra-repo/ops/
cp -R /home/user/IdeaProjects/ambar/ops/nas-monitoring /home/user/IdeaProjects/infra-repo/ops/
cp -R /home/user/IdeaProjects/ambar/ops/nas-jellyfin-backup /home/user/IdeaProjects/infra-repo/ops/
```

---

### Task 6: Перенос генератора ключей доступа и подписок

**Files:**
- Copy: `./ops/access-keys/` $\to$ `/home/user/IdeaProjects/infra-repo/access-keys/`

- [ ] **Step 1: Скопировать access-keys**

```bash
cp -R ./ops/access-keys /home/user/IdeaProjects/infra-repo/access-keys
```

- [ ] **Step 2: Запустить тесты генератора ключей в infra-repo**

```bash
python3 -m unittest discover /home/user/IdeaProjects/infra-repo/access-keys/
```
Ожидается: `Ran 196 tests ... OK`.

---

### Task 7: Фиксация коммита в `infra-repo` и верификация

**Files:**
- Work directory: `/home/user/IdeaProjects/infra-repo`

- [ ] **Step 1: Проверить синтаксис ключевых bash-скриптов**

```bash
bash -n /home/user/IdeaProjects/infra-repo/deploy/bin/deploy-binary.sh
bash -n /home/user/IdeaProjects/infra-repo/nodes/memory-tuning/apply.sh
```

- [ ] **Step 2: Добавить все файлы и сделать первый коммит**

```bash
cd /home/user/IdeaProjects/infra-repo
git add .
git commit -m "feat(fleet): initial commit of centralized infra-repo fleet repository"
```

---

### Task 8: Очистка `outline-proxy`

**Files:**
- Delete: `./ops/`
- Delete: `./FLEET.local.md`
- Modify: `./AGENTS.md`
- Modify: `./.gitignore`

- [ ] **Step 1: Удалить каталог `ops/` и `FLEET.local.md` в outline-proxy**

```bash
cd .
git rm -r ops/
rm -f FLEET.local.md
```

- [ ] **Step 2: Обновить AGENTS.md в outline-proxy**

Заменить ссылки на `ops/deploy` и `FLEET.local.md` на ссылку на внешний проект `infra-repo` (`/home/user/IdeaProjects/infra-repo/deploy/bin/deploy-binary.sh`).

- [ ] **Step 3: Прогнать CI-гейт в outline-proxy**

```bash
cargo fmt --check -p outline-server -p outline-client -p outline-ui \
  -p outline-metrics -p outline-net -p outline-routing -p outline-transport \
  -p outline-tun -p outline-uplink -p outline-wire \
  -p shadowsocks-crypto -p socks5-proto
cargo clippy --workspace --exclude sockudo-ws --exclude outline-windows --all-targets --no-deps -- -D warnings
cargo test --workspace --exclude sockudo-ws --exclude outline-windows
```

- [ ] **Step 4: Закоммитить и запушить изменения в outline-proxy**

```bash
git add .
git commit -m "chore(fleet): extract fleet operations and ops directory into dedicated infra-repo project"
git push origin main
cargo clean
```

---

### Task 9: Очистка `ambar`

**Files:**
- Delete: `/home/user/IdeaProjects/ambar/ops/`
- Delete: `/home/user/IdeaProjects/ambar/FLEET.local.md`
- Modify: `/home/user/IdeaProjects/ambar/AGENTS.md`
- Modify: `/home/user/IdeaProjects/ambar/README.ru.md`

- [ ] **Step 1: Удалить каталог `ops/` и `FLEET.local.md` в ambar**

```bash
cd /home/user/IdeaProjects/ambar
git rm -r ops/
rm -f FLEET.local.md
```

- [ ] **Step 2: Обновить AGENTS.md и README.ru.md в ambar**

Очистить упоминания ops-каталога, перенаправив регламент эксплуатации на `infra-repo`.

- [ ] **Step 3: Проверить сборку ambar**

```bash
cd /home/user/IdeaProjects/ambar
cargo check
```

- [ ] **Step 4: Закоммитить и запушить изменения в ambar**

```bash
git add .
git commit -m "chore(fleet): extract fleet operations and ops directory into dedicated infra-repo project"
git push origin main
cargo clean
```

---

### Task 10: Актуализация памяти Claude Code

**Files:**
- Create: `~/.claude/projects/-Users-user-IdeaProjects-infra-repo/memory/MEMORY.md`
- Modify: `~/.claude/projects/<project-slug>/memory/MEMORY.md`
- Modify: `~/.claude/projects/-Users-user-IdeaProjects-ambar/memory/` (если существует)

- [ ] **Step 1: Создать профиль памяти для infra-repo**

Зафиксировать структуру репозитория, список узлов, правила деплоя и назначения каталогов.

- [ ] **Step 2: Обновить MEMORY.md в outline-proxy**

Зафиксировать, что в `outline-proxy` остался только исходный код, а все операции деплоя ведутся из `infra-repo`.
