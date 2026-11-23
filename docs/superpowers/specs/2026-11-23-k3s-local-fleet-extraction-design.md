# Дизайн: Вынос инфраструктуры боевого парка в проект `infra-repo`

## 1. Контекст и цели

В настоящее время в репозиториях `outline-proxy` и `ambar` исторически присутствуют артефакты эксплуатации конкретного физического и облачного парка серверов (скрипты деплоя, бэкапы хостов, тюнинг ядра/sysctl, мониторинг, инвентарь нод, генераторы подписок).

**Цели:**
1. **Полное разделение кодовой базы и Ops**:
   - `outline-proxy` — исключительно чистый исходный код прокси-экосистемы (Rust-бинари, библиотеки wire-протокола, Android/macOS/Windows клиенты, UI).
   - `ambar` — исключительно чистый исходный код распределённого блочного хранилища / CSI-драйвера (Rust, gRPC proto, CSI daemonset/storageclass шаблоны, тесты).
   - `infra-repo` — единый выделенный локальный проект и Git-репозиторий для управления эксплуатацией парка, k3s-кластера, узлов, деплоя, мониторинга и конфигураций.
2. **Безопасность и чистота публичных репозиториев**:
   - Из публичных/полупубличных Git-репозиториев полностью удаляются каталоги `ops/` и любые локальные инвентари.
   - `infra-repo` остаётся локальным Git-репозиторием (без публичного remote, либо с бэкапом на домашний NAS), где хранятся боевые адреса, топология и ключи.

---

## 2. Структура проекта `infra-repo`

Каталог: `/home/user/IdeaProjects/infra-repo`

```text
infra-repo/
├── .git/                      # Локальный Git-репозиторий
├── AGENTS.md                  # Руководство для AI-агентов по управлению парком и деплою
├── README.ru.md               # Архитектура парка, сетевая схема и регламент
├── fleet/                     # Инвентарь боевого парка и провижнинг
│   ├── FLEET.md               # Бывший FLEET.local.md (топология, роли, IP узлов)
│   ├── fleet.tsv              # Боевой файл параметров памяти/узлов (из memory-tuning)
│   ├── network/               # Бывший hosts-network (бэкапы сети .102, .104)
│   ├── provision/             # Бывший fleet-provision (развёртывание новых нод)
│   └── snapshots/             # Полные слепки конфигураций узлов парка (cloud1, cloud2, nuxt, nuxt2, 102, 104, 105, k3s)
├── deploy/                    # Деплой сервисов и бинарников
│   ├── bin/                   # deploy-binary.sh, deploy-fleet.sh, revert-binary.sh
│   └── k8s/                   # Манифесты сервисов кластера (registry-gc, outline-ui и др.)
├── nodes/                     # Специфичные настройки физических хостов
│   ├── nanopi-r5c-k3s/        # sysctl, сеть, тюнинг conntrack, k3s-манифесты
│   ├── nanopi104-backup/      # Служба бэкапа nanopi104 на NAS
│   ├── memory-tuning/         # apply.sh и скрипты тюнинга памяти jemalloc/sysctl
│   ├── watchdog/              # Скрипты watchdog серверов
│   └── windows-bench/         # Стенд тестирования Windows
├── ops/                       # Мониторинг, алертинг и служебные сервисы парка
│   ├── alerting/              # Prometheus/Alertmanager правила и алерты
│   ├── grafana/               # Дашборды Grafana (outline-server, client, ambar)
│   ├── heartbeat/             # Сервис проверки доступности узлов
│   ├── hostacct/              # Учёт трафика хостов
│   ├── nas-monitoring/        # Мониторинг NAS
│   └── nas-jellyfin-backup/   # Бэкапы Jellyfin на NAS
└── access-keys/               # Генератор боевых ключей, подписок и DNS-записей
    ├── xray_json.py
    ├── ws_toml.py
    ├── generate_keys.py
    └── ...
```

---

## 3. Миграция компонентов

### 3.1. Из `outline-proxy` $\to$ `infra-repo`
| Исходный путь | Целевой путь в `infra-repo` | Примечание |
|---|---|---|
| `FLEET.local.md` | `fleet/FLEET.md` | Полное описание узлов и топологии |
| `ops/deploy/` | `deploy/bin/` | Скрипты деплоя бинарников на узлы |
| `ops/nanopi104-backup/` | `nodes/nanopi104-backup/` | Бэкап ноды .104 |
| `ops/memory-tuning/` | `nodes/memory-tuning/` | Тюнинг памяти jemalloc |
| `ops/watchdog/` | `nodes/watchdog/` | Скрипты вотчдогов |
| `ops/access-keys/` | `access-keys/` | Генератор подписок и ключей |

После переноса в `outline-proxy`:
- Удаляется весь каталог `ops/`.
- Удаляется файл `FLEET.local.md`.
- Обновляется `AGENTS.md` (удаляются ссылки на `ops/` и `FLEET.local.md`, добавляются ссылки на `infra-repo`).

### 3.2. Из `ambar` $\to$ `infra-repo`
| Исходный путь | Целевой путь в `infra-repo` | Примечание |
|---|---|---|
| `ops/nanopi-r5c-k3s/` | `nodes/nanopi-r5c-k3s/` | Конфигурация кластера NanoPi R5C |
| `ops/hosts-network/` | `fleet/network/` | Сетевые конфиги хостов |
| `ops/fleet-provision/` | `fleet/provision/` | Провижнинг хостов |
| Слепки узлов (hosts-network + архивы) | `fleet/snapshots/` | Полные слепки конфигураций (etc, network, systemd, outline) для всех узлов |
| `ops/windows-bench/` | `nodes/windows-bench/` | Стенд KVM/Docker |
| `ops/alerting/` | `ops/alerting/` | Алертинг |
| `ops/grafana/` | `ops/grafana/` | Дашборды |
| `ops/heartbeat/` | `ops/heartbeat/` | Проверка доступности |
| `ops/hostacct/` | `ops/hostacct/` | Учёт трафика |
| `ops/k3s/` | `deploy/k8s/` | k3s манифесты |
| `ops/nas-monitoring/` | `ops/nas-monitoring/` | Мониторинг NAS |
| `ops/nas-jellyfin-backup/` | `ops/nas-jellyfin-backup/` | Бэкапы Jellyfin |
| `FLEET.local.md` | сверка с `fleet/FLEET.md` | Удаляется из ambar |

После переноса в `ambar`:
- Удаляется весь каталог `ops/`.
- Удаляется файл `FLEET.local.md`.
- Обновляется `AGENTS.md` и `README.ru.md`.

---

## 4. Память Claude Code и инструкции для агентов

В `~/.claude/projects/` обновляется память:
1. `MEMORY.md` для `outline-proxy` и `ambar`: фиксируется, что вся эксплуатация парка живёт в `/home/user/IdeaProjects/infra-repo`.
2. Создаётся профиль памяти для проекта `-Users-user-IdeaProjects-infra-repo`:
   - Назначение проекта.
   - Правила подключения к узлам по SSH-алиасам.
   - Регламент деплоя (по одному узлу, проверка, откат).
   - Топология и роли сервисов.

---

## 5. План верификации

1. Проверка `git status` во всех трёх репозиториях (`outline-proxy`, `ambar`, `infra-repo`).
2. Проверка целостности скриптов в `infra-repo`:
   - `infra-repo/deploy/bin/deploy-binary.sh --help` или проверка синтаксиса `bash -n`.
   - `python3 -m unittest discover infra-repo/access-keys/`.
3. Запуск CI-гейта в `outline-proxy` (`cargo check --workspace`, `cargo test --workspace`) для подтверждения отсутствия регрессий в коде.
4. Запуск проверок в `ambar` (`cargo check`).
