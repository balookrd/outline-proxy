# Тестовый стенд Windows (dockurr/windows)

Автоматизированный тестовый стенд для сборки, отладки и E2E-верификации Windows-клиента `OutlineProxy` (`bins/outline-windows`) и сетевого ядра `outline-client.exe` на базе аппаратного гипервизора KVM и Docker на домашнем NAS UGREEN DXP4800 Plus (`198.18.1.105`).

---

## Архитектура стенда

- **Хост**: NAS UGREEN `.105` (`198.18.1.105`, доступ `ssh sysadm@198.18.1.105`).
- **Виртуальная машина**: Контейнер `dockurr/windows` с аппаратным ускорением KVM (`/dev/kvm`).
  - ОС: Windows 10 x64 Enterprise / Pro.
  - Ресурсы: 2 CPU, 4 ГБ RAM, 40 ГБ виртуальный диск (`/volume2/windows/storage/data.img`).
  - Веб-доступ (Web VNC): `http://198.18.1.105:8006` (просмотр и интерактивное управление экраном в браузере).
  - RDP: `198.18.1.105:3389` (подключение через Microsoft Remote Desktop).
- **Сетевой мост прокси**: Контейнер `http-proxy-102` (`gogost/gost`):
  - Порт `:8118` на NAS `.105`.
  - Форвардит HTTP/HTTPS трафик через домашний шлюз Node 102 (`socks5://198.18.1.102:1080`).
  - Обеспечивает стабильный выход в интернет для загрузки обновлений и пакетов.
- **Общий каталог (Shared directory)**:
  - На хосте NAS: `/volume1/docker/windows/shared`.
  - Внутри Windows VM: `\\host.lan\Data\`.
  - Установленное приложение: `C:\OutlineProxy\` (`OutlineProxy.exe`, `outline-client.exe`, `wintun.dll`).

---

## Управление стендом

Все скрипты можно запускать как локально с рабочей станции Mac (через SSH-сессию), так и непосредственно на NAS в каталоге `/volume1/docker/windows/`:

### 1. Проверка статуса
```bash
./ops/windows-bench/status.sh
```
Показывает статус контейнеров `windows` и `http-proxy-102`, доступность портов (`8118`, `8006`, `3389`), размер виртуального диска и активность фонового раннера.

### 2. Запуск стенда
```bash
./ops/windows-bench/start.sh
```
Запускает оба контейнера (старт существующей ВМ занимает около 15–20 секунд) и ожидает готовности сетевых портов.
Автозапуск раннера PowerShell (`runner_loop.ps1`) настроен в папке автозагрузки Windows (`Startup/runner_loop.cmd`).

### 3. Остановка стенда (для экономии ресурсов)
```bash
./ops/windows-bench/stop.sh
```
Выполняет корректный останов ВМ Windows и прокси-моста. Содержимое виртуального диска `data.img` и установленные программы сохраняются без изменений.

---

## Автоматизация и тестирование

### Выполнение PowerShell команд внутри ВМ
Скрипт `exec.sh` передаёт команду через общую папку и возвращает stdout:
```bash
# Получить список процессов Outline
./ops/windows-bench/exec.sh "Get-Process OutlineProxy"

# Проверить хэши бинарников
./ops/windows-bench/exec.sh "Get-FileHash C:\OutlineProxy\OutlineProxy.exe"

# Запустить внешний .ps1 скрипт
./ops/windows-bench/exec.sh -f path/to/script.ps1
```

### Снятие скриншота рабочего стола ВМ
```bash
./ops/windows-bench/screenshot.sh output.png
```
Делает снимок основного экрана гостевой системы Windows и сохраняет локально в файл `output.png`.
