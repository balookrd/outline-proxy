#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Outline Proxy — Статус тестового стенда Windows на NAS .105
# -----------------------------------------------------------------------------

TARGET_HOST="${WINDOWS_BENCH_HOST:-198.18.1.105}"
TARGET_USER="${WINDOWS_BENCH_USER:-sysadm}"
COMPOSE_DIR="/volume1/docker/windows"

run_cmd() {
    if [[ -d "${COMPOSE_DIR}" && "$(id -u)" != "0" ]]; then
        bash -c "$1"
    else
        ssh -o BatchMode=yes -o ConnectTimeout=5 "${TARGET_USER}@${TARGET_HOST}" "$1"
    fi
}

echo "=== Статус контейнеров стенда Windows (${TARGET_HOST}) ==="
run_cmd "
    docker ps -a --filter 'name=windows' --filter 'name=http-proxy-102' --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
"

echo ""
echo "=== Проверка сетевых портов ==="
run_cmd "
    printf '  Port 8118 (HTTP->SOCKS5): '; nc -z 127.0.0.1 8118 2>/dev/null && echo 'ONLINE' || echo 'DOWN'
    printf '  Port 8006 (Web VNC):      '; nc -z 127.0.0.1 8006 2>/dev/null && echo 'ONLINE' || echo 'DOWN'
    printf '  Port 3389 (RDP):          '; nc -z 127.0.0.1 3389 2>/dev/null && echo 'ONLINE' || echo 'DOWN'
"

echo ""
echo "=== Состояние хранилища и общей папки ==="
run_cmd "
    echo '  Диск ВМ (/volume2/windows/storage):'
    ls -lh /volume2/windows/storage/data.img 2>/dev/null | awk '{print \"    \" \$9 \" (\" \$5 \")\"}' || echo '    не найден'
    echo '  Последняя активность runner_loop (общая папка):'
    tail -n 3 /volume1/docker/windows/shared/loop.log 2>/dev/null | sed 's/^/    /' || echo '    нет логов'
"
