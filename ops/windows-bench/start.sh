#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Outline Proxy — Запуск тестового стенда Windows на NAS .105
# Можно запускать как локально на Mac (через SSH), так и прямо на NAS.
# -----------------------------------------------------------------------------

TARGET_HOST="${WINDOWS_BENCH_HOST:-198.18.1.105}"
TARGET_USER="${WINDOWS_BENCH_USER:-sysadm}"
COMPOSE_DIR="/volume1/docker/windows"

run_cmd() {
    if [[ -d "${COMPOSE_DIR}" && "$(id -u)" != "0" ]]; then
        # Мы уже на NAS
        bash -c "$1"
    else
        ssh -o BatchMode=yes -o ConnectTimeout=5 "${TARGET_USER}@${TARGET_HOST}" "$1"
    fi
}

echo "==> Запуск тестового стенда Windows (NAS: ${TARGET_HOST})..."

run_cmd "
    # Запускаем мост прокси и виртуальную машину Windows
    docker start http-proxy-102 windows 2>/dev/null || (
        cd ${COMPOSE_DIR} && docker compose up -d
    )
"

echo "==> Ожидание готовности портов (8118, 8006, 3389)..."
for i in {1..20}; do
    STATUS=$(run_cmd "
        nc -z 127.0.0.1 8118 2>/dev/null && nc -z 127.0.0.1 8006 2>/dev/null && echo 'OK' || echo 'WAIT'
    " || echo 'WAIT')
    if [[ "${STATUS}" =~ OK ]]; then
        echo "==> Стенд Windows успешно запущен и готов к работе!"
        echo "    - Web VNC: http://${TARGET_HOST}:8006"
        echo "    - RDP:     ${TARGET_HOST}:3389"
        echo "    - Proxy:   http://${TARGET_HOST}:8118 -> SOCKS5 198.18.1.102:1080"
        echo "    - Shared:  ${COMPOSE_DIR}/shared (внутри Windows: \\\\host.lan\\Data\\)"
        exit 0
    fi
    sleep 1
done

echo "==> Предупреждение: контейнеры запущены, но веб-порт 8006 ещё не отвечает."
echo "    Проверьте статус через ./status.sh или логи: docker logs windows"
