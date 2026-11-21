#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Outline Proxy — Остановка тестового стенда Windows на NAS .105
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

echo "==> Остановка тестового стенда Windows (NAS: ${TARGET_HOST})..."

run_cmd "
    echo '1. Остановка ВМ Windows (чистый ACPI shutdown / docker stop)...'
    docker stop windows || true
    echo '2. Остановка SOCKS-прокси моста http-proxy-102...'
    docker stop http-proxy-102 || true
"

echo "==> Стенд Windows и прокси остановлены. Диск /volume2/windows/storage/data.img сохранён."
