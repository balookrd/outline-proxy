#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Outline Proxy — Выполнение PowerShell команды/скрипта в Windows VM
# Использование:
#   ./ops/windows-bench/exec.sh "Get-Process OutlineProxy"
#   ./ops/windows-bench/exec.sh -f path/to/script.ps1
# -----------------------------------------------------------------------------

TARGET_HOST="${WINDOWS_BENCH_HOST:-198.18.1.105}"
TARGET_USER="${WINDOWS_BENCH_USER:-sysadm}"
SHARED_DIR="/volume1/docker/windows/shared"

if [[ $# -eq 0 ]]; then
    echo "Использование: $0 \"PowerShell команда\" или $0 -f script.ps1" >&2
    exit 1
fi

TMP_SCRIPT=$(mktemp)
TMP_OUT="exec_result_$(date +%s).log"
TMP_MARKER="exec_done_$(date +%s).txt"

if [[ "$1" == "-f" ]]; then
    shift
    FILE="$1"
    if [[ ! -f "$FILE" ]]; then
        echo "Файл не найден: $FILE" >&2
        exit 1
    fi
    cat "$FILE" > "$TMP_SCRIPT"
else
    CMD="$*"
    cat <<EOF > "$TMP_SCRIPT"
try {
    \$out = & { $CMD } | Out-String
    \$out | Out-File -FilePath "\\\\host.lan\\Data\\${TMP_OUT}" -Encoding utf8
} catch {
    \$_ | Out-File -FilePath "\\\\host.lan\\Data\\${TMP_OUT}" -Encoding utf8
}
"DONE" | Out-File -FilePath "\\\\host.lan\\Data\\${TMP_MARKER}" -Encoding utf8
EOF
fi

# Загружаем скрипт в exec.ps1 через SSH
cat "$TMP_SCRIPT" | ssh -o BatchMode=yes "${TARGET_USER}@${TARGET_HOST}" "rm -f ${SHARED_DIR}/${TMP_MARKER} ${SHARED_DIR}/${TMP_OUT} && cat > ${SHARED_DIR}/exec.ps1"
rm -f "$TMP_SCRIPT"

# Ждём завершения выполнения
ssh -o BatchMode=yes "${TARGET_USER}@${TARGET_HOST}" "
    for i in \$(seq 1 30); do
        if [ -f ${SHARED_DIR}/${TMP_MARKER} ]; then
            cat ${SHARED_DIR}/${TMP_OUT} 2>/dev/null
            rm -f ${SHARED_DIR}/${TMP_MARKER} ${SHARED_DIR}/${TMP_OUT}
            exit 0
        fi
        sleep 1
    done
    echo 'Таймаут выполнения команды в Windows VM (30s)' >&2
    exit 1
"
