#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Outline Proxy — Снятие скриншота экрана Windows VM
# Использование:
#   ./ops/windows-bench/screenshot.sh [output.png]
# -----------------------------------------------------------------------------

TARGET_HOST="${WINDOWS_BENCH_HOST:-198.18.1.105}"
TARGET_USER="${WINDOWS_BENCH_USER:-sysadm}"
SHARED_DIR="/volume1/docker/windows/shared"
OUTPUT_FILE="${1:-screenshot_$(date +%Y%m%d_%H%M%S).png}"
REMOTE_PNG="screen_capture_temp.png"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${SCRIPT_DIR}/exec.sh" "
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

\$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
\$bmp = New-Object System.Drawing.Bitmap \$bounds.Width, \$bounds.Height
\$g = [System.Drawing.Graphics]::FromImage(\$bmp)
\$g.CopyFromScreen(\$bounds.Left, \$bounds.Top, 0, 0, \$bounds.Size)
\$bmp.Save('\\\\host.lan\\Data\\${REMOTE_PNG}', [System.Drawing.Imaging.ImageFormat]::Png)
\$g.Dispose()
\$bmp.Dispose()
" >/dev/null

ssh -o BatchMode=yes "${TARGET_USER}@${TARGET_HOST}" "cat ${SHARED_DIR}/${REMOTE_PNG} && rm -f ${SHARED_DIR}/${REMOTE_PNG}" > "${OUTPUT_FILE}"

echo "==> Скриншот сохранён: ${OUTPUT_FILE}"
