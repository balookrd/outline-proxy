#!/usr/bin/env bash
set -euo pipefail

# Scripts directory and repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MACOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${MACOS_DIR}/.." && pwd)"
DIST_DIR="${MACOS_DIR}/dist"
APP_BUNDLE="${DIST_DIR}/Outline Proxy.app"

CREATE_DMG=false
for arg in "$@"; do
    case "$arg" in
        --dmg)
            CREATE_DMG=true
            ;;
        -h|--help)
            echo "Использование: $0 [--dmg]"
            echo "  --dmg    Собрать приложение и упаковать в DMG-образ"
            exit 0
            ;;
    esac
done

echo "=== Сборка Outline Proxy для macOS ==="

# 1. Сборка Rust-ядра
echo "==> [1/4] Компиляция outline-ws-rust (release)..."
cd "${REPO_ROOT}"
cargo build -p outline-ws-rust --release

# 2. Сборка Swift приложения
echo "==> [2/4] Компиляция Swift-приложения (release)..."
cd "${MACOS_DIR}"
swift build -c release

# Определение путей к собранным бинарникам
SWIFT_BIN="${MACOS_DIR}/.build/release/OutlineProxy"
RUST_BIN="${REPO_ROOT}/target/release/outline-ws-rust"

if [[ ! -f "${SWIFT_BIN}" ]]; then
    echo "Ошибка: не найден бинарник Swift: ${SWIFT_BIN}" >&2
    exit 1
fi

if [[ ! -f "${RUST_BIN}" ]]; then
    echo "Ошибка: не найден бинарник Rust: ${RUST_BIN}" >&2
    exit 1
fi

# 3. Формирование бандла .app
echo "==> [3/4] Сборка бандла ${APP_BUNDLE}..."
rm -rf "${APP_BUNDLE}"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

cp "${MACOS_DIR}/Resources/Info.plist" "${APP_BUNDLE}/Contents/Info.plist"
echo -n "APPL????" > "${APP_BUNDLE}/Contents/PkgInfo"

cp "${SWIFT_BIN}" "${APP_BUNDLE}/Contents/MacOS/OutlineProxy"
cp "${RUST_BIN}" "${APP_BUNDLE}/Contents/Resources/outline-ws-rust"
cp "${MACOS_DIR}/Resources/tun-runner.sh" "${APP_BUNDLE}/Contents/Resources/tun-runner.sh"

# Скопировать иконки и графические ассеты интерфейса (логотипы, кольцо, карта мира)
cp "${MACOS_DIR}/Resources/"*.png "${APP_BUNDLE}/Contents/Resources/" 2>/dev/null || true
if [[ -f "${MACOS_DIR}/Resources/AppIcon.icns" ]]; then
    cp "${MACOS_DIR}/Resources/AppIcon.icns" "${APP_BUNDLE}/Contents/Resources/AppIcon.icns"
fi

chmod +x "${APP_BUNDLE}/Contents/MacOS/OutlineProxy"
chmod +x "${APP_BUNDLE}/Contents/Resources/outline-ws-rust"
chmod +x "${APP_BUNDLE}/Contents/Resources/tun-runner.sh"

# 4. Ad-hoc подпись (работает на любом Mac без платного Developer ID)
echo "==> [4/4] Ad-hoc подпись бандла..."
codesign --force --deep --sign - "${APP_BUNDLE}"

echo ""
echo "✅ Приложение успешно собрано: ${APP_BUNDLE}"
echo "Для запуска выполните: open \"${APP_BUNDLE}\""

if [[ "${CREATE_DMG}" == "true" ]]; then
    echo ""
    "${SCRIPT_DIR}/package-dmg.sh" --skip-build
fi
