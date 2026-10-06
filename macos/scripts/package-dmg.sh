#!/usr/bin/env bash
set -euo pipefail

# Скрипт сборки и упаковки DMG-образа Outline Proxy для macOS.
# Поддерживает архитектуры: universal (x86_64 + arm64), aarch64 (Apple Silicon), x86_64 (Intel), native.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MACOS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${MACOS_DIR}/.." && pwd)"
DIST_DIR="${MACOS_DIR}/dist"

ARCH="native"
VERSION=""
OUTPUT_DIR="${DIST_DIR}"
DMG_NAME=""
APP_PATH=""
SKIP_BUILD=false

# Разбор аргументов командной строки
while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --dmg-name)
            DMG_NAME="$2"
            shift 2
            ;;
        --app-path)
            APP_PATH="$2"
            SKIP_BUILD=true
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        -h|--help)
            echo "Использование: $0 [опции]"
            echo "Опции:"
            echo "  --arch <native|universal|aarch64|x86_64>  Архитектура бинарников (по умолчанию: native)"
            echo "  --version <версия>                      Версия для имени файла (по умолчанию из Cargo.toml)"
            echo "  --output-dir <каталог>                  Куда сохранить DMG (по умолчанию: macos/dist)"
            echo "  --dmg-name <имя>                        Точное имя DMG-файла"
            echo "  --app-path <путь>                       Использовать уже собранный .app"
            echo "  --skip-build                            Пропустить сборку и взять существующий .app"
            exit 0
            ;;
        *)
            echo "Неизвестный параметр: $1" >&2
            exit 1
            ;;
    esac
done

# Определение версии, если не передана явно
if [[ -z "${VERSION}" ]]; then
    if [[ -f "${REPO_ROOT}/bins/outline-ws-rust/Cargo.toml" ]]; then
        VERSION="$(grep -m1 '^version =' "${REPO_ROOT}/bins/outline-ws-rust/Cargo.toml" | cut -d '"' -f2)"
    elif [[ -f "${MACOS_DIR}/Resources/Info.plist" ]]; then
        VERSION="$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "${MACOS_DIR}/Resources/Info.plist" 2>/dev/null || echo "1.0.0")"
    else
        VERSION="1.0.0"
    fi
fi

if [[ "${OUTPUT_DIR}" != /* ]]; then
    OUTPUT_DIR="${REPO_ROOT}/${OUTPUT_DIR}"
fi
mkdir -p "${OUTPUT_DIR}"

APP_BUNDLE="${DIST_DIR}/Outline Proxy.app"
if [[ -n "${APP_PATH}" ]]; then
    APP_BUNDLE="${APP_PATH}"
fi

echo "=========================================="
echo "Сборка DMG-образа Outline Proxy v${VERSION}"
echo "Архитектура: ${ARCH}"
echo "=========================================="

if [[ "${SKIP_BUILD}" == "false" ]]; then
    echo "==> [1/4] Сборка приложения OutlineProxy.app (${ARCH})..."
    
    cd "${REPO_ROOT}"
    
    case "${ARCH}" in
        universal)
            echo "--> Сборка Rust-движка (aarch64 + x86_64)..."
            cargo build -p outline-ws-rust --release --target aarch64-apple-darwin
            cargo build -p outline-ws-rust --release --target x86_64-apple-darwin
            
            mkdir -p "${REPO_ROOT}/target/universal/release"
            lipo -create \
                "${REPO_ROOT}/target/aarch64-apple-darwin/release/outline-ws-rust" \
                "${REPO_ROOT}/target/x86_64-apple-darwin/release/outline-ws-rust" \
                -output "${REPO_ROOT}/target/universal/release/outline-ws-rust"
            RUST_BIN="${REPO_ROOT}/target/universal/release/outline-ws-rust"

            echo "--> Сборка Swift GUI (arm64 + x86_64)..."
            cd "${MACOS_DIR}"
            swift build -c release --triple arm64-apple-macosx
            swift build -c release --triple x86_64-apple-macosx
            
            # Находим скомпилированные бинарники Swift
            SWIFT_ARM64="$(find "${MACOS_DIR}/.build" -path "*/arm64*Release/OutlineProxy" -o -path "*/Release/OutlineProxy" -type f -perm +111 | head -n1)"
            SWIFT_X86_64="$(find "${MACOS_DIR}/.build" -path "*/x86_64*Release/OutlineProxy" -type f -perm +111 | head -n1)"
            
            mkdir -p "${MACOS_DIR}/.build/universal"
            if [[ -n "${SWIFT_ARM64}" && -n "${SWIFT_X86_64}" && "${SWIFT_ARM64}" != "${SWIFT_X86_64}" ]]; then
                lipo -create "${SWIFT_ARM64}" "${SWIFT_X86_64}" -output "${MACOS_DIR}/.build/universal/OutlineProxy"
                SWIFT_BIN="${MACOS_DIR}/.build/universal/OutlineProxy"
            else
                # Fallback: компиляция под хост
                swift build -c release
                SWIFT_BIN="${MACOS_DIR}/.build/release/OutlineProxy"
            fi
            ;;

        aarch64|arm64)
            echo "--> Сборка Rust-движка (aarch64-apple-darwin)..."
            cargo build -p outline-ws-rust --release --target aarch64-apple-darwin
            RUST_BIN="${REPO_ROOT}/target/aarch64-apple-darwin/release/outline-ws-rust"

            echo "--> Сборка Swift GUI (arm64)..."
            cd "${MACOS_DIR}"
            swift build -c release --triple arm64-apple-macosx
            SWIFT_BIN="${MACOS_DIR}/.build/release/OutlineProxy"
            [[ ! -f "${SWIFT_BIN}" ]] && SWIFT_BIN="$(find "${MACOS_DIR}/.build" -name "OutlineProxy" -type f -perm +111 | head -n1)"
            ;;

        x86_64)
            echo "--> Сборка Rust-движка (x86_64-apple-darwin)..."
            cargo build -p outline-ws-rust --release --target x86_64-apple-darwin
            RUST_BIN="${REPO_ROOT}/target/x86_64-apple-darwin/release/outline-ws-rust"

            echo "--> Сборка Swift GUI (x86_64)..."
            cd "${MACOS_DIR}"
            swift build -c release --triple x86_64-apple-macosx
            SWIFT_BIN="$(find "${MACOS_DIR}/.build" -path "*/Release/OutlineProxy" -type f -perm +111 | head -n1)"
            ;;

        native|*)
            echo "--> Нативная сборка Rust-движка под хост..."
            cargo build -p outline-ws-rust --release
            RUST_BIN="${REPO_ROOT}/target/release/outline-ws-rust"

            echo "--> Нативная сборка Swift GUI под хост..."
            cd "${MACOS_DIR}"
            swift build -c release
            SWIFT_BIN="${MACOS_DIR}/.build/release/OutlineProxy"
            ;;
    esac

    # Проверка наличия бинарников
    if [[ ! -f "${SWIFT_BIN:-}" ]]; then
        echo "Ошибка: не найден бинарник Swift: ${SWIFT_BIN:-<пусто>}" >&2
        exit 1
    fi
    if [[ ! -f "${RUST_BIN:-}" ]]; then
        echo "Ошибка: не найден бинарник Rust: ${RUST_BIN:-<пусто>}" >&2
        exit 1
    fi

    # Сборка структуры бандла
    echo "==> [2/4] Формирование бандла ${APP_BUNDLE}..."
    rm -rf "${APP_BUNDLE}"
    mkdir -p "${APP_BUNDLE}/Contents/MacOS"
    mkdir -p "${APP_BUNDLE}/Contents/Resources"

    cp "${MACOS_DIR}/Resources/Info.plist" "${APP_BUNDLE}/Contents/Info.plist"
    echo -n "APPL????" > "${APP_BUNDLE}/Contents/PkgInfo"

    # Внедрение динамических метаданных сборки в Info.plist
    PLIST="${APP_BUNDLE}/Contents/Info.plist"
    GIT_COMMIT="$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo "")"
    GIT_DIRTY=""
    if ! git -C "${REPO_ROOT}" diff --quiet 2>/dev/null; then
        GIT_DIRTY="-dirty"
    fi
    COMMIT_STR="${GIT_COMMIT}${GIT_DIRTY}"

    CURRENT_TAG="$(git -C "${REPO_ROOT}" describe --tags --exact-match 2>/dev/null || echo "")"
    if [[ "${CURRENT_TAG}" =~ ^macos-v[0-9]+ ]]; then
        BUILD_CHANNEL="release"
        APP_VERSION="${CURRENT_TAG#macos-v}"
    else
        BUILD_CHANNEL="nightly"
        APP_VERSION="${VERSION:-$(grep -m1 '^version =' "${REPO_ROOT}/bins/outline-ws-rust/Cargo.toml" | cut -d '"' -f2)}"
    fi

    BUILD_DATE="$(date -u +'%Y-%m-%d')"

    /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${APP_VERSION}" "${PLIST}" 2>/dev/null || \
    /usr/libexec/PlistBuddy -c "Add :CFBundleShortVersionString string ${APP_VERSION}" "${PLIST}"

    /usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${COMMIT_STR:-1}" "${PLIST}" 2>/dev/null || \
    /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string ${COMMIT_STR:-1}" "${PLIST}"

    /usr/libexec/PlistBuddy -c "Set :OutlineBuildCommit ${COMMIT_STR}" "${PLIST}" 2>/dev/null || \
    /usr/libexec/PlistBuddy -c "Add :OutlineBuildCommit string ${COMMIT_STR}" "${PLIST}"

    /usr/libexec/PlistBuddy -c "Set :OutlineBuildChannel ${BUILD_CHANNEL}" "${PLIST}" 2>/dev/null || \
    /usr/libexec/PlistBuddy -c "Add :OutlineBuildChannel string ${BUILD_CHANNEL}" "${PLIST}"

    /usr/libexec/PlistBuddy -c "Set :OutlineBuildDate ${BUILD_DATE}" "${PLIST}" 2>/dev/null || \
    /usr/libexec/PlistBuddy -c "Add :OutlineBuildDate string ${BUILD_DATE}" "${PLIST}"

    cp "${SWIFT_BIN}" "${APP_BUNDLE}/Contents/MacOS/OutlineProxy"
    cp "${RUST_BIN}" "${APP_BUNDLE}/Contents/Resources/outline-ws-rust"
    cp "${MACOS_DIR}/Resources/tun-runner.sh" "${APP_BUNDLE}/Contents/Resources/tun-runner.sh"

    cp "${MACOS_DIR}/Resources/"*.png "${APP_BUNDLE}/Contents/Resources/" 2>/dev/null || true
    if [[ -f "${MACOS_DIR}/Resources/AppIcon.icns" ]]; then
        cp "${MACOS_DIR}/Resources/AppIcon.icns" "${APP_BUNDLE}/Contents/Resources/AppIcon.icns"
    fi

    chmod +x "${APP_BUNDLE}/Contents/MacOS/OutlineProxy"
    chmod +x "${APP_BUNDLE}/Contents/Resources/outline-ws-rust"
    chmod +x "${APP_BUNDLE}/Contents/Resources/tun-runner.sh"

    # Ad-hoc подпись бандла
    codesign --force --deep --sign - "${APP_BUNDLE}"
fi

if [[ ! -d "${APP_BUNDLE}" ]]; then
    echo "Ошибка: бандл приложения не найден по пути: ${APP_BUNDLE}" >&2
    exit 1
fi

# Имя выходного DMG файла
if [[ -z "${DMG_NAME}" ]]; then
    if [[ "${ARCH}" == "universal" ]]; then
        DMG_NAME="OutlineProxy-v${VERSION}-macOS-Universal.dmg"
    elif [[ "${ARCH}" == "native" ]]; then
        DMG_NAME="OutlineProxy-v${VERSION}-macOS.dmg"
    else
        DMG_NAME="OutlineProxy-v${VERSION}-macOS-${ARCH}.dmg"
    fi
fi

DMG_PATH="${OUTPUT_DIR}/${DMG_NAME}"
TEMP_DMG="${OUTPUT_DIR}/pack.temp.dmg"

echo "==> [3/4] Подготовка содержимого образа DMG..."
STAGING_DIR="$(mktemp -d -t outline-dmg-staging-XXXXXX)"
cleanup() {
    rm -rf "${STAGING_DIR}" "${TEMP_DMG}" 2>/dev/null || true
}
trap cleanup EXIT

# Копируем приложение и ярлык /Applications для Drag-and-Drop установки
cp -R "${APP_BUNDLE}" "${STAGING_DIR}/Outline Proxy.app"
ln -s /Applications "${STAGING_DIR}/Applications"

# Иконка тома, если доступна
if [[ -f "${MACOS_DIR}/Resources/AppIcon.icns" ]]; then
    cp "${MACOS_DIR}/Resources/AppIcon.icns" "${STAGING_DIR}/.VolumeIcon.icns"
    if command -v SetFile >/dev/null 2>&1; then
        SetFile -a C "${STAGING_DIR}" 2>/dev/null || true
    fi
fi

echo "==> [4/4] Создание сжатого DMG-образа: ${DMG_PATH}..."
rm -f "${DMG_PATH}" "${TEMP_DMG}"

hdiutil create \
    -volname "Outline Proxy" \
    -srcfolder "${STAGING_DIR}" \
    -ov \
    -format UDZO \
    "${DMG_PATH}"

# Проверка целостности созданного DMG
hdiutil verify "${DMG_PATH}" >/dev/null

# Вычисление контрольной суммы SHA256
SHA_FILE="${DMG_PATH}.sha256"
if command -v shasum >/dev/null 2>&1; then
    (cd "${OUTPUT_DIR}" && shasum -a 256 "$(basename "${DMG_PATH}")" > "$(basename "${SHA_FILE}")")
elif command -v sha256sum >/dev/null 2>&1; then
    (cd "${OUTPUT_DIR}" && sha256sum "$(basename "${DMG_PATH}")" > "$(basename "${SHA_FILE}")")
fi

DMG_SIZE="$(du -h "${DMG_PATH}" | awk '{print $1}')"

echo ""
echo "=========================================="
echo "✅ DMG-образ успешно создан!"
echo "Файл:    ${DMG_PATH}"
echo "Размер:  ${DMG_SIZE}"
if [[ -f "${SHA_FILE}" ]]; then
    echo "SHA256:  $(cat "${SHA_FILE}")"
fi
echo "=========================================="
