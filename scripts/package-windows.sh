#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Outline Proxy — Скрипт сборки и упаковки клиента под Windows (x86_64)
# -----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Автоматическое обнаружение LLVM и LLD из Homebrew на macOS для cargo-xwin
for llvm_candidate in /opt/homebrew/opt/llvm@* /opt/homebrew/opt/llvm /usr/local/opt/llvm@* /usr/local/opt/llvm; do
    if [[ -d "${llvm_candidate}/bin" ]]; then
        export PATH="${llvm_candidate}/bin:${PATH}"
        break
    fi
done

for lld_candidate in /opt/homebrew/opt/lld@* /opt/homebrew/opt/lld /usr/local/opt/lld@* /usr/local/opt/lld; do
    if [[ -d "${lld_candidate}/bin" ]]; then
        export PATH="${lld_candidate}/bin:${PATH}"
        break
    fi
done

DEFAULT_OUTPUT_DIR="${REPO_ROOT}/dist/windows"
OUTPUT_DIR="${DEFAULT_OUTPUT_DIR}"
CACHE_DIR="${REPO_ROOT}/.cache"
ZIP_ARCHIVE="OutlineProxy-x86_64.zip"

CHECK_ONLY=false
SKIP_UI=false

WINTUN_VERSION="0.14.1"
WINTUN_URL="https://www.wintun.net/builds/wintun-${WINTUN_VERSION}.zip"
WINTUN_EXPECTED_SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
WINTUN_ZIP="${CACHE_DIR}/wintun-${WINTUN_VERSION}.zip"

TARGET_TRIPLE="x86_64-pc-windows-msvc"
TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}/${TARGET_TRIPLE}"

print_help() {
    cat <<EOF
Использование: $(basename "$0") [ОПЦИИ]

Скрипт компиляции и бандлинга Windows-клиента Outline Proxy (x86_64).
Собирает сетевое ядро outline-client.exe, GUI-оболочку OutlineProxy.exe (Tauri v2 + Svelte 5),
загружает проверенный драйвер Wintun (wintun.dll) и формирует архив OutlineProxy-x86_64.zip.

Опции:
  -h, --help           Показать эту справку и выйти
  --check-only         Проверить окружение, наличие инструментов и исходников без сборки
  --output-dir <DIR>   Каталог вывода собранных файлов (по умолчанию: dist/windows)
  --zip-name <NAME>    Имя формируемого zip-архива (по умолчанию: OutlineProxy-x86_64.zip)
  --skip-ui            Собрать только сетевое ядро (outline-client.exe) и wintun.dll без GUI

Примеры:
  $(basename "$0") --check-only
  $(basename "$0")
  $(basename "$0") --skip-ui --output-dir /tmp/outline-dist
EOF
}

# Парсинг аргументов
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            print_help
            exit 0
            ;;
        --check-only)
            CHECK_ONLY=true
            shift
            ;;
        --skip-ui)
            SKIP_UI=true
            shift
            ;;
        --output-dir)
            if [[ $# -lt 2 || -z "$2" ]]; then
                echo "Ошибка: опция --output-dir требует указания пути к каталогу" >&2
                exit 1
            fi
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --zip-name)
            if [[ $# -lt 2 || -z "$2" ]]; then
                echo "Ошибка: опция --zip-name требует указания имени архива" >&2
                exit 1
            fi
            ZIP_ARCHIVE="$2"
            shift 2
            ;;
        *)
            echo "Ошибка: неизвестный аргумент: $1" >&2
            echo "Используйте --help для получения справки" >&2
            exit 1
            ;;
    esac
done

# Определение типа ОС хоста
IS_WINDOWS=false
case "${OSTYPE:-}" in
    msys*|cygwin*|win32*|mingw*)
        IS_WINDOWS=true
        ;;
    *)
        if [[ "$(uname -s 2>/dev/null)" =~ ^(CYGWIN|MINGW|MSYS) ]]; then
            IS_WINDOWS=true
        fi
        ;;
esac

# Определение метаданных сборки (коммит и канал)
if [[ -z "${OUTLINE_BUILD_COMMIT:-}" ]]; then
    if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        OUTLINE_BUILD_COMMIT="$(git rev-parse --short HEAD)"
    else
        OUTLINE_BUILD_COMMIT="dev"
    fi
fi
export OUTLINE_BUILD_COMMIT
export OUTLINE_BUILD_CHANNEL="${OUTLINE_BUILD_CHANNEL:-nightly}"

compute_sha256() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${file}" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${file}" | awk '{print $1}'
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], 'rb').read()).hexdigest())" "${file}"
    else
        echo "Ошибка: не найден инструмент для вычисления SHA256 (sha256sum, shasum, python3)" >&2
        return 1
    fi
}

extract_wintun_dll() {
    local zip_file="$1"
    local dest_file="$2"
    if command -v unzip >/dev/null 2>&1; then
        unzip -p "${zip_file}" "wintun/bin/amd64/wintun.dll" > "${dest_file}"
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "
import zipfile, sys
with zipfile.ZipFile(sys.argv[1], 'r') as z:
    with open(sys.argv[2], 'wb') as f:
        f.write(z.read('wintun/bin/amd64/wintun.dll'))
" "${zip_file}" "${dest_file}"
    else
        echo "Ошибка: для распаковки wintun.dll требуется утилита unzip или python3" >&2
        return 1
    fi
}

fetch_wintun() {
    local dest_file="${1:-${OUTPUT_DIR}/wintun.dll}"
    mkdir -p "${CACHE_DIR}"
    mkdir -p "$(dirname "${dest_file}")"

    local need_download=true
    if [[ -f "${WINTUN_ZIP}" ]]; then
        local actual_sha256
        actual_sha256="$(compute_sha256 "${WINTUN_ZIP}")"
        if [[ "${actual_sha256}" == "${WINTUN_EXPECTED_SHA256}" ]]; then
            echo "    Переиспользование кэша: ${WINTUN_ZIP}"
            need_download=false
        else
            echo "    Кэш поврежден (SHA256 не совпадает). Повторное скачивание..."
            rm -f "${WINTUN_ZIP}"
        fi
    fi

    if [[ "${need_download}" == "true" ]]; then
        echo "    Скачивание ${WINTUN_URL}..."
        curl -fSL "${WINTUN_URL}" -o "${WINTUN_ZIP}.tmp"
        local downloaded_sha256
        downloaded_sha256="$(compute_sha256 "${WINTUN_ZIP}.tmp")"
        if [[ "${downloaded_sha256}" != "${WINTUN_EXPECTED_SHA256}" ]]; then
            echo "Ошибка: контрольная сумма Wintun не совпадает!" >&2
            echo "Ожидалось: ${WINTUN_EXPECTED_SHA256}" >&2
            echo "Получено:   ${downloaded_sha256}" >&2
            rm -f "${WINTUN_ZIP}.tmp"
            return 1
        fi
        mv "${WINTUN_ZIP}.tmp" "${WINTUN_ZIP}"
        echo "    Wintun успешно скачан и проверен."
    fi

    echo "    Извлечение wintun.dll (x86_64)..."
    extract_wintun_dll "${WINTUN_ZIP}" "${dest_file}"
}

create_zip_archive() {
    local zip_name="$1"
    shift
    local files=("$@")

    # Удаление предыдущего архива перед упаковкой для предотвращения
    # попадания устаревших файлов из прошлых сборок (например, при --skip-ui)
    rm -f "${OUTPUT_DIR}/${zip_name}"

    if command -v zip >/dev/null 2>&1; then
        (cd "${OUTPUT_DIR}" && zip -9 -q "${zip_name}" "${files[@]}")
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "
import zipfile, sys, os
out_zip = sys.argv[1]
output_dir = sys.argv[2]
files = sys.argv[3:]
zip_path = os.path.join(output_dir, out_zip)
with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
    for f in files:
        full_path = os.path.join(output_dir, f)
        if os.path.exists(full_path):
            z.write(full_path, arcname=f)
" "${zip_name}" "${OUTPUT_DIR}" "${files[@]}"
    else
        echo "Предупреждение: утилита zip или python3 не найдена, архив не создан" >&2
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Режим --check-only
# -----------------------------------------------------------------------------
if [[ "${CHECK_ONLY}" == "true" ]]; then
    echo "=== Валидация окружения сборки Windows-клиента Outline Proxy ==="
    echo "Платформа хоста: $(uname -s) ($(uname -m))"
    echo "Целевой таргет: ${TARGET_TRIPLE}"
    echo "Канал сборки: ${OUTLINE_BUILD_CHANNEL}"
    echo "Коммит: ${OUTLINE_BUILD_COMMIT}"
    if [[ "${IS_WINDOWS}" == "true" ]]; then
        echo "Режим сборки: нативная компиляция (Windows MSVC)"
    else
        echo "Режим сборки: кросс-компиляция (cargo-xwin)"
    fi
    echo ""

    ERRORS=0

    # Проверка Rust
    if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1; then
        echo "[OK] Rust: $(rustc --version)"
    else
        echo "[ОШИБКА] Cargo/Rust не найдены на PATH" >&2
        ERRORS=$((ERRORS + 1))
    fi

    # Проверка инструментов кросс-компиляции
    if [[ "${IS_WINDOWS}" == "false" ]]; then
        if command -v cargo-xwin >/dev/null 2>&1; then
            echo "[OK] cargo-xwin: $(cargo-xwin --version 2>/dev/null || echo 'установлен')"
        else
            echo "[ИНФО] cargo-xwin не найден. Для кросс-компиляции с macOS/Linux выполните: cargo install cargo-xwin"
        fi
    fi

    # Проверка Node/pnpm
    if command -v pnpm >/dev/null 2>&1; then
        echo "[OK] pnpm: v$(pnpm --version)"
    elif command -v npm >/dev/null 2>&1; then
        echo "[OK] npm: v$(npm --version) (рекомендуется pnpm)"
    else
        echo "[ПРЕДУПРЕЖДЕНИЕ] pnpm или npm не найдены (требуются для сборки фронтенда)"
    fi

    # Проверка утилит скачивания и хеширования
    if command -v curl >/dev/null 2>&1; then
        echo "[OK] curl доступен"
    else
        echo "[ОШИБКА] curl не найден" >&2
        ERRORS=$((ERRORS + 1))
    fi

    if command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
        echo "[OK] Утилита вычисления SHA256 доступна"
    else
        echo "[ОШИБКА] Не найдена утилита для проверки SHA256" >&2
        ERRORS=$((ERRORS + 1))
    fi

    if command -v unzip >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1; then
        echo "[OK] Утилита распаковки ZIP доступна"
    else
        echo "[ОШИБКА] Не найдена утилита для распаковки ZIP (unzip или python3)" >&2
        ERRORS=$((ERRORS + 1))
    fi

    # Проверка исходников в репозитории
    echo ""
    echo "--- Проверка исходных файлов репозитория ---"
    if [[ -f "${REPO_ROOT}/bins/outline-client/Cargo.toml" ]]; then
        echo "[OK] Сетевое ядро: bins/outline-client/Cargo.toml"
    else
        echo "[ОШИБКА] Не найден bins/outline-client/Cargo.toml" >&2
        ERRORS=$((ERRORS + 1))
    fi

    if [[ -f "${REPO_ROOT}/bins/outline-windows/Cargo.toml" && -f "${REPO_ROOT}/bins/outline-windows/tauri.conf.json" ]]; then
        echo "[OK] Windows GUI: bins/outline-windows"
    else
        echo "[ОШИБКА] Не найдены конфигурации bins/outline-windows" >&2
        ERRORS=$((ERRORS + 1))
    fi

    # Проверка зависимостей node_modules для сборки UI
    if [[ -d "${REPO_ROOT}/bins/outline-windows/node_modules" ]]; then
        echo "[OK] Зависимости интерфейса: bins/outline-windows/node_modules"
    else
        echo "[ПРЕДУПРЕЖДЕНИЕ] bins/outline-windows/node_modules не найдены. Перед сборкой интерфейса выполните: (cd bins/outline-windows && pnpm install)"
    fi

    # Проверка состояния кэша Wintun
    if [[ -f "${WINTUN_ZIP}" ]]; then
        ACTUAL_SHA256="$(compute_sha256 "${WINTUN_ZIP}")"
        if [[ "${ACTUAL_SHA256}" == "${WINTUN_EXPECTED_SHA256}" ]]; then
            echo "[OK] Кэш Wintun ${WINTUN_VERSION} проверен: ${WINTUN_ZIP}"
        else
            echo "[ПРЕДУПРЕЖДЕНИЕ] Кэш Wintun поврежден (хэш не совпадает), при сборке будет перекачан"
        fi
    else
        echo "[ИНФО] Кэш Wintun отсутствует, будет автоматически скачан при сборке"
    fi

    echo ""
    if [[ ${ERRORS} -eq 0 ]]; then
        echo "✅ Проверка окружения успешно завершена (ошибок нет)."
        exit 0
    else
        echo "❌ Проверка завершилась с ошибками (обнаружено: ${ERRORS})." >&2
        exit 1
    fi
fi

# -----------------------------------------------------------------------------
# Основной процесс сборки и бандлинга
# -----------------------------------------------------------------------------
echo "=== Сборка Outline Proxy для Windows (${TARGET_TRIPLE}) ==="
echo "Канал сборки: ${OUTLINE_BUILD_CHANNEL}"
echo "Коммит: ${OUTLINE_BUILD_COMMIT}"

# 1. Проверка окружения перед выполнением сборки
if [[ -d "/opt/homebrew/Cellar/llvm@22/22.1.8/bin" && -d "/opt/homebrew/Cellar/lld@22/22.1.8/bin" ]]; then
    export PATH="/opt/homebrew/Cellar/llvm@22/22.1.8/bin:/opt/homebrew/Cellar/lld@22/22.1.8/bin:$PATH"
fi

XWIN_CACHE="${HOME}/Library/Caches/cargo-xwin/xwin"
if [[ -d "${XWIN_CACHE}" ]]; then
    export RUSTFLAGS="-C target-feature=+crt-static -Clink-arg=libucrt.lib -Lnative=${XWIN_CACHE}/crt/lib/x86_64 -Lnative=${XWIN_CACHE}/sdk/lib/um/x86_64 -Lnative=${XWIN_CACHE}/sdk/lib/ucrt/x86_64 ${RUSTFLAGS:-}"
else
    export RUSTFLAGS="-C target-feature=+crt-static ${RUSTFLAGS:-}"
fi

if [[ "${IS_WINDOWS}" == "true" ]]; then
    # Git for Windows поставляет GNU coreutils link.exe в /usr/bin, который затеняет
    # системный линкер MSVC link.exe. Удаляем его, чтобы rustc использовал MSVC link.exe.
    rm -f "/usr/bin/link.exe" "/c/Program Files/Git/usr/bin/link.exe" "C:/Program Files/Git/usr/bin/link.exe" 2>/dev/null || true

    # На Windows MSVC архиватором является lib.exe. .cargo/config.toml глобально форсит
    # AR="zig ar" для кросс-сборки musl, однако zig ar не принимает флаги MSVC (-out:... -nologo).
    # Явно задаем AR_x86_64_pc_windows_msvc для cc-rs (aws-lc-sys и др.).
    export AR_x86_64_pc_windows_msvc="${AR_x86_64_pc_windows_msvc:-lib.exe}"
    CARGO_CMD=("cargo" "build" "--target" "${TARGET_TRIPLE}" "--release")
else
    if ! command -v cargo-xwin >/dev/null 2>&1; then
        echo "Ошибка: для кросс-компиляции под Windows с macOS/Linux требуется cargo-xwin." >&2
        echo "Установите его командой: cargo install cargo-xwin" >&2
        exit 1
    fi
    CARGO_CMD=("cargo" "xwin" "build" "--target" "${TARGET_TRIPLE}" "--release")
fi

mkdir -p "${OUTPUT_DIR}"
mkdir -p "${CACHE_DIR}"

# 2. Скачивание и валидация Wintun ${WINTUN_VERSION}
echo "==> [1/5] Проверка и подготовка Wintun ${WINTUN_VERSION}..."
fetch_wintun "${OUTPUT_DIR}/wintun.dll"

# 3. Сборка сетевого ядра outline-client
echo "==> [2/5] Компиляция сетевого ядра outline-client.exe (${TARGET_TRIPLE})..."
(cd "${REPO_ROOT}" && "${CARGO_CMD[@]}" -p outline-client)

CLIENT_EXE="${TARGET_DIR}/release/outline-client.exe"
if [[ ! -f "${CLIENT_EXE}" ]]; then
    echo "Ошибка: собранный бинарник не найден: ${CLIENT_EXE}" >&2
    exit 1
fi
cp "${CLIENT_EXE}" "${OUTPUT_DIR}/outline-client.exe"

# 4. Сборка фронтенда и GUI-оболочки (если не --skip-ui)
PACK_FILES=("outline-client.exe" "wintun.dll")

if [[ "${SKIP_UI}" == "false" ]]; then
    echo "==> [3/5] Сборка интерфейса пользователя (Svelte 5 + Vite)..."
    if command -v pnpm >/dev/null 2>&1; then
        NPM_BUILD_CMD=("pnpm" "build")
    elif command -v npm >/dev/null 2>&1; then
        NPM_BUILD_CMD=("npm" "run" "build")
    else
        echo "Ошибка: для сборки фронтенда требуется pnpm или npm." >&2
        exit 1
    fi

    if [[ -f "${REPO_ROOT}/bins/outline-windows/package.json" ]]; then
        (cd "${REPO_ROOT}/bins/outline-windows" && "${NPM_BUILD_CMD[@]}")
    elif [[ -f "${REPO_ROOT}/bins/outline-windows/frontend/package.json" ]]; then
        (cd "${REPO_ROOT}/bins/outline-windows/frontend" && "${NPM_BUILD_CMD[@]}")
    fi

    echo "==> [4/5] Компиляция GUI-оболочки OutlineProxy.exe (-p outline-windows)..."
    (cd "${REPO_ROOT}" && "${CARGO_CMD[@]}" -p outline-windows)

    GUI_EXE=""
    if [[ -f "${TARGET_DIR}/release/OutlineProxy.exe" ]]; then
        GUI_EXE="${TARGET_DIR}/release/OutlineProxy.exe"
    elif [[ -f "${TARGET_DIR}/release/outline-windows.exe" ]]; then
        GUI_EXE="${TARGET_DIR}/release/outline-windows.exe"
    fi

    if [[ -z "${GUI_EXE}" || ! -f "${GUI_EXE}" ]]; then
        echo "Ошибка: собранный бинарник GUI не найден в ${TARGET_DIR}/release/" >&2
        exit 1
    fi

    cp "${GUI_EXE}" "${OUTPUT_DIR}/OutlineProxy.exe"
    PACK_FILES=("OutlineProxy.exe" "${PACK_FILES[@]}")
else
    echo "==> [3/5] Пропуск сборки интерфейса (--skip-ui)"
    echo "==> [4/5] Пропуск сборки GUI-оболочки (--skip-ui)"
fi

# 5. Упаковка в ZIP-архив
echo "==> [5/5] Формирование архива ${ZIP_ARCHIVE}..."
create_zip_archive "${ZIP_ARCHIVE}" "${PACK_FILES[@]}"

echo ""
echo "================================================================="
echo "✅ Сборка успешно завершена!"
echo "Каталог пакета: ${OUTPUT_DIR}"
echo "Состав:"
for f in "${PACK_FILES[@]}"; do
    echo "  - ${OUTPUT_DIR}/${f}"
done
if [[ -f "${OUTPUT_DIR}/${ZIP_ARCHIVE}" ]]; then
    echo "Архив релиза: ${OUTPUT_DIR}/${ZIP_ARCHIVE}"
fi
echo "================================================================="
