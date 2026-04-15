#!/usr/bin/env bash
set -Eeuo pipefail

REPO="${REPO:-balookrd/outline-ss-rust}"
BINARY_NAME="outline-ss-rust"
SERVICE_NAME="${SERVICE_NAME:-outline-ss-rust.service}"
CHANNEL="${CHANNEL:-stable}"
VERSION="${VERSION:-}"
FORCE="${FORCE:-}"
GITHUB_API="${GITHUB_API:-https://api.github.com}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

INSTALL_BIN_DIR="${INSTALL_BIN_DIR:-/usr/local/bin}"
INSTALL_BIN_PATH="${INSTALL_BIN_DIR}/${BINARY_NAME}"

CONFIG_DIR="${CONFIG_DIR:-/etc/outline-ss-rust}"
CONFIG_PATH="${CONFIG_DIR}/config.toml"

STATE_DIR="${STATE_DIR:-/var/lib/outline-ss-rust}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_PATH="${SYSTEMD_DIR}/${SERVICE_NAME}"

SERVICE_USER="${SERVICE_USER:-outline-ss-rust}"
SERVICE_GROUP="${SERVICE_GROUP:-outline-ss-rust}"
SERVICE_WAS_ACTIVE=0
INSTALLED_VERSION=""
SKIP_UPDATE=0
RELEASE_COMMIT=""
NIGHTLY_COMMIT_FILE="${NIGHTLY_COMMIT_FILE:-${STATE_DIR}/nightly-commit}"

TMP_DIR=""
trap '[[ -n "${TMP_DIR:-}" ]] && rm -rf "$TMP_DIR"' EXIT

log() {
  printf '[+] %s\n' "$*"
}

warn() {
  printf '[!] %s\n' "$*" >&2
}

die() {
  printf '[x] %s\n' "$*" >&2
  exit 1
}

show_usage() {
  cat <<EOF
Usage:
  ./install.sh [--help]

Устанавливает или обновляет ${BINARY_NAME} на Linux.
Саму установку нужно запускать от root, но справку можно посмотреть без root.

Режимы установки:
  CHANNEL=stable    установить последний stable release (по умолчанию)
  CHANNEL=nightly   установить rolling nightly prerelease
  VERSION=v1.2.3    установить конкретный stable tag

Примеры:
  ./install.sh --help
  sudo ./install.sh
  sudo CHANNEL=nightly ./install.sh
  sudo VERSION=v1.2.3 ./install.sh

Дополнительные переменные окружения:
  REPO=${REPO}
  SERVICE_NAME=${SERVICE_NAME}
  INSTALL_BIN_DIR=${INSTALL_BIN_DIR}
  CONFIG_DIR=${CONFIG_DIR}
  STATE_DIR=${STATE_DIR}
  SYSTEMD_DIR=${SYSTEMD_DIR}
  SERVICE_USER=${SERVICE_USER}
  SERVICE_GROUP=${SERVICE_GROUP}
  FORCE=1            принудительно переустановить, даже если версия актуальна
  GITHUB_TOKEN=...   GitHub token для обхода rate limit API
EOF
}

need_root() {
  [[ "${EUID}" -eq 0 ]] || die "Запусти скрипт от root"
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

fetch() {
  local url="$1"
  local out="$2"

  if have_cmd curl; then
    curl -fL --retry 3 --connect-timeout 15 -o "$out" "$url"
  elif have_cmd wget; then
    wget -O "$out" "$url"
  else
    die "Нужен curl или wget"
  fi
}

fetch_stdout() {
  local url="$1"

  if have_cmd curl; then
    curl -fsSL --retry 3 --connect-timeout 15 "$url"
  elif have_cmd wget; then
    wget -qO- "$url"
  else
    die "Нужен curl или wget"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        show_usage
        exit 0
        ;;
      -f|--force)
        FORCE=1
        ;;
      *)
        die "Неизвестный аргумент: $1. Используй --help для справки."
        ;;
    esac
    shift
  done
}

prepare_tmp_dir() {
  TMP_DIR="$(mktemp -d)"
}

require_tools() {
  have_cmd tar || die "Не найден tar"
  have_cmd uname || die "Не найден uname"
  have_cmd install || die "Не найден install"
  have_cmd find || die "Не найден find"
  have_cmd systemctl || die "Не найден systemctl"
  have_cmd mktemp || die "Не найден mktemp"
  have_cmd getent || die "Не найден getent"
  have_cmd useradd || die "Не найден useradd"
  have_cmd groupadd || die "Не найден groupadd"

  if ! have_cmd systemd-analyze; then
    warn "systemd-analyze не найден, проверка unit будет пропущена"
  fi
}

detect_arch() {
  local arch
  arch="$(uname -m)"

  case "$arch" in
    x86_64|amd64)
      TARGET_TRIPLE="x86_64-unknown-linux-musl"
      ;;
    aarch64|arm64)
      TARGET_TRIPLE="aarch64-unknown-linux-musl"
      ;;
    *)
      die "Неподдерживаемая архитектура: $arch"
      ;;
  esac
}

github_api_get() {
  local url="$1"
  if [[ -n "$GITHUB_TOKEN" ]]; then
    curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "$url"
  else
    curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "$url"
  fi
}

github_api_url() {
  local path="$1"
  printf '%s/repos/%s/%s' "$GITHUB_API" "$REPO" "$path"
}

# Извлекает значение строкового поля из JSON-ответа GitHub API.
release_field() {
  local field="$1"
  grep -oE "\"${field}\":[[:space:]]*\"([^\"\\\\]|\\\\.)*\"" \
    | head -n1 \
    | sed -E "s/^\"${field}\":[[:space:]]*\"(([^\"\\\\]|\\\\.)*)\"$/\\1/"
}

strip_v() { echo "${1#v}"; }

# Возвращает короткий (12 символов) SHA коммита для тега nightly.
# Сначала берёт target_commitish из release JSON; если это ветка, а не SHA —
# делает доп. запрос к refs API и при annotated-теге разыменовывает его.
get_nightly_commit_sha() {
  local release_json="$1"
  local commitish sha type ref_json tag_json

  commitish="$(printf '%s' "$release_json" | release_field target_commitish)"

  if [[ "$commitish" =~ ^[0-9a-f]{40}$ ]]; then
    echo "${commitish:0:12}"
    return
  fi

  # target_commitish — имя ветки; резолвим через refs API
  ref_json="$(github_api_get "$(github_api_url "git/ref/tags/nightly")" 2>/dev/null || true)"

  [[ -n "$ref_json" ]] || { echo ""; return; }

  type="$(printf '%s' "$ref_json" \
    | grep -oE '"type":[[:space:]]*"[^"]+"' | head -n1 \
    | sed -E 's/^"type":[[:space:]]*"([^"]+)"$/\1/')"
  sha="$(printf '%s' "$ref_json" \
    | grep -oE '"sha":[[:space:]]*"[^"]+"' | head -n1 \
    | sed -E 's/^"sha":[[:space:]]*"([^"]+)"$/\1/')"

  if [[ "$type" == "tag" ]]; then
    # Annotated tag — разыменовываем до commit-объекта
    tag_json="$(github_api_get "$(github_api_url "git/tags/${sha}")" 2>/dev/null || true)"
    sha="$(printf '%s' "$tag_json" \
      | grep -oE '"sha":[[:space:]]*"[^"]+"' | tail -n1 \
      | sed -E 's/^"sha":[[:space:]]*"([^"]+)"$/\1/')"
  fi

  echo "${sha:0:12}"
}

resolve_release() {
  local api_path release_json asset_pattern

  if [[ -n "$VERSION" ]]; then
    [[ "$VERSION" == v* ]] || die "VERSION должен быть в формате v1.2.3"
    [[ "$CHANNEL" == "stable" ]] || die "Нельзя одновременно задавать VERSION и CHANNEL=${CHANNEL}. Используй либо stable по VERSION, либо CHANNEL=nightly."
    api_path="releases/tags/${VERSION}"
  else
    case "$CHANNEL" in
      stable)
        api_path="releases/latest"
        ;;
      nightly)
        api_path="releases/tags/nightly"
        ;;
      *)
        die "Неподдерживаемый CHANNEL: ${CHANNEL}. Допустимо: stable, nightly"
        ;;
    esac
  fi

  release_json="$(github_api_get "$(github_api_url "$api_path")")" || die "Не удалось получить release metadata из GitHub API"

  RELEASE_TAG="$(printf '%s' "$release_json" | release_field tag_name)"
  [[ -n "$RELEASE_TAG" ]] || die "Не удалось определить tag_name релиза"

  if [[ "$CHANNEL" == "nightly" ]]; then
    RELEASE_COMMIT="$(get_nightly_commit_sha "$release_json")"
    [[ -n "$RELEASE_COMMIT" ]] || warn "Не удалось получить commit SHA для nightly — проверка версии будет пропущена"
  fi

  asset_pattern="/${BINARY_NAME}-v[^/]*-${TARGET_TRIPLE}\\.tar\\.gz$"
  RELEASE_ASSET_URL="$(printf '%s' "$release_json" \
    | grep -oE '"browser_download_url":[[:space:]]*"[^"]+"' \
    | sed -E 's/^"browser_download_url":[[:space:]]*"([^"]+)"$/\1/' \
    | grep -E "$asset_pattern" | head -n1 || true)"

  [[ -n "$RELEASE_ASSET_URL" ]] || \
    die "Не удалось найти release-артефакт для ${TARGET_TRIPLE} в релизе ${RELEASE_TAG}"
}

tag_raw_url() {
  local tag="$1"
  local path="$2"
  printf 'https://raw.githubusercontent.com/%s/%s/%s' "$REPO" "$tag" "$path"
}

extract_binary() {
  local archive="$1"
  local dest_tmp="$2"
  local extract_dir="${TMP_DIR}/extract"

  rm -rf "$extract_dir"
  mkdir -p "$extract_dir"
  tar -xzf "$archive" -C "$extract_dir"

  local found=""
  while IFS= read -r -d '' f; do
    local base
    base="$(basename "$f")"

    if [[ -f "$f" ]] && [[ "$base" == "$BINARY_NAME" || "$base" == "${BINARY_NAME}-"* ]]; then
      found="$f"
      break
    fi
  done < <(find "$extract_dir" -type f -print0)

  [[ -n "$found" ]] || die "Не удалось найти бинарь ${BINARY_NAME} в архиве"
  install -m 0755 "$found" "$dest_tmp"
}

ensure_user_group() {
  if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    log "Создаю группу ${SERVICE_GROUP}"
    groupadd --system "$SERVICE_GROUP"
  fi

  if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "Создаю пользователя ${SERVICE_USER}"
    useradd \
      --system \
      --gid "$SERVICE_GROUP" \
      --home-dir "$STATE_DIR" \
      --create-home \
      --shell /usr/sbin/nologin \
      "$SERVICE_USER"
  fi
}

install_dirs() {
  install -d -m 0755 "$INSTALL_BIN_DIR"
  install -d -m 0755 "$CONFIG_DIR"
  install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR"
}

install_config_if_missing() {
  if [[ -f "$CONFIG_PATH" ]]; then
    log "Конфиг уже существует: ${CONFIG_PATH}"
    return
  fi

  local cfg_url
  cfg_url="$(tag_raw_url "$RELEASE_TAG" "config.toml")"

  log "Скачиваю пример конфига ${cfg_url}"
  fetch "$cfg_url" "$CONFIG_PATH"
  chmod 0640 "$CONFIG_PATH"
  chown root:"$SERVICE_GROUP" "$CONFIG_PATH"
}

install_systemd_unit() {
  local unit_url tmp_unit
  unit_url="$(tag_raw_url "$RELEASE_TAG" "systemd/${SERVICE_NAME}")"
  tmp_unit="${TMP_DIR}/${SERVICE_NAME}"

  log "Скачиваю systemd unit ${unit_url}"
  fetch "$unit_url" "$tmp_unit"
  chmod 0644 "$tmp_unit"

  if have_cmd systemd-analyze; then
    log "Проверяю unit через systemd-analyze verify"
    systemd-analyze verify "$tmp_unit" >/dev/null
  fi

  install -m 0644 "$tmp_unit" "$SERVICE_PATH"
}

install_binary() {
  local archive tmp_bin backup_path=""
  archive="${TMP_DIR}/${BINARY_NAME}.tar.gz"
  tmp_bin="${TMP_DIR}/${BINARY_NAME}.new"

  log "Скачиваю архив ${RELEASE_ASSET_URL}"
  if ! fetch "$RELEASE_ASSET_URL" "$archive"; then
    die "Не удалось скачать release-артефакт для ${TARGET_TRIPLE}. Текущий GitHub CI публикует только x86_64-unknown-linux-musl и aarch64-unknown-linux-musl."
  fi

  log "Распаковываю бинарь"
  extract_binary "$archive" "$tmp_bin"

  if [[ -f "$INSTALL_BIN_PATH" ]]; then
    backup_path="${INSTALL_BIN_PATH}.bak.$(date +%Y%m%d%H%M%S)"
    log "Делаю backup старого бинаря: ${backup_path}"
    cp -a "$INSTALL_BIN_PATH" "$backup_path"
  fi

  log "Устанавливаю бинарь в ${INSTALL_BIN_PATH}"
  install -m 0755 "$tmp_bin" "${INSTALL_BIN_PATH}.tmp"
  mv -f "${INSTALL_BIN_PATH}.tmp" "$INSTALL_BIN_PATH"
  save_release_commit
}

get_installed_version() {
  if [[ -x "$INSTALL_BIN_PATH" ]]; then
    "$INSTALL_BIN_PATH" --version 2>/dev/null | awk '{print $2}' || true
  fi
}

check_up_to_date() {
  INSTALLED_VERSION="$(get_installed_version)"

  if [[ -z "$INSTALLED_VERSION" ]]; then
    log "Бинарь не установлен, выполняю первичную установку"
    return
  fi

  if [[ "$CHANNEL" == "nightly" ]]; then
    if [[ -z "$RELEASE_COMMIT" ]]; then
      log "Nightly: commit SHA недоступен — устанавливаю безусловно"
      return
    fi

    local stored_commit=""
    [[ -f "$NIGHTLY_COMMIT_FILE" ]] && stored_commit="$(cat "$NIGHTLY_COMMIT_FILE" 2>/dev/null || true)"

    if [[ -z "$stored_commit" ]]; then
      log "Nightly: сохранённый коммит не найден, выполняю установку"
    elif [[ "$stored_commit" == "$RELEASE_COMMIT" ]]; then
      if [[ -n "$FORCE" ]]; then
        log "Nightly: уже установлен коммит ${RELEASE_COMMIT}, но FORCE — продолжаю"
      else
        SKIP_UPDATE=1
        log "Nightly: уже установлен актуальный коммит ${RELEASE_COMMIT} — обновление не требуется"
        log "Используй --force или FORCE=1 для принудительной переустановки"
      fi
    else
      log "Nightly: доступно обновление ${stored_commit} → ${RELEASE_COMMIT}"
    fi
    return
  fi

  local release_ver
  release_ver="$(strip_v "$RELEASE_TAG")"

  if [[ "$INSTALLED_VERSION" == "$release_ver" ]]; then
    if [[ -n "$FORCE" ]]; then
      log "Установлена актуальная версия ${INSTALLED_VERSION}, но FORCE — продолжаю"
    else
      SKIP_UPDATE=1
      log "Уже установлена актуальная версия ${INSTALLED_VERSION} — обновление не требуется"
      log "Используй --force или FORCE=1 для принудительной переустановки"
    fi
  else
    log "Доступно обновление: ${INSTALLED_VERSION} → ${release_ver}"
  fi
}

save_release_commit() {
  if [[ -n "$RELEASE_COMMIT" ]]; then
    mkdir -p "$(dirname "$NIGHTLY_COMMIT_FILE")"
    printf '%s\n' "$RELEASE_COMMIT" > "$NIGHTLY_COMMIT_FILE"
    chmod 0644 "$NIGHTLY_COMMIT_FILE"
    log "Nightly commit: ${RELEASE_COMMIT}"
  elif [[ -f "$NIGHTLY_COMMIT_FILE" ]]; then
    rm -f "$NIGHTLY_COMMIT_FILE"
    log "Удалён файл nightly-commit (переключение на stable)"
  fi
}

remember_service_state() {
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    SERVICE_WAS_ACTIVE=1
    log "Сервис ${SERVICE_NAME} уже запущен, будет перезапущен после обновления"
  else
    SERVICE_WAS_ACTIVE=0
  fi
}

reload_systemd() {
  log "Перечитываю конфигурацию systemd"
  systemctl daemon-reload
}

restart_service_if_needed() {
  if [[ "$SERVICE_WAS_ACTIVE" -eq 1 ]]; then
    log "Перезапускаю уже запущенный сервис ${SERVICE_NAME}"
    systemctl restart "$SERVICE_NAME"
  fi
}

show_summary() {
  echo
  echo "Готово."
  echo "Channel: ${CHANNEL}"
  echo "Release: ${RELEASE_TAG}"
  if [[ "$CHANNEL" == "nightly" && -n "$RELEASE_COMMIT" ]]; then
    echo "Commit  : ${RELEASE_COMMIT}"
  elif [[ -n "$INSTALLED_VERSION" && "$INSTALLED_VERSION" != "${RELEASE_TAG#v}" ]]; then
    echo "Обновлено: ${INSTALLED_VERSION} → ${RELEASE_TAG#v}"
  fi
  echo "Binary : ${INSTALL_BIN_PATH}"
  echo "Service: ${SERVICE_PATH}"
  echo "Config : ${CONFIG_PATH}"
  echo
  if [[ "$SERVICE_WAS_ACTIVE" -eq 1 ]]; then
    echo "Сервис был активен до обновления и был перезапущен автоматически."
  else
    echo "Сервис не был запущен автоматически."
  fi
  echo "Запуск:"
  echo "  sudo systemctl enable --now ${SERVICE_NAME}"
  echo
  echo "После изменения конфигурации или обновления бинаря:"
  echo "  sudo systemctl restart ${SERVICE_NAME}"
  echo
  echo "Проверка:"
  echo "  systemctl status ${SERVICE_NAME} --no-pager"
  echo "  journalctl -u ${SERVICE_NAME} -e --no-pager"
}

main() {
  parse_args "$@"
  need_root
  prepare_tmp_dir
  require_tools
  detect_arch
  resolve_release

  log "Архитектура: ${TARGET_TRIPLE}"
  log "Канал: ${CHANNEL}"
  log "Release: ${RELEASE_TAG}"

  check_up_to_date
  [[ "$SKIP_UPDATE" -eq 0 ]] || exit 0

  remember_service_state
  ensure_user_group
  install_dirs
  install_binary
  install_config_if_missing
  install_systemd_unit
  reload_systemd
  restart_service_if_needed
  show_summary
}

main "$@"
