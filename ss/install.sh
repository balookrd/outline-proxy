#!/usr/bin/env bash
set -Eeuo pipefail

REPO="${REPO:-balookrd/outline-ss-rust}"
BINARY_NAME="outline-ss-rust"
SERVICE_NAME="${SERVICE_NAME:-outline-ss-rust.service}"
CHANNEL="${CHANNEL:-stable}"
VERSION="${VERSION:-}"

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

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

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

github_api_url() {
  local path="$1"
  printf 'https://api.github.com/repos/%s/%s' "$REPO" "$path"
}

resolve_release() {
  local api_path release_json tag_line url_line asset_pattern

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

  release_json="$(fetch_stdout "$(github_api_url "$api_path")")" || die "Не удалось получить release metadata из GitHub API"

  tag_line="$(printf '%s\n' "$release_json" | grep -m1 '"tag_name":')"
  RELEASE_TAG="$(printf '%s\n' "$tag_line" | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/')"
  [[ -n "$RELEASE_TAG" && "$RELEASE_TAG" != "$tag_line" ]] || die "Не удалось определить tag_name релиза"

  asset_pattern="/${BINARY_NAME}-v[^/]*-${TARGET_TRIPLE}\\.tar\\.gz$"
  url_line="$(printf '%s\n' "$release_json" | sed -nE 's/.*"browser_download_url":[[:space:]]*"([^"]+)".*/\1/p' | grep -E "$asset_pattern" | head -n1 || true)"
  RELEASE_ASSET_URL="$url_line"

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
  need_root
  require_tools
  detect_arch
  resolve_release

  log "Архитектура: ${TARGET_TRIPLE}"
  log "Канал: ${CHANNEL}"
  log "Release: ${RELEASE_TAG}"

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
