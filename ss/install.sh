#!/usr/bin/env bash
set -Eeuo pipefail

REPO="${REPO:-balookrd/outline-ss-rust}"
BINARY_NAME="outline-ss-rust"
SERVICE_NAME="${SERVICE_NAME:-outline-ss-rust.service}"

INSTALL_BIN_DIR="${INSTALL_BIN_DIR:-/usr/local/bin}"
INSTALL_BIN_PATH="${INSTALL_BIN_DIR}/${BINARY_NAME}"

CONFIG_DIR="${CONFIG_DIR:-/etc/outline-ss-rust}"
CONFIG_PATH="${CONFIG_DIR}/config.toml"

STATE_DIR="${STATE_DIR:-/var/lib/outline-ss-rust}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_PATH="${SYSTEMD_DIR}/${SERVICE_NAME}"

SERVICE_USER="${SERVICE_USER:-outline-ss-rust}"
SERVICE_GROUP="${SERVICE_GROUP:-outline-ss-rust}"

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
  if [[ "${EUID}" -ne 0 ]]; then
    die "Запусти скрипт от root"
  fi
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

fetch() {
  local url="$1"
  local out="$2"

  if have_cmd curl; then
    curl -fsSL --retry 3 --connect-timeout 15 -o "$out" "$url"
  elif have_cmd wget; then
    wget -qO "$out" "$url"
  else
    die "Нужен curl или wget"
  fi
}

fetch_to_stdout() {
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
  have_cmd systemctl || die "Не найден systemctl"
  have_cmd uname || die "Не найден uname"
  have_cmd grep || die "Не найден grep"
  have_cmd sed || die "Не найден sed"
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
    armv7l|armv7|armhf)
      TARGET_TRIPLE="armv7-unknown-linux-musleabihf"
      ;;
    *)
      die "Неподдерживаемая архитектура: $arch"
      ;;
  esac
}

github_api_latest_release() {
  fetch_to_stdout "https://api.github.com/repos/${REPO}/releases/latest"
}

extract_release_tag() {
  sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1
}

extract_asset_url() {
  local triple="$1"
  grep -o '"browser_download_url":[[:space:]]*"[^"]*"' \
    | sed 's/.*"browser_download_url":[[:space:]]*"\([^"]*\)"/\1/' \
    | grep "/${BINARY_NAME}-.*-${triple}\.tar\.gz$" \
    | head -n1
}

extract_raw_binary() {
  local archive="$1"
  local dest="$2"

  tar -xzf "$archive" -C "$TMP_DIR"

  local found=""
  while IFS= read -r -d '' f; do
    if [[ "$(basename "$f")" == "$BINARY_NAME" ]] && [[ -x "$f" ]]; then
      found="$f"
      break
    fi
  done < <(find "$TMP_DIR" -type f -perm -111 -print0)

  [[ -n "$found" ]] || die "Не удалось найти бинарь ${BINARY_NAME} в архиве"

  install -m 0755 "$found" "$dest"
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

  local raw_url="https://raw.githubusercontent.com/${REPO}/main/config.toml"
  log "Скачиваю пример конфига ${raw_url}"
  fetch "$raw_url" "$CONFIG_PATH"
  chmod 0640 "$CONFIG_PATH"
  chown root:"$SERVICE_GROUP" "$CONFIG_PATH"
}

install_systemd_unit() {
  local raw_url="https://raw.githubusercontent.com/${REPO}/main/systemd/${SERVICE_NAME}"
  log "Скачиваю systemd unit ${raw_url}"
  fetch "$raw_url" "$SERVICE_PATH"
  chmod 0644 "$SERVICE_PATH"
}

service_exists() {
  systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -Fxq "$SERVICE_NAME"
}

service_active() {
  systemctl is-active --quiet "$SERVICE_NAME"
}

restart_service() {
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null

  if service_active; then
    log "Перезапускаю ${SERVICE_NAME}"
    systemctl restart "$SERVICE_NAME"
  else
    log "Запускаю ${SERVICE_NAME}"
    systemctl restart "$SERVICE_NAME"
  fi
}

show_summary() {
  echo
  echo "Готово."
  echo "Binary : ${INSTALL_BIN_PATH}"
  echo "Service: ${SERVICE_PATH}"
  echo "Config : ${CONFIG_PATH}"
  echo
  echo "Проверка:"
  echo "  systemctl status ${SERVICE_NAME} --no-pager"
  echo "  journalctl -u ${SERVICE_NAME} -e --no-pager"
}

main() {
  need_root
  require_tools
  detect_arch

  log "Архитектура: ${TARGET_TRIPLE}"
  log "Получаю latest release для ${REPO}"

  local release_json
  release_json="$(github_api_latest_release)"

  local tag
  tag="$(printf '%s\n' "$release_json" | extract_release_tag)"
  [[ -n "$tag" ]] || die "Не удалось определить tag latest release"

  local asset_url
  asset_url="$(printf '%s\n' "$release_json" | extract_asset_url "$TARGET_TRIPLE")"
  [[ -n "$asset_url" ]] || die "Не найден asset для ${TARGET_TRIPLE} в релизе ${tag}"

  log "Latest release: ${tag}"
  log "Asset: ${asset_url}"

  local archive="${TMP_DIR}/${BINARY_NAME}.tar.gz"
  fetch "$asset_url" "$archive"

  if [[ -f "$INSTALL_BIN_PATH" ]]; then
    local backup="${INSTALL_BIN_PATH}.bak.$(date +%Y%m%d%H%M%S)"
    log "Делаю backup старого бинаря: ${backup}"
    cp -a "$INSTALL_BIN_PATH" "$backup"
  fi

  log "Устанавливаю бинарь в ${INSTALL_BIN_PATH}"
  extract_raw_binary "$archive" "$INSTALL_BIN_PATH"

  ensure_user_group
  install_dirs
  install_config_if_missing
  install_systemd_unit
  restart_service
  show_summary
}

main "$@"
