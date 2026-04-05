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
    armv7l|armv7|armhf)
      TARGET_TRIPLE="armv7-unknown-linux-musleabihf"
      ;;
    *)
      die "Неподдерживаемая архитектура: $arch"
      ;;
  esac
}

resolve_latest_tag() {
  local url final_url
  url="https://github.com/${REPO}/releases/latest"

  if have_cmd curl; then
    final_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "$url")"
  elif have_cmd wget; then
    final_url="$(wget -qSO- "$url" 2>&1 | awk '/^  Location: /{print $2}' | tail -n1 | tr -d '\r')"
  else
    die "Нужен curl или wget"
  fi

  LATEST_TAG="${final_url##*/}"
  [[ -n "${LATEST_TAG}" && "${LATEST_TAG}" != "latest" ]] || die "Не удалось определить latest release tag"
}

release_asset_url() {
  local tag="$1"
  local triple="$2"
  printf 'https://github.com/%s/releases/download/%s/%s-%s-%s.tar.gz' \
    "$REPO" "$tag" "$BINARY_NAME" "$tag" "$triple"
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
    if [[ "$(basename "$f")" == "$BINARY_NAME" ]] && [[ -f "$f" ]]; then
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
  cfg_url="$(tag_raw_url "$LATEST_TAG" "config.toml")"

  log "Скачиваю пример конфига ${cfg_url}"
  fetch "$cfg_url" "$CONFIG_PATH"
  chmod 0640 "$CONFIG_PATH"
  chown root:"$SERVICE_GROUP" "$CONFIG_PATH"
}

install_systemd_unit() {
  local unit_url tmp_unit
  unit_url="$(tag_raw_url "$LATEST_TAG" "systemd/${SERVICE_NAME}")"
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
  local asset_url archive tmp_bin backup_path=""
  asset_url="$(release_asset_url "$LATEST_TAG" "$TARGET_TRIPLE")"
  archive="${TMP_DIR}/${BINARY_NAME}.tar.gz"
  tmp_bin="${TMP_DIR}/${BINARY_NAME}.new"

  log "Скачиваю архив ${asset_url}"
  fetch "$asset_url" "$archive"

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

reload_and_restart_service() {
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null

  if systemctl is-active --quiet "$SERVICE_NAME"; then
    log "Перезапускаю ${SERVICE_NAME}"
    systemctl try-restart "$SERVICE_NAME"
  else
    log "Запускаю ${SERVICE_NAME}"
    systemctl start "$SERVICE_NAME"
  fi
}

show_summary() {
  echo
  echo "Готово."
  echo "Release: ${LATEST_TAG}"
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
  resolve_latest_tag

  log "Архитектура: ${TARGET_TRIPLE}"
  log "Latest release: ${LATEST_TAG}"

  ensure_user_group
  install_dirs
  install_binary
  install_config_if_missing
  install_systemd_unit
  reload_and_restart_service
  show_summary
}

main "$@"
