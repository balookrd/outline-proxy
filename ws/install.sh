#!/usr/bin/env bash
set -Eeuo pipefail

REPO_OWNER="${REPO_OWNER:-balookrd}"
REPO_NAME="${REPO_NAME:-outline-ws-rust}"
REPO_REF="${REPO_REF:-main}"

BINARY_NAME="${BINARY_NAME:-outline-ws-rust}"
INSTALL_PATH="${INSTALL_PATH:-/usr/local/bin/${BINARY_NAME}}"

SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
CONFIG_DIR="${CONFIG_DIR:-/etc/outline-ws-rust}"
STATE_DIR="${STATE_DIR:-/var/lib/outline-ws-rust}"
TMP_DIR="${TMP_DIR:-/tmp/${BINARY_NAME}-install}"

CHANNEL="${CHANNEL:-stable}"   # stable | nightly
VERSION="${VERSION:-}"         # stable: 1.0.0 or v1.0.0 ; nightly: exact tag nightly-v1.0.0-deadbeef1234
GITHUB_API="${GITHUB_API:-https://api.github.com}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

# Откуда качать unit-файлы
RAW_BASE="${RAW_BASE:-https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_REF}}"
RAW_SERVICE_URL="${RAW_SERVICE_URL:-${RAW_BASE}/systemd/outline-ws-rust.service}"
RAW_TEMPLATE_URL="${RAW_TEMPLATE_URL:-${RAW_BASE}/systemd/outline-ws-rust@.service}"

# Откуда качать config-файлы
RAW_CONFIG_URL="${RAW_CONFIG_URL:-${RAW_BASE}/config.toml}"
RAW_INSTANCE_CONFIG_URL="${RAW_INSTANCE_CONFIG_URL:-${RAW_BASE}/config.toml}"

SERVICE_NAME="outline-ws-rust.service"
TEMPLATE_NAME="outline-ws-rust@.service"

log() {
  printf '[%s] %s\n' "$(date '+%F %T')" "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Не найдена команда: $1"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Запусти скрипт от root: sudo ./install.sh"
  fi
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

map_arch_to_target() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)
      echo "x86_64-unknown-linux-musl"
      ;;
    aarch64|arm64)
      echo "aarch64-unknown-linux-musl"
      ;;
    *)
      die "Неподдерживаемая архитектура: ${arch}. Нужны x86_64/amd64 или aarch64/arm64."
      ;;
  esac
}

normalize_version_tag() {
  local v="$1"

  if [[ "$CHANNEL" == "stable" ]]; then
    if [[ -z "$v" ]]; then
      echo ""
    elif [[ "$v" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "$v"
    elif [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "v${v}"
    else
      die "Для CHANNEL=stable VERSION должен быть вида 1.2.3 или v1.2.3"
    fi
  else
    if [[ -z "$v" ]]; then
      echo ""
    elif [[ "$v" =~ ^nightly-v[0-9]+\.[0-9]+\.[0-9]+-[0-9a-f]{12}$ ]]; then
      echo "$v"
    else
      die "Для CHANNEL=nightly VERSION должен быть точным тегом вида nightly-v1.2.3-abcdef123456"
    fi
  fi
}

select_release_json() {
  local tag

  if [[ -n "$VERSION" ]]; then
    tag="$(normalize_version_tag "$VERSION")"
    github_api_get "${GITHUB_API}/repos/${REPO_OWNER}/${REPO_NAME}/releases/tags/${tag}"
    return 0
  fi

  github_api_get "${GITHUB_API}/repos/${REPO_OWNER}/${REPO_NAME}/releases?per_page=100" | \
    python3 - "$CHANNEL" <<'PY'
import json, re, sys
channel = sys.argv[1]
releases = json.load(sys.stdin)

def is_stable_server_release(rel):
    tag = rel.get("tag_name", "")
    return (
        not rel.get("draft", False)
        and not rel.get("prerelease", False)
        and re.fullmatch(r"v\d+\.\d+\.\d+", tag) is not None
    )

def is_nightly_server_release(rel):
    tag = rel.get("tag_name", "")
    return (
        not rel.get("draft", False)
        and rel.get("prerelease", False)
        and re.fullmatch(r"nightly-v\d+\.\d+\.\d+-[0-9a-f]{12}", tag) is not None
    )

filtered = [r for r in releases if is_stable_server_release(r)] if channel == "stable" \
           else [r for r in releases if is_nightly_server_release(r)]

if not filtered:
    raise SystemExit("Не удалось найти подходящий release")

print(json.dumps(filtered[0]))
PY
}

release_field() {
  local field="$1"
  python3 - "$field" <<'PY'
import json, sys
field = sys.argv[1]
data = json.load(sys.stdin)
print(data.get(field, ""))
PY
}

asset_url_from_release() {
  local target="$1"
  python3 - "$target" <<'PY'
import json, re, sys
target = sys.argv[1]
rel = json.load(sys.stdin)

assets = rel.get("assets", [])
patterns = [
    rf"^outline-ws-rust-v\d+\.\d+\.\d+-{re.escape(target)}\.tar\.gz$",
]

for asset in assets:
    name = asset.get("name", "")
    if any(re.fullmatch(p, name) for p in patterns):
        print(asset["browser_download_url"])
        raise SystemExit(0)

raise SystemExit(f"Не найден asset под target={target}")
PY
}

install_binary() {
  local archive="$1"
  local workdir="$2"

  rm -rf "$workdir"
  mkdir -p "$workdir"
  tar -xzf "$archive" -C "$workdir"

  local extracted=""
  extracted="$(find "$workdir" -maxdepth 2 -type f \( -name "${BINARY_NAME}" -o -name "${BINARY_NAME}-*" \) | head -n1 || true)"
  [[ -n "$extracted" ]] || die "Не найден бинарник ${BINARY_NAME} после распаковки"

  chmod +x "$extracted"
  mkdir -p "$(dirname "$INSTALL_PATH")"

  if [[ -f "$INSTALL_PATH" ]]; then
    cp -f "$INSTALL_PATH" "${INSTALL_PATH}.bak"
  fi

  install -m 0755 "$extracted" "$INSTALL_PATH"
}

download_unit_files() {
  local svc_tmp="$1"
  local tpl_tmp="$2"

  log "Скачивание unit-файлов из репозитория"
  curl -fsSL -o "$svc_tmp" "$RAW_SERVICE_URL"
  curl -fsSL -o "$tpl_tmp" "$RAW_TEMPLATE_URL"
}

install_unit_files() {
  local svc_tmp="$1"
  local tpl_tmp="$2"

  install -m 0644 "$svc_tmp" "${SYSTEMD_DIR}/${SERVICE_NAME}"
  install -m 0644 "$tpl_tmp" "${SYSTEMD_DIR}/${TEMPLATE_NAME}"
}

download_default_config_if_missing() {
  if [[ ! -f "${CONFIG_DIR}/config.toml" ]]; then
    log "Скачивание default config"
    curl -fsSL -o "${CONFIG_DIR}/config.toml" "$RAW_CONFIG_URL"
    chmod 600 "${CONFIG_DIR}/config.toml"
  else
    log "config.toml уже существует — не перезаписываем"
  fi
}

download_instance_example_if_missing() {
  mkdir -p "${CONFIG_DIR}/instances"

  if [[ ! -f "${CONFIG_DIR}/instances/example.toml" ]]; then
    log "Скачивание example instance config"
    curl -fsSL -o "${CONFIG_DIR}/instances/example.toml" "$RAW_INSTANCE_CONFIG_URL"
    chmod 600 "${CONFIG_DIR}/instances/example.toml"
  else
    log "instance example уже существует — не перезаписываем"
  fi
}

collect_active_units() {
  systemctl list-units --type=service --state=active --no-legend --no-pager \
    | awk '{print $1}' \
    | grep -E '^outline-ws-rust(\.service|@.+\.service)$' || true
}

restart_previously_active_units() {
  local had=0
  local unit

  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    had=1
    log "Перезапуск ${unit}"
    systemctl restart "$unit"
  done < <(collect_active_units)

  if [[ "$had" -eq 0 ]]; then
    log "Активных outline-ws-rust unit'ов не найдено"
  fi
}

main() {
  require_root
  need_cmd curl
  need_cmd tar
  need_cmd python3
  need_cmd install
  need_cmd systemctl
  need_cmd sed
  need_cmd uname

  local target release_json release_tag release_name asset_url archive_path workdir
  local svc_tmp tpl_tmp
  target="$(map_arch_to_target)"
  archive_path="${TMP_DIR}/${BINARY_NAME}.tar.gz"
  workdir="${TMP_DIR}/work"
  svc_tmp="${TMP_DIR}/${SERVICE_NAME}"
  tpl_tmp="${TMP_DIR}/${TEMPLATE_NAME}"

  mkdir -p "$TMP_DIR" "$CONFIG_DIR" "${CONFIG_DIR}/instances" "$STATE_DIR"

  log "Архитектура: $(uname -m)"
  log "Target: ${target}"
  log "Канал: ${CHANNEL}"

  release_json="$(select_release_json)"
  release_tag="$(printf '%s' "$release_json" | release_field tag_name)"
  release_name="$(printf '%s' "$release_json" | release_field name)"
  asset_url="$(printf '%s' "$release_json" | asset_url_from_release "$target")"

  log "Релиз: ${release_tag}${release_name:+ (${release_name})}"
  log "Скачивание бинарника: ${asset_url}"

  curl -fL --retry 3 --retry-delay 2 -o "$archive_path" "$asset_url"
  install_binary "$archive_path" "$workdir"
  log "Бинарник установлен: ${INSTALL_PATH}"

  download_unit_files "$svc_tmp" "$tpl_tmp"
  install_unit_files "$svc_tmp" "$tpl_tmp"

  download_default_config_if_missing
  download_instance_example_if_missing

  systemctl daemon-reload
  systemctl enable outline-ws-rust.service >/dev/null 2>&1 || true

  restart_previously_active_units

  log "Готово"
  log "Обычный unit:   ${SYSTEMD_DIR}/${SERVICE_NAME}"
  log "Шаблонный unit: ${SYSTEMD_DIR}/${TEMPLATE_NAME}"
  log "Обычный конфиг: ${CONFIG_DIR}/config.toml"
  log "Инстансы:       ${CONFIG_DIR}/instances/NAME.toml"
  log "Запуск инстанса: systemctl enable --now outline-ws-rust@NAME.service"
}

main "$@"
