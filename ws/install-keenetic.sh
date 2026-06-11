#!/bin/sh
set -eu

REPO="balookrd/outline-ws-rust"
APP_NAME="outline-ws-rust"
CHANNEL="${CHANNEL:-stable}"
VERSION="${VERSION:-}"

INSTALL_DIR="/opt/bin"
BIN_PATH="${INSTALL_DIR}/${APP_NAME}"

CONFIG_DIR="/opt/etc/outline"
CONFIG_FILE="${CONFIG_DIR}/config.toml"

INIT_SCRIPT="/opt/etc/init.d/S99${APP_NAME}"
VERSION_FILE="${CONFIG_DIR}/installed-release.txt"

TMP_DIR="/opt/tmp/${APP_NAME}.$$"
RELEASES_URL="https://api.github.com/repos/${REPO}/releases?per_page=100"

PATH="/opt/bin:/opt/sbin:/usr/sbin:/usr/bin:/sbin:/bin"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

log() { echo "[${APP_NAME}] $*"; }
die() { echo "[${APP_NAME}] ERROR: $*" >&2; exit 1; }

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT INT TERM

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing: $1"
}

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsL "$1" -o "$2"
    else
        wget -qO "$2" "$1"
    fi
}

detect_arch() {
    case "$(uname -m)" in
        aarch64|arm64) echo "aarch64" ;;
        x86_64|amd64) echo "x86_64" ;;
        armv7l|armv7) echo "armv7" ;;
        armv6l|armv6) echo "armv6" ;;
        mips) echo "mips" ;;
        mipsel) echo "mipsel" ;;
        *) die "unsupported arch: $(uname -m)" ;;
    esac
}

get_patterns() {
    case "$1" in
        aarch64)
            printf '%s\n' \
                "aarch64-unknown-linux-musl" \
                "aarch64-linux-musl"
            ;;
        x86_64)
            printf '%s\n' \
                "x86_64-unknown-linux-musl" \
                "x86_64-linux-musl"
            ;;
        armv7)
            printf '%s\n' \
                "armv7-unknown-linux-musleabihf" \
                "armv7-linux-musleabihf" \
                "arm-unknown-linux-musleabihf"
            ;;
        armv6)
            printf '%s\n' \
                "arm-unknown-linux-musleabi" \
                "arm-linux-musleabi"
            ;;
        mips)
            printf '%s\n' \
                "mips-unknown-linux-musl" \
                "mips-linux-musl"
            ;;
        mipsel)
            printf '%s\n' \
                "mipsel-unknown-linux-musl" \
                "mipsel-linux-musl"
            ;;
    esac
}

find_binary() {
    for f in "$1"/* "$1"/*/*; do
        [ -f "$f" ] || continue
        case "$(basename "$f")" in
            ${APP_NAME}|${APP_NAME}-*)
                echo "$f"
                return 0
                ;;
        esac
    done
    return 1
}

install_binary() {
    mkdir -p "$INSTALL_DIR"
    cp "$1" "$BIN_PATH"
    chmod 0755 "$BIN_PATH"
}

install_config() {
    mkdir -p "$CONFIG_DIR"

    if [ -f "$CONFIG_FILE" ]; then
        log "keeping existing config: $CONFIG_FILE"
        return 0
    fi

    if [ -f "$SCRIPT_DIR/config.toml" ]; then
        log "using config from script dir"
        cp "$SCRIPT_DIR/config.toml" "$CONFIG_FILE"
    elif [ -f "./config.toml" ]; then
        log "using ./config.toml"
        cp "./config.toml" "$CONFIG_FILE"
    else
        log "creating default config"
        cat > "$CONFIG_FILE" <<'EOF'
# fill config
EOF
    fi

    chmod 0644 "$CONFIG_FILE"
}

write_init() {
    mkdir -p "$(dirname "$INIT_SCRIPT")"

    cat > "$INIT_SCRIPT" <<'EOF'
#!/bin/sh

ENABLED=yes
PROCS=outline-ws-rust
ARGS="--config /opt/etc/outline/config.toml"
PREARGS=""
DESC="outline-ws-rust"

PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin

. /opt/etc/init.d/rc.func
EOF

    chmod +x "$INIT_SCRIPT"
}

select_release_tag() {
    json="$1"

    if [ -n "$VERSION" ]; then
        case "$CHANNEL:$VERSION" in
            stable:v[0-9]*.[0-9]*.[0-9]*|stable:[0-9]*.[0-9]*.[0-9]*)
                case "$VERSION" in
                    v*) echo "$VERSION" ;;
                    *) echo "v$VERSION" ;;
                esac
                ;;
            nightly:nightly)
                echo "nightly"
                ;;
            stable:*)
                die "for CHANNEL=stable, VERSION must be 1.2.3 or v1.2.3"
                ;;
            nightly:*)
                die "for CHANNEL=nightly, VERSION must be nightly"
                ;;
            *)
                die "unsupported CHANNEL=$CHANNEL"
                ;;
        esac
        return 0
    fi

    case "$CHANNEL" in
        stable)
            jq -r '
                map(select(.draft == false and .prerelease == false))
                | map(select(
                    .tag_name
                    | startswith("v")
                    and ((.[1:] | split(".")) as $parts
                        | ($parts | length) == 3
                        and all($parts[]; (tonumber?) != null))
                ))
                | .[0].tag_name // empty
            ' "$json"
            ;;
        nightly)
            jq -r '
                map(select(.draft == false and .prerelease == true and .tag_name == "nightly"))
                | .[0].tag_name // empty
            ' "$json"
            ;;
        *)
            die "unsupported CHANNEL=$CHANNEL"
            ;;
    esac
}

main() {
    need_cmd jq
    need_cmd tar
    need_cmd uname
    need_cmd cp
    need_cmd rm
    need_cmd mkdir
    need_cmd chmod

    mkdir -p "$TMP_DIR"

    json="$TMP_DIR/releases.json"
    patterns_file="$TMP_DIR/patterns.txt"
    archive_file="$TMP_DIR/asset.tar.gz"

    fetch "$RELEASES_URL" "$json"

    tag="$(select_release_tag "$json")"
    [ -n "$tag" ] || die "no matching $CHANNEL release found"

    arch="$(detect_arch)"
    get_patterns "$arch" > "$patterns_file"

    url=""
    while IFS= read -r pat; do
        [ -n "$pat" ] || continue

        candidate="$(jq -r --arg t "$tag" --arg p "$pat" '
            (map(select(.tag_name == $t))[0].assets // [])
            | map(select(
                (.name | endswith(".tar.gz"))
                and (.name | contains($p))
                and (.name | startswith("outline-ws-rust-router-v"))
            ))
            | .[0].browser_download_url // empty
        ' "$json")"

        if [ -n "$candidate" ]; then
            url="$candidate"
            break
        fi
    done < "$patterns_file"

    [ -n "$url" ] || die "no matching router musl asset found for arch=$arch in release $tag"

    installed_tag=""
    if [ -f "$VERSION_FILE" ]; then
        installed_tag="$(cat "$VERSION_FILE" 2>/dev/null || true)"
    fi

    if [ "$installed_tag" = "$tag" ] && [ -x "$BIN_PATH" ]; then
        log "already up to date: $installed_tag"
        write_init
        install_config
        exit 0
    fi

    log "selected release: $tag"
    log "downloading asset"
    fetch "$url" "$archive_file"

    log "extracting archive"
    tar -xzf "$archive_file" -C "$TMP_DIR"

    bin="$(find_binary "$TMP_DIR" || true)"
    [ -n "$bin" ] || die "binary ${APP_NAME}* not found inside archive"

    log "installing binary to $BIN_PATH"
    install_binary "$bin"

    write_init
    install_config

    mkdir -p "$CONFIG_DIR"
    printf '%s\n' "$tag" > "$VERSION_FILE"
    chmod 0644 "$VERSION_FILE"

    log "done"
    log "installed version: $tag"
    log "binary: $BIN_PATH"
    log "init script: $INIT_SCRIPT"
    log "config: $CONFIG_FILE"
}

main "$@"
