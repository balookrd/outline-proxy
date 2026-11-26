#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

NET="${OUTLINE_STAND_NET:-outline-stand-net}"
RUNTIME_IMAGE="${OUTLINE_STAND_BASE_IMAGE:-alpine:3.21}"
SOCKS_BIND_PORT="${OUTLINE_STAND_SOCKS_PORT:-}"

arch_target() {
  case "$(uname -m)" in
    arm64|aarch64) echo "aarch64-unknown-linux-musl" ;;
    x86_64|amd64)  echo "x86_64-unknown-linux-musl" ;;
    *)
      echo "Unsupported host architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

TARGET="$(arch_target)"
NEW_SRV_BIN="${REPO_DIR}/target/${TARGET}/release/outline-server"
NEW_CLI_BIN="${REPO_DIR}/target/${TARGET}/release/outline-client"

ensure_network() {
  if ! docker network inspect "$NET" >/dev/null 2>&1; then
    docker network create "$NET" >/dev/null
  fi
}

ensure_echo() {
  if ! docker inspect outline-stand-echo >/dev/null 2>&1; then
    docker run -d --name outline-stand-echo --network "$NET" --network-alias echo \
      -v "$SCRIPT_DIR/echo.py:/echo.py:ro" \
      "$RUNTIME_IMAGE" sh -c "apk add --no-cache python3 >/dev/null && python3 /echo.py" >/dev/null
    for _ in $(seq 1 30); do
      if docker exec outline-stand-echo python3 --version >/dev/null 2>&1; then
        return 0
      fi
      sleep 1
    done
    echo "Timed out waiting for python3 in outline-stand-echo" >&2
    exit 1
  fi
}

build_bins() {
  echo "Building release musl binaries for ${TARGET}..."
  if [ "$TARGET" = "aarch64-unknown-linux-musl" ]; then
    (cd "$REPO_DIR" && cargo server-release-musl-aarch64 && cargo client-release-musl-aarch64)
  else
    (cd "$REPO_DIR" && cargo server-release-musl-x86_64 && cargo client-release-musl-x86_64)
  fi
}

stand_down() {
  docker rm -f outline-stand-cli outline-stand-srv outline-stand-echo >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}

start_pair() {
  local mode="${1:-ss-ws}"
  local old_srv="${2:-}"
  local old_cli="${3:-}"
  local client_cfg="$SCRIPT_DIR/configs/client-${mode}.toml"

  if [ ! -f "$client_cfg" ]; then
    echo "Unknown mode '$mode' (expected ss-ws or vless-xhttp)" >&2
    exit 1
  fi

  docker rm -f outline-stand-cli outline-stand-srv >/dev/null 2>&1 || true
  ensure_network
  ensure_echo

  if [ -n "$old_srv" ]; then
    docker run -d --name outline-stand-srv --network "$NET" --network-alias srv \
      -v "$SCRIPT_DIR/configs/server.toml:/etc/outline/server.toml:ro" \
      "$old_srv" --config /etc/outline/server.toml >/dev/null
  else
    [ -x "$NEW_SRV_BIN" ] || { echo "Missing $NEW_SRV_BIN (run '$0 build' first)" >&2; exit 1; }
    docker run -d --name outline-stand-srv --network "$NET" --network-alias srv \
      -v "$NEW_SRV_BIN:/outline-server:ro" \
      -v "$SCRIPT_DIR/configs/server.toml:/etc/outline/server.toml:ro" \
      "$RUNTIME_IMAGE" /outline-server --config /etc/outline/server.toml >/dev/null
  fi

  local port_args=()
  if [ -n "$SOCKS_BIND_PORT" ]; then
    port_args=(-p "127.0.0.1:${SOCKS_BIND_PORT}:1080")
  fi

  if [ -n "$old_cli" ]; then
    docker run -d --name outline-stand-cli --network "$NET" --network-alias cli ${port_args[@]+"${port_args[@]}"} \
      -v "$client_cfg:/etc/outline/client.toml:ro" \
      "$old_cli" --config /etc/outline/client.toml >/dev/null
  else
    [ -x "$NEW_CLI_BIN" ] || { echo "Missing $NEW_CLI_BIN (run '$0 build' first)" >&2; exit 1; }
    docker run -d --name outline-stand-cli --network "$NET" --network-alias cli ${port_args[@]+"${port_args[@]}"} \
      -v "$NEW_CLI_BIN:/outline-client:ro" \
      -v "$client_cfg:/etc/outline/client.toml:ro" \
      "$RUNTIME_IMAGE" /outline-client --config /etc/outline/client.toml >/dev/null
  fi

  sleep 2
}

run_smoke() {
  local label="${1:-stand}"
  if ! docker exec -i outline-stand-echo python3 - "$label" < "$SCRIPT_DIR/smoke.py"; then
    echo "--- SERVER LOGS ($label) ---" >&2
    docker logs outline-stand-srv >&2 || true
    echo "--- CLIENT LOGS ($label) ---" >&2
    docker logs outline-stand-cli >&2 || true
    return 1
  fi
}

cmd_up() {
  local mode="ss-ws" old_srv="" old_cli=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --mode) mode="$2"; shift 2 ;;
      --old-server) old_srv="$2"; shift 2 ;;
      --old-client) old_cli="$2"; shift 2 ;;
      *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
  done
  start_pair "$mode" "$old_srv" "$old_cli"
  echo "Docker stand is up (mode=$mode). SOCKS5 inside net: cli:1080"
}

cmd_test() {
  local skip_build=0
  local old_srv="${OLD_SERVER_IMAGE:-}"
  local old_cli="${OLD_CLIENT_IMAGE:-}"
  while [ $# -gt 0 ]; do
    case "$1" in
      --skip-build) skip_build=1; shift ;;
      --old-server) old_srv="$2"; shift 2 ;;
      --old-client) old_cli="$2"; shift 2 ;;
      *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
  done

  if [ "$skip_build" -eq 0 ]; then
    build_bins
  fi

  trap stand_down EXIT

  start_pair "ss-ws" "" ""
  run_smoke "new-new-ss-ws"

  start_pair "vless-xhttp" "" ""
  run_smoke "new-new-vless-xhttp"

  if [ -n "$old_srv" ]; then
    start_pair "ss-ws" "$old_srv" ""
    run_smoke "old-srv-new-cli-ss-ws"
  fi
  if [ -n "$old_cli" ]; then
    start_pair "ss-ws" "" "$old_cli"
    run_smoke "new-srv-old-cli-ss-ws"
  fi

  echo "ALL DOCKER STAND SMOKE TESTS PASSED"
}

cmd_logs() {
  echo "=== outline-stand-srv ==="
  docker logs outline-stand-srv 2>&1 || true
  echo "=== outline-stand-cli ==="
  docker logs outline-stand-cli 2>&1 || true
}

usage() {
  cat <<EOF
Usage: $0 <command> [options]

Commands:
  build                                 Build release musl binaries for ${TARGET}
  up [--mode ss-ws|vless-xhttp]         Start echo + server + client in Docker
     [--old-server IMG] [--old-client IMG]
  smoke [LABEL]                         Run TCP + UDP + metrics smoke test against running stand
  test [--skip-build]                   Build, run ss-ws & vless-xhttp smoke tests (and optional compat matrix), then clean up
       [--old-server IMG] [--old-client IMG]
  logs                                  Print server & client logs
  down                                  Stop and remove stand containers & network
EOF
}

case "${1:-}" in
  build) shift; build_bins ;;
  up)    shift; cmd_up "$@" ;;
  smoke) shift; run_smoke "${1:-manual}" ;;
  test)  shift; cmd_test "$@" ;;
  logs)  shift; cmd_logs ;;
  down)  shift; stand_down ;;
  *)     usage; exit 1 ;;
esac
