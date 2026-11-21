#!/usr/bin/env bash
#
# migrate-node-rename.sh — чистый перевод одного узла парка с
# outline-ss-rust / outline-ws-rust на outline-server / outline-client
# без создания симлинков, с полным снимком состояния и автооткатом.
#
# Использование:
#   ops/deploy/migrate-node-rename.sh <host> <server|client|all> [--audit | --dry-run]
#
# По умолчанию бинари берутся из:
#   target/<arch>-unknown-linux-musl/release/outline-server
#   target/<arch>-unknown-linux-musl/release/outline-client
# (можно переопределить через SERVER_BIN=... и CLIENT_BIN=...).

set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*"; }

usage() {
	cat <<EOF
usage: $0 <host> <server|client|all> [--audit | --dry-run]

Roles:
  server     migrate outline-ss-rust -> outline-server
  client     migrate outline-ws-rust -> outline-client
  all        migrate both server and client on the host

Options:
  --audit    read-only host inspection (units, users, paths, cron, /opt/network)
  --dry-run  validate local binaries/arch/checksums and print planned actions
  -h, --help show this help and exit
EOF
}

for arg in "$@"; do
	case "$arg" in
		-h|--help)
			usage
			exit 0
			;;
	esac
done

[ $# -ge 2 ] || die "usage: $0 <host> <server|client|all> [--audit | --dry-run]"
HOST="$1"
ROLE="$2"
shift 2

MODE="apply"
while [ $# -gt 0 ]; do
	case "$1" in
		--audit)
			[ "$MODE" = "apply" ] || [ "$MODE" = "audit" ] || die "cannot combine --audit and --dry-run"
			MODE="audit"
			;;
		--dry-run)
			[ "$MODE" = "apply" ] || [ "$MODE" = "dry-run" ] || die "cannot combine --audit and --dry-run"
			MODE="dry-run"
			;;
		*)
			die "unknown option '$1' (expected --audit or --dry-run)"
			;;
	esac
	shift
done

DO_SERVER=0
DO_CLIENT=0
case "$ROLE" in
	server) DO_SERVER=1 ;;
	client) DO_CLIENT=1 ;;
	all)    DO_SERVER=1; DO_CLIENT=1 ;;
	*) die "unknown role '$ROLE' (expected server, client, or all)" ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

sha256_local() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

elf_arch() {
	case "$(file -b "$1")" in
		*x86-64*)  echo "x86_64" ;;
		*aarch64*) echo "aarch64" ;;
		*) die "cannot tell architecture of $1 — expected Linux ELF binary" ;;
	esac
}

# Единое SSH-соединение через ControlMaster защищает от блокировки sshguard.
CTRL_DIR="$(mktemp -d)"
CTRL_SOCK="$CTRL_DIR/ssh.sock"
SSH_OPTS=(
	-o BatchMode=yes
	-o ConnectTimeout=15
	-o ControlMaster=auto
	-o "ControlPath=$CTRL_SOCK"
	-o ControlPersist=60
)
REMOTE_STAGE=""

cleanup() {
	if [ -n "$REMOTE_STAGE" ]; then
		printf 'rm -rf %q\n' "$REMOTE_STAGE" | ssh "${SSH_OPTS[@]}" "$HOST" 'bash -s' >/dev/null 2>&1 || true
	fi
	ssh -O exit "${SSH_OPTS[@]}" "$HOST" >/dev/null 2>&1 || true
	rm -rf "$CTRL_DIR"
}
trap cleanup EXIT

HOST_ARCH="$(ssh "${SSH_OPTS[@]}" "$HOST" 'uname -m')"
[ -n "$HOST_ARCH" ] || die "failed to detect architecture on $HOST"
log "$HOST: arch=$HOST_ARCH, role=$ROLE, mode=$MODE"

if [ "$MODE" = "audit" ]; then
	ssh "${SSH_OPTS[@]}" "$HOST" 'sudo -n bash -s' <<'AUDIT'
set -euo pipefail
echo "--- systemd units (outline-*) ---"
systemctl list-unit-files 'outline-*' --no-legend --no-pager || true
echo "--- active/failed outline units ---"
systemctl list-units --all --plain 'outline-*' --no-legend --no-pager || true
echo "--- drop-in directories ---"
ls -la /etc/systemd/system/outline-*.service.d 2>/dev/null || echo "(none)"
echo "--- post-up.service ---"
grep -E '^(Before|After|ExecStart)=' /etc/systemd/system/post-up.service 2>/dev/null || echo "(no post-up.service)"
echo "--- outline-ws0-routing.service ---"
if [ -e /etc/systemd/system/outline-ws0-routing.service ]; then
	ls -la /etc/systemd/system/outline-ws0-routing.service
	cat /etc/systemd/system/outline-ws0-routing.service
else
	echo "(none)"
fi
echo "--- users & groups ---"
for u in outline-ss-rust outline-ws outline-server outline-client; do
	id "$u" 2>/dev/null || true
done
getent group outline-ss-rust outline-ws outline-server outline-client certs 2>/dev/null || true
echo "--- /usr/local/bin & /etc & /var/lib & /var/log ---"
ls -ld /usr/local/bin/outline-* /etc/outline-* /var/lib/outline-* /var/log/outline-* 2>/dev/null || echo "(none)"
echo "--- /opt/outline/outline-* ---"
ls -ld /opt/outline/outline-* 2>/dev/null || echo "(none)"
ls -la /opt/outline/outline-* 2>/dev/null || true
echo "--- config.toml path references ---"
grep -nE 'outline-[sw]s-rust|outline-ws\b' \
	/etc/outline-ws-rust/config.toml /etc/outline-ws-rust/instances/*.toml \
	/etc/outline-ss-rust/config.toml \
	/etc/outline-client/config.toml /etc/outline-client/instances/*.toml \
	/etc/outline-server/config.toml 2>/dev/null || echo "(none)"
echo "--- /opt/network/*.sh references ---"
grep -rnE 'outline-[sw]s-rust|outline-ws\b' /opt/network/*.sh 2>/dev/null || echo "(none)"
echo "--- helper scripts (/opt/outline, /opt/ddns, /opt/beerloga, /etc/default/nanopi104-backup) ---"
grep -rnE 'outline-[sw]s-rust|outline-ws\b' \
	/opt/outline/ /opt/ddns/*/permission-certs.sh /opt/beerloga/permission-certs.sh /etc/default/nanopi104-backup \
	2>/dev/null || echo "(none)"
echo "--- cron references (/etc/cron*, root crontab) ---"
grep -rnIE 'outline-[sw]s-rust|outline-ws\b' /etc/cron* /etc/crontab 2>/dev/null || echo "(none)"
(crontab -l 2>/dev/null | grep -nE 'outline-[sw]s-rust|outline-ws\b') || echo "(no root crontab hits)"
AUDIT
	exit 0
fi

MUSL_TARGET="${HOST_ARCH}-unknown-linux-musl"
SERVER_BIN="${SERVER_BIN:-$REPO_ROOT/target/$MUSL_TARGET/release/outline-server}"
CLIENT_BIN="${CLIENT_BIN:-$REPO_ROOT/target/$MUSL_TARGET/release/outline-client}"

WATCHDOG_BIN="$REPO_ROOT/ops/watchdog/outline-watchdog"
[ -f "$WATCHDOG_BIN" ] || die "missing $WATCHDOG_BIN"

SERVER_UNIT_FILE="$REPO_ROOT/bins/outline-server/systemd/outline-server.service"
CLIENT_UNIT_FILE="$REPO_ROOT/bins/outline-client/systemd/outline-client.service"
CLIENT_TPL_FILE="$REPO_ROOT/bins/outline-client/systemd/outline-client@.service"

STAGE_LOCAL="$CTRL_DIR/stage"
mkdir -p "$STAGE_LOCAL"
cp "$WATCHDOG_BIN" "$STAGE_LOCAL/outline-watchdog"

SERVER_SUM=""
CLIENT_SUM=""
if [ "$DO_SERVER" = 1 ]; then
	[ -f "$SERVER_BIN" ] || die "missing server binary: $SERVER_BIN (build with: cargo server-release-musl-$HOST_ARCH)"
	[ "$(elf_arch "$SERVER_BIN")" = "$HOST_ARCH" ] || die "server binary arch mismatch"
	[ -f "$SERVER_UNIT_FILE" ] || die "missing $SERVER_UNIT_FILE"
	SERVER_SUM="$(sha256_local "$SERVER_BIN")"
	cp "$SERVER_BIN" "$STAGE_LOCAL/outline-server"
	cp "$SERVER_UNIT_FILE" "$STAGE_LOCAL/outline-server.service"
	log "server bin ready: $(basename "$SERVER_BIN") (${SERVER_SUM:0:12})"
fi

if [ "$DO_CLIENT" = 1 ]; then
	[ -f "$CLIENT_BIN" ] || die "missing client binary: $CLIENT_BIN (build with: cargo client-release-musl-$HOST_ARCH)"
	[ "$(elf_arch "$CLIENT_BIN")" = "$HOST_ARCH" ] || die "client binary arch mismatch"
	[ -f "$CLIENT_UNIT_FILE" ] && [ -f "$CLIENT_TPL_FILE" ] || die "missing client unit files"
	CLIENT_SUM="$(sha256_local "$CLIENT_BIN")"
	cp "$CLIENT_BIN" "$STAGE_LOCAL/outline-client"
	cp "$CLIENT_UNIT_FILE" "$STAGE_LOCAL/outline-client.service"
	cp "$CLIENT_TPL_FILE" "$STAGE_LOCAL/outline-client@.service"
	log "client bin ready: $(basename "$CLIENT_BIN") (${CLIENT_SUM:0:12})"
fi

REMOTE_STAGE="/tmp/outline-rename-stage.$$"
printf 'mkdir -p %q\n' "$REMOTE_STAGE" | ssh "${SSH_OPTS[@]}" "$HOST" 'bash -s'
scp -q "${SSH_OPTS[@]}" "$STAGE_LOCAL/"* "$HOST:$REMOTE_STAGE/"

{
	printf 'MODE=%q DO_SERVER=%q DO_CLIENT=%q SERVER_SUM=%q CLIENT_SUM=%q STAGE=%q\n' \
		"$MODE" "$DO_SERVER" "$DO_CLIENT" "$SERVER_SUM" "$CLIENT_SUM" "$REMOTE_STAGE"
	cat <<'REMOTE'
set -Eeuo pipefail
trap 'rm -rf "$STAGE"' EXIT

TS="$(date +%Y%m%d%H%M%S)"
ROLLBACK="/var/tmp/outline-rename-rollback.$TS"
MIGRATED=0

save_state() {
	mkdir -p "$ROLLBACK"
	chmod 0700 "$ROLLBACK"
	for p in \
		/usr/local/bin/outline-ss-rust \
		/usr/local/bin/outline-ws-rust \
		/usr/local/sbin/outline-watchdog \
		/etc/systemd/system/post-up.service \
		/etc/systemd/system/outline-ws0-routing.service \
		/etc/default/nanopi104-backup; do
		if [ -e "$p" ] || [ -L "$p" ]; then
			mkdir -p "$ROLLBACK$(dirname "$p")"
			cp -a "$p" "$ROLLBACK$p"
		fi
	done
	for d in \
		/etc/outline-ss-rust \
		/etc/outline-ws-rust \
		/etc/systemd/system/outline-ss-rust.service \
		/etc/systemd/system/outline-ss-rust.service.d \
		/etc/systemd/system/outline-ws-rust.service \
		/etc/systemd/system/outline-ws-rust@.service \
		/etc/systemd/system/outline-ws-rust*.service.d \
		/opt/outline/outline-ss-rust \
		/opt/outline/outline-ws-rust \
		/opt/outline/access-keys/generate_keys.py \
		/opt/network \
		/opt/ddns/*/permission-certs.sh \
		/opt/beerloga/permission-certs.sh; do
		if [ -e "$d" ] || [ -L "$d" ]; then
			mkdir -p "$ROLLBACK$(dirname "$d")"
			cp -a "$d" "$ROLLBACK$d"
		fi
	done
	systemctl list-units --all --plain 'outline-*' --no-legend --no-pager > "$ROLLBACK/units.txt" || true
	id outline-ss-rust > "$ROLLBACK/id-server.txt" 2>/dev/null || true
	id outline-ws > "$ROLLBACK/id-client.txt" 2>/dev/null || true
	getent passwd outline-ss-rust > "$ROLLBACK/passwd-server.txt" 2>/dev/null || true
	getent passwd outline-ws > "$ROLLBACK/passwd-client.txt" 2>/dev/null || true
	getent group outline-ss-rust > "$ROLLBACK/group-server.txt" 2>/dev/null || true
	getent group outline-ws > "$ROLLBACK/group-client.txt" 2>/dev/null || true
}

rollback() {
	trap - ERR
	set +e
	echo "ERROR: migration failed — rolling back from $ROLLBACK" >&2

	if [ "$DO_SERVER" = 1 ]; then
		systemctl disable --now outline-watchdog@outline-server.timer 2>/dev/null
		systemctl disable --now outline-server.service 2>/dev/null
		rm -f /usr/local/bin/outline-server /etc/systemd/system/outline-server.service
		rm -rf /etc/systemd/system/outline-server.service.d

		if [ -d /etc/outline-server ] && [ ! -e /etc/outline-ss-rust ]; then
			mv /etc/outline-server /etc/outline-ss-rust
		fi
		if [ -d /var/lib/outline-server ] && [ ! -e /var/lib/outline-ss-rust ]; then
			mv /var/lib/outline-server /var/lib/outline-ss-rust
		fi
		if [ -d /opt/outline/outline-server ] && [ ! -e /opt/outline/outline-ss-rust ]; then
			mv /opt/outline/outline-server /opt/outline/outline-ss-rust
		fi

		if [ -s "$ROLLBACK/group-server.txt" ] && getent group outline-server >/dev/null && ! getent group outline-ss-rust >/dev/null; then
			groupmod -n outline-ss-rust outline-server 2>/dev/null || true
		fi
		if [ -s "$ROLLBACK/passwd-server.txt" ] && getent passwd outline-server >/dev/null && ! getent passwd outline-ss-rust >/dev/null; then
			local orig_home=""
			orig_home="$(cut -d: -f6 "$ROLLBACK/passwd-server.txt" 2>/dev/null || true)"
			orig_home="${orig_home:-/var/lib/outline-ss-rust}"
			usermod -l outline-ss-rust -g outline-ss-rust -d "$orig_home" outline-server 2>/dev/null || true
		fi
		if getent group certs >/dev/null && getent passwd outline-ss-rust >/dev/null; then
			usermod -aG certs outline-ss-rust 2>/dev/null || true
		fi

		if [ -d "$ROLLBACK/etc/outline-ss-rust" ]; then
			mkdir -p /etc/outline-ss-rust
			cp -a "$ROLLBACK/etc/outline-ss-rust/." /etc/outline-ss-rust/
		fi
		if [ -f "$ROLLBACK/usr/local/bin/outline-ss-rust" ]; then
			cp -a "$ROLLBACK/usr/local/bin/outline-ss-rust" /usr/local/bin/outline-ss-rust
		fi
		if [ -f "$ROLLBACK/etc/systemd/system/outline-ss-rust.service" ]; then
			cp -a "$ROLLBACK/etc/systemd/system/outline-ss-rust.service" /etc/systemd/system/outline-ss-rust.service
		fi
		if [ -d "$ROLLBACK/etc/systemd/system/outline-ss-rust.service.d" ]; then
			mkdir -p /etc/systemd/system/outline-ss-rust.service.d
			cp -a "$ROLLBACK/etc/systemd/system/outline-ss-rust.service.d/." /etc/systemd/system/outline-ss-rust.service.d/
		fi
		if [ -d "$ROLLBACK/opt/outline/outline-ss-rust" ]; then
			mkdir -p /opt/outline/outline-ss-rust
			cp -a "$ROLLBACK/opt/outline/outline-ss-rust/." /opt/outline/outline-ss-rust/
		fi
		if [ -f "$ROLLBACK/opt/outline/access-keys/generate_keys.py" ]; then
			cp -a "$ROLLBACK/opt/outline/access-keys/generate_keys.py" /opt/outline/access-keys/generate_keys.py
		fi
		for f in "$ROLLBACK"/opt/ddns/*/permission-certs.sh; do
			if [ -f "$f" ]; then
				local dest="${f#"$ROLLBACK"}"
				mkdir -p "$(dirname "$dest")"
				cp -a "$f" "$dest"
			fi
		done
		if [ -f "$ROLLBACK/opt/beerloga/permission-certs.sh" ]; then
			cp -a "$ROLLBACK/opt/beerloga/permission-certs.sh" /opt/beerloga/permission-certs.sh
		fi
		if getent passwd outline-ss-rust >/dev/null; then
			chown -R outline-ss-rust:outline-ss-rust /etc/outline-ss-rust /var/lib/outline-ss-rust 2>/dev/null || true
		fi
	fi

	if [ "$DO_CLIENT" = 1 ]; then
		systemctl disable --now outline-watchdog@outline-client.timer 2>/dev/null
		while IFS= read -r u; do
			[ -n "$u" ] || continue
			systemctl disable --now "$u" 2>/dev/null
		done < <(systemctl list-units --all --plain --type=service --no-legend --no-pager \
			| awk '{print $1}' | grep -E '^outline-client(\.service|@.+\.service)$' || true)
		rm -f /usr/local/bin/outline-client /etc/systemd/system/outline-client.service /etc/systemd/system/outline-client@.service
		rm -rf /etc/systemd/system/outline-client*.service.d

		if [ -d /etc/outline-client ] && [ ! -e /etc/outline-ws-rust ]; then
			mv /etc/outline-client /etc/outline-ws-rust
		fi
		if [ -d /var/lib/outline-client ] && [ ! -e /var/lib/outline-ws-rust ]; then
			mv /var/lib/outline-client /var/lib/outline-ws-rust
		fi
		if [ -d /var/log/outline-client ] && [ ! -e /var/log/outline-ws-rust ]; then
			mv /var/log/outline-client /var/log/outline-ws-rust
		fi
		if [ -d /opt/outline/outline-client ] && [ ! -e /opt/outline/outline-ws-rust ]; then
			mv /opt/outline/outline-client /opt/outline/outline-ws-rust
		fi

		if [ -s "$ROLLBACK/group-client.txt" ] && getent group outline-client >/dev/null && ! getent group outline-ws >/dev/null; then
			groupmod -n outline-ws outline-client 2>/dev/null || true
		fi
		if [ -s "$ROLLBACK/passwd-client.txt" ] && getent passwd outline-client >/dev/null && ! getent passwd outline-ws >/dev/null; then
			local orig_home=""
			orig_home="$(cut -d: -f6 "$ROLLBACK/passwd-client.txt" 2>/dev/null || true)"
			orig_home="${orig_home:-/var/lib/outline-ws-rust}"
			usermod -l outline-ws -g outline-ws -d "$orig_home" outline-client 2>/dev/null || true
		fi

		if [ -d "$ROLLBACK/etc/outline-ws-rust" ]; then
			mkdir -p /etc/outline-ws-rust
			cp -a "$ROLLBACK/etc/outline-ws-rust/." /etc/outline-ws-rust/
		fi
		if [ -f "$ROLLBACK/usr/local/bin/outline-ws-rust" ]; then
			cp -a "$ROLLBACK/usr/local/bin/outline-ws-rust" /usr/local/bin/outline-ws-rust
		fi
		if [ -f "$ROLLBACK/etc/systemd/system/outline-ws-rust.service" ]; then
			cp -a "$ROLLBACK/etc/systemd/system/outline-ws-rust.service" /etc/systemd/system/outline-ws-rust.service
		fi
		if [ -f "$ROLLBACK/etc/systemd/system/outline-ws-rust@.service" ]; then
			cp -a "$ROLLBACK/etc/systemd/system/outline-ws-rust@.service" /etc/systemd/system/outline-ws-rust@.service
		fi
		for d in "$ROLLBACK"/etc/systemd/system/outline-ws-rust*.service.d; do
			if [ -d "$d" ]; then
				local dest="${d#"$ROLLBACK"}"
				mkdir -p "$dest"
				cp -a "$d/." "$dest/"
			fi
		done
		if [ -d "$ROLLBACK/opt/outline/outline-ws-rust" ]; then
			mkdir -p /opt/outline/outline-ws-rust
			cp -a "$ROLLBACK/opt/outline/outline-ws-rust/." /opt/outline/outline-ws-rust/
		fi
		if [ -f "$ROLLBACK/etc/systemd/system/outline-ws0-routing.service" ] || [ -L "$ROLLBACK/etc/systemd/system/outline-ws0-routing.service" ]; then
			cp -a "$ROLLBACK/etc/systemd/system/outline-ws0-routing.service" /etc/systemd/system/outline-ws0-routing.service
		fi
		if [ -d "$ROLLBACK/opt/network" ]; then
			mkdir -p /opt/network
			cp -a "$ROLLBACK/opt/network/." /opt/network/
		fi
		if [ -f "$ROLLBACK/etc/default/nanopi104-backup" ]; then
			cp -a "$ROLLBACK/etc/default/nanopi104-backup" /etc/default/nanopi104-backup
		fi
		if getent passwd outline-ws >/dev/null; then
			chown -R outline-ws:outline-ws /etc/outline-ws-rust /var/lib/outline-ws-rust /var/log/outline-ws-rust 2>/dev/null || true
		fi
	fi

	if [ -f "$ROLLBACK/usr/local/sbin/outline-watchdog" ]; then
		cp -a "$ROLLBACK/usr/local/sbin/outline-watchdog" /usr/local/sbin/outline-watchdog
	fi
	if [ -f "$ROLLBACK/etc/systemd/system/post-up.service" ]; then
		cp -a "$ROLLBACK/etc/systemd/system/post-up.service" /etc/systemd/system/post-up.service
	fi

	systemctl daemon-reload
	if [ "$DO_SERVER" = 1 ] && [ -f /etc/systemd/system/outline-ss-rust.service ]; then
		systemctl enable --now outline-ss-rust.service outline-watchdog@outline-ss-rust.timer 2>/dev/null
	fi
	if [ "$DO_CLIENT" = 1 ] && [ -f /etc/systemd/system/outline-ws-rust.service ]; then
		systemctl enable --now outline-ws-rust.service outline-watchdog@outline-ws-rust.timer 2>/dev/null
		for inst in "${CLIENT_INSTANCES[@]+"${CLIENT_INSTANCES[@]}"}"; do
			systemctl enable --now "outline-ws-rust@${inst}.service" 2>/dev/null
		done
	fi
	exit 1
}

if [ "$DO_SERVER" = 1 ]; then
	got="$(sha256sum "$STAGE/outline-server" | cut -d' ' -f1)"
	[ "$got" = "$SERVER_SUM" ] || { echo "server sha256 mismatch" >&2; exit 1; }
fi
if [ "$DO_CLIENT" = 1 ]; then
	got="$(sha256sum "$STAGE/outline-client" | cut -d' ' -f1)"
	[ "$got" = "$CLIENT_SUM" ] || { echo "client sha256 mismatch" >&2; exit 1; }
fi

CLIENT_INSTANCES=()
while IFS= read -r u; do
	[ -n "$u" ] || continue
	inst="${u#outline-ws-rust@}"
	inst="${inst#outline-client@}"
	inst="${inst%.service}"
	seen=0
	for existing in "${CLIENT_INSTANCES[@]+"${CLIENT_INSTANCES[@]}"}"; do
		if [ "$existing" = "$inst" ]; then
			seen=1
			break
		fi
	done
	if [ "$seen" = 0 ]; then
		CLIENT_INSTANCES+=("$inst")
	fi
done < <(systemctl list-units --all --plain --type=service --no-legend --no-pager \
	| awk '{print $1}' | grep -E '^outline-(ws-rust|client)@.+\.service$' || true)

if [ "$MODE" = "dry-run" ]; then
	echo "[dry-run] DO_SERVER=$DO_SERVER DO_CLIENT=$DO_CLIENT instances=${CLIENT_INSTANCES[*]:-none}"
	if [ "$DO_SERVER" = 1 ]; then
		echo "[dry-run] would migrate outline-ss-rust -> outline-server (user/group+certs, /etc, /var/lib, /opt/outline/outline-server, drop-in, post-up, save-keys, generate_keys.py, permission-certs, watchdog)"
	fi
	if [ "$DO_CLIENT" = 1 ]; then
		echo "[dry-run] would migrate outline-ws-rust -> outline-client (user/group, /etc, /var/lib, /var/log, /opt/outline/outline-client, drop-in, config paths, outline-ws0-routing.service, /opt/network/*.sh, post-up, backup, watchdog)"
	fi
	exit 0
fi

save_state
trap 'if [ "$MIGRATED" = 1 ]; then rollback; fi' ERR
MIGRATED=1

# 1. Остановка старых таймеров и юнитов
if [ "$DO_SERVER" = 1 ]; then
	systemctl disable --now outline-watchdog@outline-ss-rust.timer 2>/dev/null || true
	systemctl disable --now outline-ss-rust.service 2>/dev/null || true
fi
if [ "$DO_CLIENT" = 1 ]; then
	systemctl disable --now outline-watchdog@outline-ws-rust.timer 2>/dev/null || true
	systemctl disable --now outline-ws-rust.service 2>/dev/null || true
	for inst in "${CLIENT_INSTANCES[@]+"${CLIENT_INSTANCES[@]}"}"; do
		systemctl disable --now "outline-ws-rust@${inst}.service" 2>/dev/null || true
	done
fi

# 2. Миграция пользователей, каталогов и сопутствующих скриптов
if [ "$DO_SERVER" = 1 ]; then
	if getent group outline-ss-rust >/dev/null && ! getent group outline-server >/dev/null; then
		groupmod -n outline-server outline-ss-rust
	elif ! getent group outline-server >/dev/null; then
		groupadd --system outline-server
	fi
	if getent passwd outline-ss-rust >/dev/null && ! getent passwd outline-server >/dev/null; then
		usermod -l outline-server -g outline-server -d /var/lib/outline-server outline-ss-rust
	elif ! getent passwd outline-server >/dev/null; then
		useradd --system --gid outline-server --no-create-home --home-dir /var/lib/outline-server --shell /usr/sbin/nologin outline-server
	fi
	if getent group certs >/dev/null; then
		usermod -aG certs outline-server
	fi

	if [ -d /etc/outline-ss-rust ] && [ ! -e /etc/outline-server ]; then
		mv /etc/outline-ss-rust /etc/outline-server
	fi
	if [ -d /var/lib/outline-ss-rust ] && [ ! -e /var/lib/outline-server ]; then
		mv /var/lib/outline-ss-rust /var/lib/outline-server
	fi
	mkdir -p /etc/outline-server /var/lib/outline-server

	if [ -f /etc/outline-server/config.toml ]; then
		sed -i 's#/etc/outline-ss-rust/#/etc/outline-server/#g; s#/var/lib/outline-ss-rust/#/var/lib/outline-server/#g' \
			/etc/outline-server/config.toml
	fi

	# GNU sed -i пересоздаёт файл от root:root, поэтому права выставляем строго после sed.
	chown -R outline-server:outline-server /etc/outline-server /var/lib/outline-server
	chmod 0750 /etc/outline-server
	find /etc/outline-server -maxdepth 1 -type f -exec chmod 0640 {} +

	if [ -d /etc/systemd/system/outline-ss-rust.service.d ] && [ ! -e /etc/systemd/system/outline-server.service.d ]; then
		mv /etc/systemd/system/outline-ss-rust.service.d /etc/systemd/system/outline-server.service.d
	fi
	if [ -d /etc/systemd/system/outline-server.service.d ]; then
		find /etc/systemd/system/outline-server.service.d -type f -name '*.conf' \
			-exec sed -i 's/outline-ss-rust/outline-server/g; s/outline_ss_rust/outline_server/g' {} +
	fi

	if [ -d /opt/outline/outline-ss-rust ] && [ ! -e /opt/outline/outline-server ]; then
		mv /opt/outline/outline-ss-rust /opt/outline/outline-server
	fi
	for f in \
		/opt/outline/outline-server/save-keys.sh \
		/opt/outline/outline-server/generate_keys.py \
		/opt/outline/access-keys/generate_keys.py; do
		if [ -f "$f" ]; then
			sed -i --follow-symlinks \
				's#/etc/outline-ss-rust#/etc/outline-server#g; s#/opt/outline/outline-ss-rust#/opt/outline/outline-server#g; s/outline-ss-rust/outline-server/g' \
				"$f"
			chmod 0755 "$f"
		fi
	done
	if [ -f /opt/outline/outline-server/users.txt ]; then
		chown root:outline-server /opt/outline/outline-server/users.txt
		chmod 0640 /opt/outline/outline-server/users.txt
	fi

	for f in /opt/ddns/*/permission-certs.sh /opt/beerloga/permission-certs.sh; do
		if [ -f "$f" ]; then
			was_exec=0
			if [ -x "$f" ]; then
				was_exec=1
			fi
			sed -i --follow-symlinks 's/outline-ss-rust/outline-server/g' "$f"
			if [ "$was_exec" = 1 ]; then
				chmod +x "$f"
			fi
		fi
	done
fi

if [ "$DO_CLIENT" = 1 ]; then
	if getent group outline-ws >/dev/null && ! getent group outline-client >/dev/null; then
		groupmod -n outline-client outline-ws
	elif ! getent group outline-client >/dev/null; then
		groupadd --system outline-client
	fi
	if getent passwd outline-ws >/dev/null && ! getent passwd outline-client >/dev/null; then
		usermod -l outline-client -g outline-client -d /var/lib/outline-client outline-ws
	elif ! getent passwd outline-client >/dev/null; then
		useradd --system --gid outline-client --no-create-home --home-dir /var/lib/outline-client --shell /usr/sbin/nologin outline-client
	fi

	if [ -d /etc/outline-ws-rust ] && [ ! -e /etc/outline-client ]; then
		mv /etc/outline-ws-rust /etc/outline-client
	fi
	if [ -d /var/lib/outline-ws-rust ] && [ ! -e /var/lib/outline-client ]; then
		mv /var/lib/outline-ws-rust /var/lib/outline-client
	fi
	if [ -d /var/log/outline-ws-rust ] && [ ! -e /var/log/outline-client ]; then
		mv /var/log/outline-ws-rust /var/log/outline-client
	fi
	mkdir -p /etc/outline-client /var/lib/outline-client/_default /var/log/outline-client/_default

	if [ -f /etc/outline-client/config.toml ]; then
		sed -i 's#/etc/outline-ws-rust/#/etc/outline-client/#g; s#/var/lib/outline-ws-rust/#/var/lib/outline-client/#g; s#/var/log/outline-ws-rust/#/var/log/outline-client/#g' \
			/etc/outline-client/config.toml
	fi
	if [ -d /etc/outline-client/instances ]; then
		find /etc/outline-client/instances -type f -name '*.toml' \
			-exec sed -i 's#/etc/outline-ws-rust/#/etc/outline-client/#g; s#/var/lib/outline-ws-rust/#/var/lib/outline-client/#g; s#/var/log/outline-ws-rust/#/var/log/outline-client/#g' {} +
	fi

	# GNU sed -i пересоздаёт файл от root:root, поэтому права выставляем строго после sed.
	chown -R outline-client:outline-client /etc/outline-client /var/lib/outline-client /var/log/outline-client
	chmod 0750 /etc/outline-client
	find /etc/outline-client -maxdepth 1 -type f -exec chmod 0640 {} +
	if [ -d /etc/outline-client/instances ]; then
		chmod 0750 /etc/outline-client/instances
		find /etc/outline-client/instances -maxdepth 1 -type f -exec chmod 0640 {} +
	fi

	if [ -d /etc/systemd/system/outline-ws-rust.service.d ] && [ ! -e /etc/systemd/system/outline-client.service.d ]; then
		mv /etc/systemd/system/outline-ws-rust.service.d /etc/systemd/system/outline-client.service.d
	fi
	if [ -d /etc/systemd/system/outline-client.service.d ]; then
		find /etc/systemd/system/outline-client.service.d -type f -name '*.conf' \
			-exec sed -i 's/outline-ws-rust/outline-client/g; s/outline-ws\b/outline-client/g; s/outline_ws_rust/outline_client/g' {} +
	fi
	for d in /etc/systemd/system/outline-ws-rust@*.service.d; do
		[ -d "$d" ] || continue
		target="/etc/systemd/system/outline-client@${d##*/outline-ws-rust@}"
		if [ ! -e "$target" ]; then
			mv "$d" "$target"
			find "$target" -type f -name '*.conf' \
				-exec sed -i 's/outline-ws-rust/outline-client/g; s/outline-ws\b/outline-client/g; s/outline_ws_rust/outline_client/g' {} +
		fi
	done

	if [ -d /opt/outline/outline-ws-rust ] && [ ! -e /opt/outline/outline-client ]; then
		mv /opt/outline/outline-ws-rust /opt/outline/outline-client
	fi
	if [ -f /opt/outline/outline-client/init-ws0.sh ]; then
		if grep -qE '/opt/outline/outline-ws-rust|outline-ws-rust' /opt/outline/outline-client/init-ws0.sh; then
			sed -i --follow-symlinks \
				's#/opt/outline/outline-ws-rust#/opt/outline/outline-client#g; s/outline-ws-rust/outline-client/g' \
				/opt/outline/outline-client/init-ws0.sh
		fi
		chmod 0755 /opt/outline/outline-client/init-ws0.sh
		[ -x /opt/outline/outline-client/init-ws0.sh ] || { echo "error: init-ws0.sh is not executable" >&2; exit 1; }
	fi
	for f in /opt/outline/outline-client/*.sh; do
		[ -f "$f" ] || continue
		if [ "$f" = "/opt/outline/outline-client/init-ws0.sh" ]; then
			continue
		fi
		was_exec=0
		if [ -x "$f" ]; then
			was_exec=1
		fi
		if grep -qE '/opt/outline/outline-ws-rust|outline-ws-rust' "$f"; then
			sed -i --follow-symlinks \
				's#/opt/outline/outline-ws-rust#/opt/outline/outline-client#g; s/outline-ws-rust/outline-client/g' \
				"$f"
		fi
		if [ "$was_exec" = 1 ]; then
			chmod +x "$f"
			[ -x "$f" ] || { echo "error: $f lost +x permission" >&2; exit 1; }
		fi
	done
	if [ -f /etc/systemd/system/outline-ws0-routing.service ]; then
		if grep -qE '/opt/outline/outline-ws-rust|outline-ws-rust' /etc/systemd/system/outline-ws0-routing.service; then
			sed -i --follow-symlinks \
				's#/opt/outline/outline-ws-rust#/opt/outline/outline-client#g; s/outline-ws-rust/outline-client/g' \
				/etc/systemd/system/outline-ws0-routing.service
		fi
	fi
	for f in /opt/network/*.sh; do
		[ -f "$f" ] || continue
		was_exec=0
		if [ -x "$f" ]; then
			was_exec=1
		fi
		if grep -qE '/opt/outline/outline-ws-rust|outline-ws-rust' "$f"; then
			sed -i --follow-symlinks \
				's#/opt/outline/outline-ws-rust#/opt/outline/outline-client#g; s/outline-ws-rust/outline-client/g' \
				"$f"
		fi
		if [ "$was_exec" = 1 ]; then
			chmod +x "$f"
			[ -x "$f" ] || { echo "error: $f lost +x permission" >&2; exit 1; }
		fi
	done

	if [ -f /etc/default/nanopi104-backup ]; then
		sed -i 's/outline-ws-rust/outline-client/g' /etc/default/nanopi104-backup
	fi
fi

if [ -f /etc/systemd/system/post-up.service ]; then
	if [ "$DO_SERVER" = 1 ]; then
		sed -i 's/outline-ss-rust\.service/outline-server.service/g' /etc/systemd/system/post-up.service
	fi
	if [ "$DO_CLIENT" = 1 ]; then
		sed -i 's/outline-ws-rust\.service/outline-client.service/g' /etc/systemd/system/post-up.service
	fi
fi

# 3. Установка новых бинарей, watchdog и unit-файлов + удаление старых
install -o root -g root -m 0755 "$STAGE/outline-watchdog" /usr/local/sbin/outline-watchdog

if [ "$DO_SERVER" = 1 ]; then
	install -o root -g root -m 0755 "$STAGE/outline-server" /usr/local/bin/outline-server
	install -o root -g root -m 0644 "$STAGE/outline-server.service" /etc/systemd/system/outline-server.service
	rm -f /etc/systemd/system/outline-ss-rust.service /usr/local/bin/outline-ss-rust
fi
if [ "$DO_CLIENT" = 1 ]; then
	install -o root -g root -m 0755 "$STAGE/outline-client" /usr/local/bin/outline-client
	install -o root -g root -m 0644 "$STAGE/outline-client.service" /etc/systemd/system/outline-client.service
	install -o root -g root -m 0644 "$STAGE/outline-client@.service" /etc/systemd/system/outline-client@.service
	rm -f /etc/systemd/system/outline-ws-rust.service /etc/systemd/system/outline-ws-rust@.service /usr/local/bin/outline-ws-rust
fi

systemctl daemon-reload

# 4. Запуск и проверка /metrics
check_metrics() {
	local unit="$1" port="$2"
	local ok=0 code=""
	for _ in $(seq 1 15); do
		sleep 2
		systemctl is-active --quiet "$unit" || continue
		code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/metrics" || true)
		if [ "$code" = "200" ]; then
			ok=1
			break
		fi
	done
	if [ "$ok" != 1 ]; then
		echo "error: $unit did not answer HTTP 200 on 127.0.0.1:$port/metrics" >&2
		return 1
	fi
}

if [ "$DO_SERVER" = 1 ]; then
	systemctl enable --now outline-server.service
	check_metrics outline-server.service 9090
	systemctl enable --now outline-watchdog@outline-server.timer
	echo "    ok: outline-server active, /metrics 200"
fi
if [ "$DO_CLIENT" = 1 ]; then
	systemctl enable --now outline-client.service
	check_metrics outline-client.service 9091
	for inst in "${CLIENT_INSTANCES[@]+"${CLIENT_INSTANCES[@]}"}"; do
		systemctl enable --now "outline-client@${inst}.service"
	done
	systemctl enable --now outline-watchdog@outline-client.timer
	echo "    ok: outline-client active, /metrics 200"
fi

MIGRATED=0
echo "    completed! rollback snapshot kept at $ROLLBACK"
REMOTE
} | ssh "${SSH_OPTS[@]}" "$HOST" 'sudo -n bash -s'
