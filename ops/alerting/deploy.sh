#!/usr/bin/env bash
#
# deploy.sh — render and push the vmalert rules and the Alertmanager config.
#   ./deploy.sh --render <dir>   # write <dir>/alertmanager.yml, touch nothing else
#   ./deploy.sh                  # apply ConfigMap vmalert-rules and Secrets
#                                # alertmanager-config, alertmanager-smtp
# Secrets come from $OUTLINE_SECRETS_DIR (default ~/.config/outline):
# heartbeat-token, telegram-bot-token, telegram-chat-id. The SMTP password is
# copied from the existing Secret grafana-smtp (key smtp).
set -euo pipefail
cd "$(dirname "$0")"

conf=${OUTLINE_SECRETS_DIR:-$HOME/.config/outline}

require() { [ -s "$1" ] || { echo "missing $1 — $2" >&2; exit 1; }; }
require "$conf/heartbeat-token"    "shared heartbeat token (mode 0600)"
require "$conf/telegram-bot-token" "Telegram bot token from @BotFather (mode 0600)"
require "$conf/telegram-chat-id"   "Telegram chat id"

render() { # render <out dir>
	local token tg_token tg_chat
	token="$(tr -d '\n' < "$conf/heartbeat-token")"
	tg_token="$(tr -d '\n' < "$conf/telegram-bot-token")"
	tg_chat="$(tr -d '\n' < "$conf/telegram-chat-id")"
	case "$tg_chat" in ''|*[!0-9-]*) echo "telegram-chat-id must be an integer" >&2; exit 1 ;; esac
	TOKEN="$token" TG_TOKEN="$tg_token" TG_CHAT="$tg_chat" OUT_FILE="$1/alertmanager.yml" python3 -c '
import os
token = os.environ["TOKEN"]
tg_token = os.environ["TG_TOKEN"]
tg_chat = os.environ["TG_CHAT"]
out_file = os.environ["OUT_FILE"]
with open("alertmanager/alertmanager.yml", "r", encoding="utf-8") as f:
    content = f.read()
content = content.replace("__HEARTBEAT_TOKEN__", token)
content = content.replace("__TELEGRAM_BOT_TOKEN__", tg_token)
content = content.replace("__TELEGRAM_CHAT_ID__", tg_chat)
with open(out_file, "w", encoding="utf-8") as f:
    f.write(content)
'
	if grep -q '__[A-Z_]*__' "$1/alertmanager.yml"; then
		echo "unsubstituted placeholder left in alertmanager.yml" >&2
		exit 1
	fi
}

if [ "${1:-}" = "--render" ]; then
	[ -d "${2:-}" ] || { echo "usage: $0 --render <existing dir>" >&2; exit 1; }
	render "$2"
	exit 0
fi

command -v kubectl >/dev/null || { echo "kubectl not in PATH" >&2; exit 1; }
: "${KUBECONFIG:?set KUBECONFIG (e.g. ~/.kube/k3s-home.yaml)}"

echo "==> offline checks"
./test.sh

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
render "$tmp"

kubectl -n monitoring get secret grafana-smtp -o jsonpath='{.data.smtp}' \
	| base64 -d > "$tmp/smtp"
[ -s "$tmp/smtp" ] || { echo "Secret grafana-smtp has no key smtp" >&2; exit 1; }

kubectl create configmap vmalert-rules -n monitoring \
	--from-file=rules.yaml=vmalert/rules.yaml \
	--dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic alertmanager-config -n monitoring \
	--from-file=alertmanager.yml="$tmp/alertmanager.yml" \
	--dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic alertmanager-smtp -n monitoring \
	--from-file=smtp="$tmp/smtp" \
	--dry-run=client -o yaml | kubectl apply -f -

cat <<'EOF'

==> applied.
    vmalert re-reads its rules by itself (-configCheckInterval=1m) once the
    kubelet syncs the ConfigMap into the pod, ~1-2 minutes.
    Alertmanager reads its config only on start or on /-/reload. After ~90 s
    (Secret sync) reload EVERY replica — no restart, notification state is kept:

    for i in 0 1 2; do kubectl -n monitoring exec alertmanager-$i -- \
      wget -qO- --post-data='' http://127.0.0.1:9093/-/reload; done

    and confirm:

    for i in 0 1 2; do kubectl -n monitoring logs alertmanager-$i --since=2m | grep -i "completed loading"; done
EOF
