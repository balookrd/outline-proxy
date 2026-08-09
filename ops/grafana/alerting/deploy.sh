#!/usr/bin/env bash
#
# deploy.sh — push the Grafana alerting provisioning.
# Run from the development machine:
#   ./deploy.sh          # legacy: copy to the docker Grafana on .102
#   ./deploy.sh --k3s    # cluster: one Secret in the monitoring namespace
#
# Grafana re-reads provisioning files on its own, so this needs no restart —
# which is the whole reason the rules live in files rather than in the UI.

set -euo pipefail
cd "$(dirname "$0")"

k3s=0
if [ "${1:-}" = "--k3s" ]; then
	k3s=1
	shift
fi

host=${GRAFANA_HOST:-mmv@198.18.1.102}
conf=${OUTLINE_SECRETS_DIR:-$HOME/.config/outline}
token_file=${HEARTBEAT_TOKEN_FILE:-$conf/heartbeat-token}
tg_token_file=${TELEGRAM_TOKEN_FILE:-$conf/telegram-bot-token}
tg_chat_file=${TELEGRAM_CHAT_FILE:-$conf/telegram-chat-id}
dest=/opt/grafana/provisioning/alerting

require() {
	[ -s "$1" ] || { echo "missing $1 — $2" >&2; exit 1; }
}
require "$token_file"    "put the shared heartbeat token there (mode 0600)"
require "$tg_token_file" "put the Telegram bot token there (from @BotFather, mode 0600)"
require "$tg_chat_file"  "put the Telegram chat id there"

token="$(tr -d '\n' < "$token_file")"
tg_token="$(tr -d '\n' < "$tg_token_file")"
tg_chat="$(tr -d '\n' < "$tg_chat_file")"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for f in rules.yaml contact-points.yaml policies.yaml; do
	[ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
	sed -e "s|__HEARTBEAT_TOKEN__|$token|g" \
		-e "s|__TELEGRAM_BOT_TOKEN__|$tg_token|g" \
		-e "s|__TELEGRAM_CHAT_ID__|$tg_chat|g" "$f" > "$tmp/$f"
done

# A YAML syntax error would otherwise surface only as a silent no-op in the
# Grafana log, hours later, with the old rules still in force. PyYAML is present
# on the gateway but not on every development machine, so fall back to ruby's
# psych, which ships with the macOS system ruby.
if python3 -c 'import yaml' 2>/dev/null; then
	python3 -c "
import sys, yaml
for p in sys.argv[1:]:
    yaml.safe_load(open(p))
print('yaml ok (pyyaml)')
" "$tmp"/*.yaml
elif command -v ruby >/dev/null; then
	# safe_load(File.read) rather than safe_load_file: the system ruby on macOS
	# ships a psych old enough to lack the latter.
	ruby -ryaml -e 'ARGV.each { |p| YAML.safe_load(File.read(p)) }; puts "yaml ok (psych)"' "$tmp"/*.yaml
else
	echo "no YAML parser available (pyyaml or ruby) — refusing to deploy unchecked" >&2
	exit 1
fi

if [ "$k3s" = 1 ]; then
	# Cluster mode: the three files become one Secret, not a ConfigMap —
	# contact-points.yaml carries the Telegram bot token and the heartbeat
	# token after substitution.
	command -v kubectl >/dev/null || { echo "kubectl not in PATH" >&2; exit 1; }
	: "${KUBECONFIG:?set KUBECONFIG (e.g. ~/.kube/k3s-home.yaml)}"
	kubectl create secret generic grafana-alerting -n monitoring \
		--from-file="$tmp/rules.yaml" \
		--from-file="$tmp/contact-points.yaml" \
		--from-file="$tmp/policies.yaml" \
		--dry-run=client -o yaml | kubectl apply -f -
	cat <<EOF

==> Secret applied, but NOT yet in force. Alerting provisioning runs once at
    startup, so the pod has to restart (a production action — ask the owner
    first):

    kubectl -n monitoring rollout restart deploy/grafana

and confirm it took:

    kubectl -n monitoring logs deploy/grafana --since=2m | grep "provision alerting"
EOF
	exit 0
fi

echo "==> copying to $host:$dest"
scp -q "$tmp"/rules.yaml "$tmp"/contact-points.yaml "$tmp"/policies.yaml "$host:/tmp/"
ssh "$host" "
	set -e
	for f in rules.yaml contact-points.yaml policies.yaml; do
		sudo install -D -m 0640 -o 1000 -g 1000 \"/tmp/\$f\" \"$dest/\$f\"
		rm -f \"/tmp/\$f\"
	done
"

cat <<EOF

==> copied, but NOT yet in force.

Alerting provisioning runs once at startup — unlike dashboards, there is no
poller re-reading the directory. Files dropped in later just sit there (verified
2026-08-07: a copy landing 27 seconds after startup left zero rules in the
database). Restarting is a production action, so ask the owner first, then:

    ssh $host 'sudo docker restart grafana'

and confirm it took:

    ssh $host 'sudo docker logs --since 2m grafana 2>&1 | grep "provision alerting"'
EOF
