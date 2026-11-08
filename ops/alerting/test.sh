#!/usr/bin/env bash
#
# test.sh — offline checks for the vmalert rules and the Alertmanager config.
# Needs only docker. Run from anywhere: ./ops/alerting/test.sh
set -euo pipefail
cd "$(dirname "$0")"

VMALERT_TOOL=victoriametrics/vmalert-tool@sha256:b03d29d0a11b906a85879a6a4009c9d0a9d5a8b9a744ebb7dd3a7721f1e78f36

echo "==> annotations free of < > & (Telegram parse_mode HTML, templates do not escape)"
if grep -nE '^\s+(summary|description):.*[<>&]' vmalert/rules.yaml; then
	echo "annotation contains < > or &" >&2
	exit 1
fi

echo "==> vmalert-tool unittest"
docker run --rm -v "$PWD/vmalert:/w" -w /w "$VMALERT_TOOL" \
	unittest --files=tests/uplink.yaml --files=tests/nodes.yaml --files=tests/heartbeat.yaml

ALERTMANAGER=prom/alertmanager@sha256:39d8bb3966c694a124428a3a88fbcffd40bd069129ecd47c059f8a3f17c55f3b

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/secrets" "$tmp/conf"
echo dummy-heartbeat > "$tmp/secrets/heartbeat-token"
echo 123:dummy-bot   > "$tmp/secrets/telegram-bot-token"
echo 42              > "$tmp/secrets/telegram-chat-id"
echo dummy-smtp      > "$tmp/conf/smtp"

echo "==> render alertmanager.yml with dummy secrets"
OUTLINE_SECRETS_DIR="$tmp/secrets" ./deploy.sh --render "$tmp/conf"

amtool() {
	docker run --rm -v "$tmp/conf:/etc/alertmanager/conf:ro" \
		-v "$tmp/conf:/etc/alertmanager/secrets:ro" \
		--entrypoint amtool "$ALERTMANAGER" "$@"
}

echo "==> amtool check-config"
amtool check-config /etc/alertmanager/conf/alertmanager.yml

route() { # route <expected receiver> <label=value>...
	local want="$1"; shift
	amtool config routes test --config.file=/etc/alertmanager/conf/alertmanager.yml \
		--verify.receivers="$want" "$@" >/dev/null \
		|| { echo "route for $* is not $want" >&2; exit 1; }
	echo "    $* -> $want"
}

echo "==> routing"
route heartbeat-observers alertname=DeadMansSwitch
route heartbeat-observers alertname=DeadMansSwitch shadow=true
route blackhole           alertname=TargetDown shadow=true instance=ubuntu
route owner               alertname=TargetDown instance=ubuntu
route owner               alertname=UplinkCarrierLossHigh instance=ubuntu
route owner-events        alertname=ClientRestarted instance=ubuntu
route owner-events        alertname=NodeRebooted instance=k3s-2
route owner               alertname=AlertingSelfTest instance=selftest

echo "==> all checks passed"
