#!/usr/bin/env bash
# Capture what fresh Chrome stable and Firefox release send to local sinks.
#
# Usage: capture.sh [--install] <out-dir>
#
# --install  apt-installs tshark, Xvfb, NSS tools, Google Chrome stable (Google's
#            repository) and Firefox release (Mozilla's repository, not snap/ESR).
#
# CHROME / FIREFOX override the browser binaries (default google-chrome,
# firefox), e.g. CHROME=chromium for a local arm64 run without --install.
#
# Writes <out-dir>/versions.json and, per browser, <out-dir>/<browser>/
# {h2,h1}-{hello,plain}.pcap and quic.pcap — the layout normalize.py reads.
# Linux only. Exits non-zero when a sink saw no ClientHello: a capture failure,
# never reported as drift.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
install=0
if [ "${1:-}" = --install ]; then install=1; shift; fi
[ $# -eq 1 ] || { echo "usage: $0 [--install] <out-dir>" >&2; exit 2; }
mkdir -p "$1"
out=$(cd "$1" && pwd)
sudo=; [ "$(id -u)" = 0 ] || sudo=sudo

TCP_H2=8443
TCP_H1=8444
UDP_QUIC=8445
SINK_SECS=30
BROWSER_SECS=25
CHROME=${CHROME:-google-chrome}
FIREFOX=${FIREFOX:-firefox}

install_deps() {
  export DEBIAN_FRONTEND=noninteractive
  $sudo apt-get update -qq
  $sudo apt-get install -y -qq ca-certificates wget gnupg tshark xvfb xauth libnss3-tools \
    openssl python3 >/dev/null
  wget -qO- https://dl.google.com/linux/linux_signing_key.pub \
    | $sudo gpg --dearmor --yes -o /usr/share/keyrings/google-chrome.gpg
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" \
    | $sudo tee /etc/apt/sources.list.d/google-chrome.list >/dev/null
  $sudo install -d -m 0755 /etc/apt/keyrings
  wget -qO- https://packages.mozilla.org/apt/repo-signing-key.gpg \
    | $sudo tee /etc/apt/keyrings/packages.mozilla.org.asc >/dev/null
  echo "deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.asc] https://packages.mozilla.org/apt mozilla main" \
    | $sudo tee /etc/apt/sources.list.d/mozilla.list >/dev/null
  printf 'Package: *\nPin: origin packages.mozilla.org\nPin-Priority: 1000\n' \
    | $sudo tee /etc/apt/preferences.d/mozilla >/dev/null
  $sudo apt-get update -qq
  $sudo apt-get install -y -qq google-chrome-stable firefox >/dev/null
}

[ $install = 1 ] && install_deps
# localtest.me resolves to 127.0.0.1 publicly; pin it so a resolver hiccup is
# not mistaken for a browser change.
grep -q 'localtest\.me' /etc/hosts || echo '127.0.0.1 localtest.me' | $sudo tee -a /etc/hosts >/dev/null

spki=$("$here/ca.sh" "$out/ca")
cert=$out/ca/chain.pem
key=$out/ca/leaf.key

printf '{"chrome": "%s", "firefox": "%s"}\n' "$($CHROME --version)" "$($FIREFOX --version)" \
  > "$out/versions.json"
cat "$out/versions.json"

pids=()
tls_sink() { # <port> <out-prefix> [sink flags...]
  python3 "$here/tls_sink.py" "$1" "$cert" "$key" "$2" "$SINK_SECS" "${@:3}" &
  pids+=($!)
}
quic_sink() { # <port> <out.pcap>
  python3 "$repo/scripts/quic-initial-sink.py" "$1" "$2" "$SINK_SECS" &
  pids+=($!)
}
wait_sinks() {
  local failed=0
  for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
  pids=()
  return $failed
}

require_packets() { # <pcap>: a QUIC sink that saw nothing leaves only the 24-byte header
  [ "$(wc -c <"$1")" -gt 24 ] || { echo "capture: no QUIC Initial captured in $1" >&2; exit 1; }
}

chrome() { # <log> <args...>
  local log=$1; shift
  local sandbox=(); [ "$(id -u)" = 0 ] && sandbox=(--no-sandbox)
  timeout "$BROWSER_SECS" xvfb-run -a "$CHROME" "${sandbox[@]}" \
    --user-data-dir="$(mktemp -d)" --no-first-run --no-default-browser-check \
    --ignore-certificate-errors-spki-list="$spki" "$@" >"$log" 2>&1 || true
}

firefox_profile() {
  local p
  p=$(mktemp -d)
  certutil -N -d "sql:$p" --empty-password
  certutil -A -n fingerprint-drift -t "C,," -i "$out/ca/ca.pem" -d "sql:$p"
  cat > "$p/user.js" <<'EOF'
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("network.trr.mode", 5);
EOF
  echo "$p"
}

firefox_run() { # <log> <url>
  timeout "$BROWSER_SECS" xvfb-run -a "$FIREFOX" --no-remote --profile "$(firefox_profile)" "$2" \
    >"$1" 2>&1 || true
}

mkdir -p "$out/chrome" "$out/firefox"

# Chrome: page over h2 (hello, preface, navigation, fetch, WebSocket over h2) ...
tls_sink $TCP_H2 "$out/chrome/h2"
chrome "$out/chrome/h2.log" "https://localtest.me:$TCP_H2/page"
wait_sinks
# ... over http/1.1 only (the WebSocket connection's own `http/1.1` hello) ...
tls_sink $TCP_H1 "$out/chrome/h1" --h1-only
chrome "$out/chrome/h1.log" "https://localtest.me:$TCP_H1/page"
wait_sinks
# ... and the QUIC Initial, forced: no TCP leg at all.
quic_sink $UDP_QUIC "$out/chrome/quic.pcap"
chrome "$out/chrome/quic.log" --origin-to-force-quic-on="localtest.me:$UDP_QUIC" \
  "https://localtest.me:$UDP_QUIC/page"
wait_sinks
require_packets "$out/chrome/quic.pcap"

# Firefox: the h2 page advertises Alt-Svc, so the same run sends the QUIC Initial.
tls_sink $TCP_H2 "$out/firefox/h2" --alt-svc $UDP_QUIC
quic_sink $UDP_QUIC "$out/firefox/quic.pcap"
firefox_run "$out/firefox/h2.log" "https://localtest.me:$TCP_H2/page"
wait_sinks
require_packets "$out/firefox/quic.pcap"
tls_sink $TCP_H1 "$out/firefox/h1" --h1-only
firefox_run "$out/firefox/h1.log" "https://localtest.me:$TCP_H1/page"
wait_sinks

echo "capture: $out"
