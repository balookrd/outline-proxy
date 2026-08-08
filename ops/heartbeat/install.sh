#!/usr/bin/env bash
#
# install.sh — install the heartbeat receiver on a cloud node. Idempotent.
# Copy this directory to the node and run: sudo ./install.sh
#
# Deliberately stops short of reloading nginx: this node terminates production
# traffic, and reloading it is the owner's call, not the installer's.

set -euo pipefail
cd "$(dirname "$0")"

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }

site=/etc/nginx/sites-enabled/beerloga.su
token_file=/etc/heartbeat-watch/token

[ -s "$token_file" ] || {
	echo "missing $token_file — write the shared heartbeat token there first" >&2
	echo "  (same token as the Grafana webhook URL; mode 0600, root-owned)" >&2
	exit 1
}
[ -f "$site" ] || { echo "no $site on this host — wrong node?" >&2; exit 1; }

token="$(tr -d '\n' < "$token_file")"
case "$token" in
	*[!A-Za-z0-9_-]*) echo "token has characters that do not belong in a URL path" >&2; exit 1 ;;
esac

echo "==> installing watcher + units"
install -D -m 0755 heartbeat-watch          /usr/local/sbin/heartbeat-watch
install -D -m 0644 heartbeat-watch.service  /etc/systemd/system/heartbeat-watch.service
install -D -m 0644 heartbeat-watch.timer    /etc/systemd/system/heartbeat-watch.timer
install -D -m 0644 README.md                /usr/local/share/heartbeat-watch/README.md
install -d -m 0755                          /var/lib/heartbeat-watch

echo "==> installing nginx snippet"
sed "s|__HEARTBEAT_TOKEN__|$token|" nginx-heartbeat.conf > /etc/nginx/snippets/heartbeat.conf
chmod 0644 /etc/nginx/snippets/heartbeat.conf

if grep -q 'snippets/heartbeat.conf' "$site"; then
	echo "==> $site already includes the snippet"
else
	echo "==> adding the include to $site"
	# The backup goes to its own directory, never next to the original: nginx.conf
	# includes /etc/nginx/sites-enabled/* by bare glob, so a copy left there is
	# loaded as a second config and collides with the block it backs up
	# ("conflicting server name ... ignored").
	install -d -m 0755 /etc/nginx/heartbeat-backups
	cp -p "$site" "/etc/nginx/heartbeat-backups/beerloga.su.$(date +%Y%m%d%H%M%S)"
	# Anchor on the listen line, not on server_name: the file opens with a
	# commented-out :80 block carrying the same server_name, and appending after
	# the first match would drop the include outside any server block.
	python3 - "$site" <<-'PY'
		import sys

		path = sys.argv[1]
		anchor = "listen 127.0.0.1:8080 proxy_protocol;"
		src = open(path, encoding="utf-8").read()

		if src.count(anchor) != 1:
		    sys.exit(f"expected exactly one {anchor!r} in {path}, found {src.count(anchor)}")

		src = src.replace(anchor, anchor + "\n\n    include snippets/heartbeat.conf;", 1)
		open(path, "w", encoding="utf-8").write(src)
	PY
fi

echo "==> checking the nginx configuration"
if ! nginx -t; then
	echo "nginx -t failed — the include was NOT activated; fix or restore from the .bak" >&2
	exit 1
fi

systemctl daemon-reload
systemctl enable --now heartbeat-watch.timer

cat <<'EOF'

==> installed. Two things remain, both for the owner:

  1. Write /etc/heartbeat-watch/smtp.env (mode 0600, root) with:
         SMTP_HOST=smtp.gmail.com:587
         SMTP_USER=<the gmail address>
         SMTP_PASSWORD=<the 16-character app password>
         MAIL_TO=<the recipient>

  2. Activate the nginx include — this reloads production nginx:
         sudo systemctl reload nginx
EOF
