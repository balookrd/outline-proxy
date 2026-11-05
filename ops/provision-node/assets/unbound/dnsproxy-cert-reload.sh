#!/bin/sh
#
# Restart dnsproxy once the node's certificate has been renewed. Owned by
# ops/provision-node/assets/unbound/dnsproxy-cert-reload.sh — install.sh writes
# this file to /opt/unbound/dnsproxy-cert-reload.sh with %DOMAIN% expanded, so
# edit it here rather than on a node. Run hourly from
# /etc/cron.d/dnsproxy-cert-reload (assets/unbound/dnsproxy-cert-reload.cron).
#
# dnsproxy reads --tls-crt/--tls-key once at start-up and never looks at the
# files again: no SIGHUP, no file watcher, nothing in its flags. So after lego
# renews the certificate the container keeps serving the OLD one on
# :8853/:8443 until it is restarted, and every DoT/DoH client that verifies
# the chain drops the node the moment the old one expires. That is how the
# fleet lost google.com on 2026-11-05: cloud1/cloud2 forward that zone over
# DoT to nuxt/nuxt2, whose dnsproxy had been serving expired certificates for
# weeks (nuxt since 2026-10-14) while the renewed files sat next to them.
#
# The renewal itself lives in /opt/beerloga/update-certs.sh, which is copied
# from the reference and differs per family, so this hook deliberately does not
# depend on it: it compares the certificate file's mtime with the container's
# start time and restarts dnsproxy when the file is the newer of the two. A
# restart costs a sub-second gap on the DoT/DoH listeners; unbound behind them
# is not touched.
#
# Exit status is 0 whenever there was nothing to do, so cron stays quiet.

CERT=/opt/beerloga/.lego/certificates/%DOMAIN%.crt
CONTAINER=dnsproxy

[ -f "$CERT" ] || exit 0

started="$(docker inspect -f '{{.State.StartedAt}}' "$CONTAINER" 2>/dev/null)" || exit 0
[ -n "$started" ] || exit 0

# StartedAt is RFC 3339, normally with nanoseconds
# ("2026-11-05T10:15:03.123456789Z"); date(1) on Ubuntu parses it once the
# fraction is dropped and the zone suffix is kept.
started="${started%%.*}"
started="${started%Z}Z"
started_epoch="$(date -d "$started" +%s 2>/dev/null)" || exit 0
cert_epoch="$(stat -c %Y "$CERT")"

[ "$cert_epoch" -gt "$started_epoch" ] || exit 0

if docker restart "$CONTAINER" >/dev/null; then
    logger -t dnsproxy-cert-reload "restarted $CONTAINER: $CERT is newer than the container"
else
    logger -t dnsproxy-cert-reload "failed to restart $CONTAINER after $CERT changed"
    exit 1
fi
