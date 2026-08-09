#!/usr/bin/env bash
#
# Push the *.k3s.beerloga.su certificate issued by lego into the cluster.
#
# Runs on 198.18.1.102 (where lego and the reg.ru credentials already live),
# called from /opt/beerloga/update-certs.sh right after renewal. Deployed copy:
#   /opt/beerloga/publish-cert.sh
#
# Idempotent: when the certificate has not changed, `apply` is a no-op, so this
# can run on every nightly pass without churning the Secret.
#
# The kubeconfig carries the cert-publisher ServiceAccount token, which may only
# get/update/patch this one Secret — see apps/ingress/cert-publisher.rbac.yaml.
set -euo pipefail

CERT_DIR=${CERT_DIR:-/opt/beerloga/.lego/certificates}
KUBECONFIG_FILE=${KUBECONFIG_FILE:-/opt/beerloga/k3s-cert.kubeconfig}
NAMESPACE=traefik
SECRET=k3s-wildcard-tls

# lego stores wildcards with '_' in place of '*'.
CRT="$CERT_DIR/_.k3s.beerloga.su.crt"
KEY="$CERT_DIR/_.k3s.beerloga.su.key"

for f in "$CRT" "$KEY" "$KUBECONFIG_FILE"; do
  [ -s "$f" ] || { echo "publish-cert: missing or empty $f" >&2; exit 1; }
done

kubectl --kubeconfig="$KUBECONFIG_FILE" -n "$NAMESPACE" \
  create secret tls "$SECRET" --cert="$CRT" --key="$KEY" \
  --dry-run=client -o yaml \
  | kubectl --kubeconfig="$KUBECONFIG_FILE" apply -f -
