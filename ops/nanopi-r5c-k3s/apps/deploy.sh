#!/usr/bin/env bash
#
# Bootstrap / re-sync the k3s service layer for the NanoPi R5C cluster:
#   storage (NFS provisioner) -> ingress (MetalLB + Traefik) -> workloads.
#
# Idempotent — safe to re-run: helm uses `upgrade --install`, kubectl `apply`.
# Requires kubectl + helm with a working kubeconfig. On a node:
#   export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
#
# Usage:
#   ./deploy.sh                # run every stage in order
#   ./deploy.sh metallb        # one stage: repos|storage|metallb|traefik|apps|ingress
#   ./deploy.sh edge           # ingress layer only: MetalLB + Traefik + routes,
#                              # without touching workloads
#
# Files ending in .example.yaml are never applied (secret templates). Any
# manifest still carrying <PLACEHOLDER> tokens is left unapplied with a warning
# instead of creating a broken object (unfilled image, coordinator, etc.).
set -euo pipefail

cd "$(dirname "$0")"

log()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[skip]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[err]\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1' in PATH"; }

# Apply one manifest, unless it's a template or still has <PLACEHOLDER> tokens.
apply_file() {
  local f="$1"
  case "$f" in *.example.yaml) return 0 ;; esac
  if grep -qE '<[A-Z0-9_]+>' "$f"; then
    warn "$(basename "$f"): unfilled $(grep -oE '<[A-Z0-9_]+>' "$f" | sort -u | tr '\n' ' ')— left unapplied"
    return 0
  fi
  kubectl apply -f "$f"
}

# Apply every *.yaml manifest in a dir (skips helm values — those live in files
# named *.values.yaml and are never bare manifests in the workload dirs).
apply_dir() {
  local dir="$1" f
  for f in "$dir"/*.yaml; do
    [ -e "$f" ] || continue
    case "$f" in *.values.yaml) continue ;; esac
    apply_file "$f"
  done
}

stage_repos() {
  log "helm repos"
  helm repo add nfs-subdir-external-provisioner \
    https://kubernetes-sigs.github.io/nfs-subdir-external-provisioner/ >/dev/null 2>&1 || true
  helm repo add metallb https://metallb.github.io/metallb >/dev/null 2>&1 || true
  helm repo add traefik https://traefik.github.io/charts   >/dev/null 2>&1 || true
  helm repo update >/dev/null
}

stage_storage() {
  log "NFS provisioner (198.18.1.125:/nfs/k8s)"
  helm upgrade --install nfs-client \
    nfs-subdir-external-provisioner/nfs-subdir-external-provisioner \
    -n kube-system -f storage/nfs-provisioner.values.yaml
}

stage_metallb() {
  log "MetalLB"
  helm upgrade --install metallb metallb/metallb \
    -n metallb-system --create-namespace
  kubectl -n metallb-system rollout status deploy/metallb-controller --timeout=180s
  # The validating webhook comes up a beat after the controller is Ready;
  # applying the pool too early fails with a webhook connection error. Retry.
  log "MetalLB pool 198.18.1.200-210 (announced on wan0)"
  local i
  for i in $(seq 1 10); do
    if kubectl apply -f ingress/metallb-pool.yaml; then return 0; fi
    warn "pool apply failed (webhook not ready?), retry $i/10"
    sleep 6
  done
  die "could not apply MetalLB pool"
}

stage_traefik() {
  log "Traefik (VIP 198.18.1.200)"
  helm upgrade --install traefik traefik/traefik \
    -n traefik --create-namespace -f ingress/traefik.values.yaml
  log "waiting for Traefik EXTERNAL-IP from MetalLB"
  local i ip=""
  for i in $(seq 1 24); do
    ip=$(kubectl -n traefik get svc traefik \
      -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
    [ -n "$ip" ] && { log "Traefik EXTERNAL-IP = $ip"; return 0; }
    sleep 5
  done
  warn "Traefik still has no EXTERNAL-IP — check MetalLB controller/pool"
}

# Namespaces are needed by the ingress layer too (the Ingress objects live in
# monitoring/home), so they are a stage of their own rather than part of apps.
stage_namespaces() {
  log "namespaces"
  kubectl apply -f namespaces.yaml
}

stage_apps() {
  stage_namespaces
  local d
  for d in monitoring home outline vpn; do
    log "workloads: $d"
    apply_dir "$d"
  done
}

stage_ingress() {
  log "cert publisher RBAC + default TLSStore"
  apply_file ingress/cert-publisher.rbac.yaml
  apply_file ingress/tls-store.yaml
  log "HTTP ingress routes"
  apply_file ingress/ingress-routes.yaml
}

main() {
  need kubectl
  need helm
  local stage="${1:-all}"
  case "$stage" in
    repos)   stage_repos ;;
    storage) stage_repos; stage_storage ;;
    metallb) stage_repos; stage_metallb ;;
    traefik) stage_repos; stage_traefik ;;
    apps)    stage_apps ;;
    ingress) stage_ingress ;;
    edge)    stage_repos; stage_metallb; stage_traefik; stage_namespaces; stage_ingress ;;
    all)     stage_repos; stage_storage; stage_metallb; stage_traefik; stage_apps; stage_ingress ;;
    *)       die "unknown stage '$stage' (repos|storage|metallb|traefik|apps|ingress|edge|all)" ;;
  esac
  log "done: $stage"
}

main "$@"
