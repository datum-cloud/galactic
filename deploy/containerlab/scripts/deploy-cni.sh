#!/bin/bash
# deploy-cni.sh — Mint a long-lived token for the galactic-cni ServiceAccount
# and push a kubeconfig to each worker so galactic-cni can reach the API
# server. Every pod attach (CNI ADD/DEL) depends on this, not just test VPCs.
# Requires deploy:system (RBAC) first. The CNI wrapper that points
# KUBECONFIG at /etc/galactic/kubeconfig is baked into the node image by
# containers/kindest-node-galactic/scripts/install.sh.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

setup_cni_kubeconfig() {
  local control_plane="$1"
  shift
  local workers=("$@")

  echo "Setting up galactic-cni on ${control_plane}..."

  # Resolve the API server IPv6 address on the Docker bridge.
  local api_ip
  api_ip=$(docker inspect "${control_plane}" \
    --format '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' \
    | head -1)

  # Mint a long-lived token and fetch the CA cert.
  local token ca_data
  token=$(docker exec "${control_plane}" \
    kubectl create token galactic-cni -n galactic-system --duration=87600h)
  ca_data=$(docker exec "${control_plane}" \
    kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')

  for worker in "${workers[@]}"; do
    echo "  -> ${worker}"
    docker exec "${worker}" mkdir -p /etc/galactic
    cat <<EOF | docker exec -i "${worker}" tee /etc/galactic/kubeconfig > /dev/null
apiVersion: v1
kind: Config
clusters:
  - name: galactic
    cluster:
      server: https://[${api_ip}]:6443
      certificate-authority-data: ${ca_data}
contexts:
  - name: galactic
    context:
      cluster: galactic
      user: galactic-cni
current-context: galactic
users:
  - name: galactic-cni
    user:
      token: ${token}
EOF
  done
}

setup_cni_kubeconfig "$(control_plane dfw)" dfw-worker
setup_cni_kubeconfig "$(control_plane sjc)" sjc-worker
setup_cni_kubeconfig "$(control_plane iad)" iad-worker iad-worker-control

echo "Done."
