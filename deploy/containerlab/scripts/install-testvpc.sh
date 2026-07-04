#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RESOURCES_DIR="${SCRIPT_DIR}/../resources"

# setup_cni_kubeconfig mints a token and pushes a kubeconfig to each worker
# so galactic-cni can reach the API server. Requires deploy:system (RBAC) first.
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

  # Push kubeconfig and CNI wrapper to each worker.
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
    # Write the CNI wrapper. Escaped $ and " so $(hostname) and "$@"
    # are written literally and evaluated at runtime, not install time.
    docker exec "${worker}" sh -c 'cat > /opt/cni/bin/galactic-cni <<'"'"'WRAPPER'"'"'
#!/bin/sh
export GALACTIC_CNI_NODE_NAME=$(hostname)
export KUBECONFIG=/etc/galactic/kubeconfig
exec /opt/cni/bin/galactic-cni.bin "$@"
WRAPPER
chmod 0755 /opt/cni/bin/galactic-cni'
  done
}

# Deploy test pods across all clusters.
for site_node in dfw-control-plane:dfw sjc-control-plane:sjc iad-control-plane:iad; do
  IFS=: read -r node site <<< "${site_node}"
  echo "Applying testvpc/${site} to ${node}..."
  docker cp "${RESOURCES_DIR}/testvpc/${site}" "${node}:/galactic/resources/testvpc-${site}/"
  docker exec "${node}" kubectl apply -f "/galactic/resources/testvpc-${site}/"
done

setup_cni_kubeconfig dfw-control-plane dfw-worker
setup_cni_kubeconfig sjc-control-plane sjc-worker
setup_cni_kubeconfig iad-control-plane iad-worker iad-worker-control

echo "Done."
