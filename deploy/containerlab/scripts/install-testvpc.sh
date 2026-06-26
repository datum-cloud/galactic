#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RESOURCES_DIR="${SCRIPT_DIR}/../resources"

# setup_cni_kubeconfig applies the galactic-cni ServiceAccount/RBAC to a
# cluster and writes a kubeconfig for it onto the corresponding worker node(s).
# The kubeconfig uses the control-plane's Docker-network IPv6 address so it
# is reachable from workers within the same ContainerLab bridge network.
setup_cni_kubeconfig() {
  local control_plane="$1"
  shift
  local workers=("$@")

  echo "Setting up galactic-cni RBAC on ${control_plane}..."
  docker cp "${RESOURCES_DIR}/testvpc/rbac.yaml" "${control_plane}:/galactic/resources/testvpc-rbac.yaml"
  docker exec "${control_plane}" kubectl apply -f /galactic/resources/testvpc-rbac.yaml

  # Resolve the API server address reachable from worker nodes: use the
  # control-plane container's IPv6 address on the Docker bridge (port 6443).
  local api_ip
  api_ip=$(docker inspect "${control_plane}" \
    --format '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' \
    | head -1)
  local api_server="https://[${api_ip}]:6443"

  # Mint a long-lived token for the ServiceAccount.
  local token
  token=$(docker exec "${control_plane}" \
    kubectl create token galactic-cni -n galactic-system --duration=87600h)

  # Fetch the cluster CA cert.
  local ca_data
  ca_data=$(docker exec "${control_plane}" \
    kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')

  # Write a minimal kubeconfig and push it to each worker.
  local kubeconfig
  kubeconfig=$(cat <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: galactic
    cluster:
      server: ${api_server}
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
)

  for worker in "${workers[@]}"; do
    echo "Installing galactic-cni kubeconfig on ${worker}..."
    docker exec "${worker}" mkdir -p /etc/galactic
    echo "${kubeconfig}" | docker exec -i "${worker}" tee /etc/galactic/kubeconfig > /dev/null

    # Update the wrapper to export KUBECONFIG and NODE_NAME so the CNI binary
    # can reach the API server and resolve the node name. Rewrite the wrapper
    # in-place.
    docker exec "${worker}" sh -c 'cat > /opt/cni/bin/galactic-cni <<'"'"'EOF'"'"'
#!/bin/sh
export NODE_NAME=$(hostname)
export GALACTIC_CNI_NODE_NAME=$(hostname)
export KUBECONFIG=/etc/galactic/kubeconfig
exec /opt/cni/bin/galactic-cni.bin "$@"
EOF
chmod 0755 /opt/cni/bin/galactic-cni'
  done
}

apply_testvpc() {
  local node="$1"
  local site="$2"
  echo "Applying testvpc/${site} to ${node}..."
  docker cp "${RESOURCES_DIR}/testvpc/${site}" "${node}:/galactic/resources/testvpc-${site}"
  # Apply NAD first so the network is available when the pod starts, then the
  # Deployment. BGPVRFInstance and BGPAdvertisement are created by the CNI on
  # pod attach — do not pre-apply them here.
  docker exec "${node}" sh -c 'kubectl create namespace vpc --dry-run=client -o yaml | kubectl apply -f -'
  docker exec "${node}" kubectl apply -f /galactic/resources/testvpc-${site}/nad.yaml
  docker exec "${node}" kubectl apply -f /galactic/resources/testvpc-${site}/nginx.yaml
}

setup_cni_kubeconfig dfw-control-plane dfw-worker
setup_cni_kubeconfig sjc-control-plane sjc-worker
setup_cni_kubeconfig iad-control-plane iad-worker iad-worker-rr

apply_testvpc dfw-control-plane dfw
apply_testvpc sjc-control-plane sjc
apply_testvpc iad-control-plane iad

echo "Done."
