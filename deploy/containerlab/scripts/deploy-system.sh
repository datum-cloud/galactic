#!/bin/bash
# deploy-system.sh — Install Cosmos CRDs, then apply the galactic-system
# namespace and shared RBAC (galactic-cni, galactic-router) to every cluster.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# Extract the cosmos commit SHA from go.mod (pseudo-version suffix after the
# last hyphen, e.g. v0.0.0-20260625022501-1b617fd1bad4 → 1b617fd1bad4).
COSMOS_SHA=$(awk '/go\.miloapis\.com\/cosmos/ {print $2}' "${SCRIPT_DIR}/../../../go.mod" | sed 's/.*-//')
COSMOS_CRD_URL="https://raw.githubusercontent.com/milo-os/cosmos/${COSMOS_SHA}/config/crd"

cosmos_crds=(
  bgp.miloapis.com_bgpadvertisements.yaml
  bgp.miloapis.com_bgppeers.yaml
  bgp.miloapis.com_bgppolicies.yaml
  bgp.miloapis.com_bgprouters.yaml
  bgp.miloapis.com_bgpvrfinstances.yaml
  vpc.miloapis.com_vpcs.yaml
  vpc.miloapis.com_vpcattachments.yaml
)

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Applying system to ${node}..."

  # Install CRDs from GitHub before any namespace-scoped resources.
  for crd in "${cosmos_crds[@]}"; do
    curl -sL "${COSMOS_CRD_URL}/${crd}" | docker exec -i "${node}" kubectl apply -f -
  done

  copy_to "${node}" system
  apply_f "${node}" /galactic/resources/system/
done

echo "Done."
