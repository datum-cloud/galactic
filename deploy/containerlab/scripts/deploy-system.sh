#!/bin/bash
# deploy-system.sh — Install BGP CRDs (datum-cloud/network) and VPC CRDs
# (Cosmos), then apply the galactic-system namespace and shared RBAC
# (galactic-cni, galactic-router) to every cluster. The namespace and
# ServiceAccount/RBAC manifests are applied straight from the repo's
# config/ — the same ones used in production — so the lab never forks them.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# Extract the datum-cloud/network commit SHA from go.mod (pseudo-version
# suffix after the last hyphen, e.g. v0.0.0-20260708202618-77cf276d17f1 →
# 77cf276d17f1).
NETWORK_SHA=$(awk '/go\.datum\.net\/network/ {print $2}' "${SCRIPT_DIR}/../../../go.mod" | sed 's/.*-//')
NETWORK_CRD_URL="https://raw.githubusercontent.com/datum-cloud/network/${NETWORK_SHA}/config/crd"

# VPC/VPCAttachment CRDs still come from Cosmos — they're owned by the
# separate companion VPC operator, not part of this migration.
COSMOS_SHA=$(awk '/go\.miloapis\.com\/cosmos/ {print $2}' "${SCRIPT_DIR}/../../../go.mod" | sed 's/.*-//')
COSMOS_CRD_URL="https://raw.githubusercontent.com/milo-os/cosmos/${COSMOS_SHA}/config/crd"

network_crds=(
  network.datumapis.com_bgpadvertisements.yaml
  network.datumapis.com_bgppeers.yaml
  network.datumapis.com_bgppolicies.yaml
  network.datumapis.com_bgprouters.yaml
  network.datumapis.com_bgpvrfinstances.yaml
)

cosmos_crds=(
  vpc.miloapis.com_vpcs.yaml
  vpc.miloapis.com_vpcattachments.yaml
)

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Applying system to ${node}..."

  # Install CRDs from GitHub before any namespace-scoped resources.
  for crd in "${network_crds[@]}"; do
    curl -sL "${NETWORK_CRD_URL}/${crd}" | docker exec -i "${node}" kubectl apply -f -
  done
  for crd in "${cosmos_crds[@]}"; do
    curl -sL "${COSMOS_CRD_URL}/${crd}" | docker exec -i "${node}" kubectl apply -f -
  done

  copy_config "${node}"
  apply_f "${node}" /galactic/config/galactic-system/namespace.yaml
  apply_f "${node}" /galactic/config/galactic-cni/serviceaccount.yaml
  apply_f "${node}" /galactic/config/galactic-cni/rbac.yaml
  apply_f "${node}" /galactic/config/galactic-router/serviceaccount.yaml
  apply_f "${node}" /galactic/config/galactic-router/rbac.yaml
done

echo "Done."
