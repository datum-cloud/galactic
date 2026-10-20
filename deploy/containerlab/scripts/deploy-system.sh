#!/bin/bash
# deploy-system.sh — Install Galactic CRDs, then apply the galactic-system namespace and shared
# RBAC (galactic-cni, galactic-router, galactic-nat, galactic-gateway) to
# every cluster. The namespace and
# ServiceAccount/RBAC manifests are applied straight from the repo's
# config/ — the same ones used in production — so the lab never forks them.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Applying system to ${node}..."

  copy_config "${node}"
  apply_k "${node}" /galactic/config/crd
  apply_f "${node}" /galactic/config/galactic-system/namespace.yaml
  apply_f "${node}" /galactic/config/galactic-cni/serviceaccount.yaml
  apply_f "${node}" /galactic/config/galactic-cni/rbac.yaml
  apply_f "${node}" /galactic/config/galactic-router/serviceaccount.yaml
  apply_f "${node}" /galactic/config/galactic-router/rbac.yaml
  apply_f "${node}" /galactic/config/galactic-nat/serviceaccount.yaml
  apply_f "${node}" /galactic/config/galactic-nat/rbac.yaml
  apply_f "${node}" /galactic/config/galactic-gateway/serviceaccount.yaml
  apply_f "${node}" /galactic/config/galactic-gateway/rbac.yaml
done

echo "Done."
