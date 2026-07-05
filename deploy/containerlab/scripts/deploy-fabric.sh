#!/bin/bash
# deploy-fabric.sh — Install the FRR fabric DaemonSets on every cluster.
# iad additionally receives the control-node fabric overlay.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# dfw and sjc only need the fabric overlay.
for site in dfw sjc; do
  node=$(control_plane "${site}")
  copy_to "${node}" fabric
  apply_k "${node}" "/galactic/resources/fabric/${site}/"
done

# iad-control-plane needs fabric + control/fabric — batch all copies together.
node=$(control_plane iad)
echo "Copying resources to ${node}..."
copy_to "${node}" fabric
copy_to "${node}" control
copy_to "${node}" tenant
copy_to "${node}" bgp/tenant /galactic/resources/bgp-tenant/
copy_to "${node}" bgp/control /galactic/resources/bgp-control/

# iad fabric is a kustomize overlay; control/fabric is raw manifests.
apply_k "${node}" /galactic/resources/fabric/iad/
apply_f "${node}" /galactic/resources/control/fabric/iad/

echo "Done."
