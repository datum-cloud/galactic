#!/bin/bash
# deploy-fabric.sh — Install the FRR fabric DaemonSets on every cluster.
# iad additionally receives the control-node fabric overlay.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# config/fabric/ (shared with production) is a single DaemonSet whose
# affinity allows both the edge and control node labels. resources/fabric/
# base/ and resources/control/fabric/iad/ each build on a copy of it and
# patch in the lab-only image/imagePullPolicy plus a narrower affinity
# (edge-only / control-only respectively) — iad needs the two split back
# apart because its two nodes need different frr.conf. Copied onto the node
# at deploy time nested under each consuming overlay's own root so its
# "fabric" resource reference resolves (kustomize requires resources in or
# below the overlay root).
FABRIC_DIR=$(cd "${SCRIPT_DIR}/../../../config/fabric" && pwd)

# copy_fabric_config NODE copies config/fabric/ onto NODE, nested under
# resources/fabric/base/ so the base overlay's "fabric" resource reference
# resolves.
copy_fabric_config() {
  local node="$1"
  docker cp "${FABRIC_DIR}" "${node}:/galactic/resources/fabric/base/fabric"
}

# copy_fabric_control_config NODE copies config/fabric/ onto NODE, nested
# under resources/control/fabric/iad/ so that overlay's "fabric" resource
# reference resolves.
copy_fabric_control_config() {
  local node="$1"
  docker cp "${FABRIC_DIR}" "${node}:/galactic/resources/control/fabric/iad/fabric"
}

# dfw and sjc only need the fabric overlay.
for site in dfw sjc; do
  node=$(control_plane "${site}")
  copy_to "${node}" fabric
  copy_fabric_config "${node}"
  apply_k "${node}" "/galactic/resources/fabric/${site}/"
done

# iad-control-plane needs fabric + control/fabric — batch all copies together.
node=$(control_plane iad)
echo "Copying resources to ${node}..."
copy_to "${node}" fabric
copy_fabric_config "${node}"
copy_to "${node}" control
copy_fabric_control_config "${node}"
copy_to "${node}" tenant
copy_to "${node}" bgp/tenant /galactic/resources/bgp-tenant/
copy_to "${node}" bgp/control /galactic/resources/bgp-control/

# Both fabric overlays (per-site and iad's control role) are kustomize now.
apply_k "${node}" /galactic/resources/fabric/iad/
apply_k "${node}" /galactic/resources/control/fabric/iad/

echo "Done."
