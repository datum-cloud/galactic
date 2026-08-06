#!/bin/bash
# deploy-fabric.sh — Install the FRR fabric DaemonSets on every cluster.
# iad additionally receives the control-node fabric overlay.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# config/fabric/ (shared with production) is a single DaemonSet whose
# affinity allows both the edge and control node labels. resources/fabric-router/
# base/ and resources/fabric-control/iad/ each build on a copy of it and
# patch in the lab-only image/imagePullPolicy plus a narrower affinity
# (edge-only / control-only respectively) — iad needs the two split back
# apart because its two nodes need different frr.conf. Copied onto the node
# at deploy time nested under each consuming overlay's own root so its
# "fabric" resource reference resolves (kustomize requires resources in or
# below the overlay root).
FABRIC_DIR=$(cd "${SCRIPT_DIR}/../../../config/fabric" && pwd)

# copy_fabric_config NODE copies config/fabric/ onto NODE, nested under
# resources/fabric-router/base/ so the base overlay's "fabric" resource
# reference resolves.
copy_fabric_config() {
  local node="$1"
  docker cp "${FABRIC_DIR}" "${node}:/galactic/resources/fabric-router/base/fabric"
}

# copy_fabric_control_config NODE copies config/fabric/ onto NODE, nested
# under resources/fabric-control/iad/ so that overlay's "fabric"
# resource reference resolves.
copy_fabric_control_config() {
  local node="$1"
  docker cp "${FABRIC_DIR}" "${node}:/galactic/resources/fabric-control/iad/fabric"
}

# dfw and sjc only need the fabric overlay.
for site in dfw sjc; do
  node=$(control_plane "${site}")
  copy_to "${node}" fabric-router
  copy_fabric_config "${node}"
  apply_k "${node}" "/galactic/resources/fabric-router/${site}/"
done

# iad-control-plane needs fabric + fabric-control + galactic-router —
# batch all copies together.
node=$(control_plane iad)
echo "Copying resources to ${node}..."
copy_to "${node}" fabric-router
copy_fabric_config "${node}"
copy_to "${node}" fabric-control
copy_fabric_control_config "${node}"
copy_to "${node}" galactic-router
copy_to "${node}" galactic-control

# Both fabric overlays (per-site and iad's control role) are kustomize now.
apply_k "${node}" /galactic/resources/fabric-router/iad/
apply_k "${node}" /galactic/resources/fabric-control/iad/

echo "Done."
