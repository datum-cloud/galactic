#!/bin/bash
# deploy-fabric.sh — Install the FRR fabric DaemonSets on every cluster.
# iad additionally receives the route-reflector-node fabric overlay.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# config/fabric-router/ (shared with production) is a single DaemonSet whose
# affinity allows any node carrying galactic.datumapis.com/fabric,
# regardless of its galactic.datumapis.com/node value or
# galactic-route-reflector flag.
# resources/fabric-router/base/ and resources/fabric-control/iad/ each
# build on a copy of it and patch in the lab-only image/imagePullPolicy
# plus a narrower affinity (compute+edge / route-reflector-only respectively) —
# iad needs the route-reflector node split back out because it needs its own
# frr.conf and would otherwise get two competing fabric pods; compute and
# edge share one DaemonSet since neither needs anything but a
# per-node frr.conf key (fabric-router/iad/kustomization.yaml's
# configMapGenerator carries both). Copied onto the node at deploy time
# nested under each consuming overlay's own root so its "fabric" resource
# reference resolves (kustomize requires resources in or below the
# overlay root).
FABRIC_DIR=$(cd "${SCRIPT_DIR}/../../../config/fabric-router" && pwd)

# copy_fabric_config NODE copies config/fabric-router/ onto NODE, nested under
# resources/fabric-router/base/ so the base overlay's "fabric" resource
# reference resolves. rm -rf first: like deploy-galactic-router.sh's
# copy_router_config, docker cp nests SRC inside an already-existing DEST
# dir instead of overwriting it, so a rerun against an already-provisioned
# node would silently keep serving the prior copy from underneath the new
# one -- kubectl would then report the DaemonSet "unchanged" even after a
# real manifest edit (found live: a fabric-lab-patch.yaml affinity fix
# never took effect on a redeploy until this guard was added).
copy_fabric_config() {
  local node="$1"
  docker exec "${node}" rm -rf /galactic/resources/fabric-router/base/fabric
  docker cp "${FABRIC_DIR}" "${node}:/galactic/resources/fabric-router/base/fabric"
}

# copy_fabric_control_config NODE copies config/fabric-router/ onto NODE, nested
# under resources/fabric-control/iad/ so that overlay's "fabric"
# resource reference resolves. rm -rf first -- see copy_fabric_config's
# comment.
copy_fabric_control_config() {
  local node="$1"
  docker exec "${node}" rm -rf /galactic/resources/fabric-control/iad/fabric
  docker cp "${FABRIC_DIR}" "${node}:/galactic/resources/fabric-control/iad/fabric"
}

# dfw and sjc only need the fabric overlay. rm -rf first -- see
# copy_fabric_config's comment; copy_to (lib.sh) doesn't overwrite an
# already-provisioned node's copy on its own either.
for site in dfw sjc; do
  node=$(control_plane "${site}")
  docker exec "${node}" rm -rf /galactic/resources/fabric-router
  copy_to "${node}" fabric-router
  copy_fabric_config "${node}"
  apply_k "${node}" "/galactic/resources/fabric-router/${site}/"
done

# iad-control-plane needs fabric + fabric-control + galactic-router —
# batch all copies together. fabric-router/iad/ alone covers both
# iad-worker and iad-gateway1/2 (its ConfigMap carries all three
# frr.conf.<nodename> keys; ../base/'s affinity matches both roles).
node=$(control_plane iad)
echo "Copying resources to ${node}..."
docker exec "${node}" rm -rf /galactic/resources/fabric-router /galactic/resources/fabric-control
copy_to "${node}" fabric-router
copy_fabric_config "${node}"
copy_to "${node}" fabric-control
copy_fabric_control_config "${node}"
copy_to "${node}" galactic-router
copy_to "${node}" galactic-control

# Both fabric overlays (per-site/gateway, and iad's control role) are
# kustomize now.
apply_k "${node}" /galactic/resources/fabric-router/iad/
apply_k "${node}" /galactic/resources/fabric-control/iad/

echo "Done."
