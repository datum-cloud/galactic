#!/bin/bash
# deploy-fabric.sh — Install the FRR fabric DaemonSet on every cluster.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# config/fabric-router/ (shared with production) is a single DaemonSet whose
# affinity allows any node carrying galactic.datumapis.com/fabric=router,
# regardless of its galactic.datumapis.com/node value or
# galactic.datumapis.com/galactic mode. resources/fabric-router/base/ builds
# on a copy of it and patches in nothing but the lab-only
# image/imagePullPolicy -- one DaemonSet per cluster covers every role,
# since frr-init selects a per-node frr.conf.<nodename> key from
# fabric-config via NODE_NAME and each site's kustomization generates one
# key per matching node. Copied onto the node at deploy time nested under
# the overlay's own root so its "fabric" resource reference resolves
# (kustomize requires resources in or below the overlay root).
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

# rm -rf first -- see copy_fabric_config's comment; copy_to (lib.sh) doesn't
# overwrite an already-provisioned node's copy on its own either.
for site in dfw iad sjc; do
  node=$(control_plane "${site}")
  docker exec "${node}" rm -rf /galactic/resources/fabric-router
  copy_to "${node}" fabric-router
  copy_fabric_config "${node}"
  apply_k "${node}" "/galactic/resources/fabric-router/${site}/"
done

# iad-control-plane also carries the galactic-router route-reflector
# resources, applied by deploy-galactic-router.sh -- copied here so both
# land in one pass.
node=$(control_plane iad)
echo "Copying resources to ${node}..."
docker exec "${node}" rm -rf /galactic/resources/galactic-router /galactic/resources/galactic-control
copy_to "${node}" galactic-router
copy_to "${node}" galactic-control

echo "Done."
