#!/bin/bash
# deploy-galactic-router.sh — Install galactic-router DaemonSets and BGP resources
# for every site. iad additionally layers its route-reflector overlay on top.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# The router DaemonSet base and the production tenant/tenant-control
# overlays (node affinity keeping each role on the right nodes) live in
# config/router/{base,tenant,tenant-control}/ (shared with production;
# the shared RBAC/ServiceAccount aren't needed here).
# resources/galactic-router/base/ and resources/galactic-control/iad/
# build on the copied tenant/tenant-control overlays and patch in only the
# lab-only image and env vars. Dirs are copied onto the node at deploy time
# nested under each consuming overlay's own root (kustomize requires resources
# in or below the overlay root) rather than duplicated in the repo.
GALACTIC_ROUTER_BASE_DIR=$(cd "${SCRIPT_DIR}/../../../config/router/base" && pwd)
GALACTIC_ROUTER_TENANT_DIR=$(cd "${SCRIPT_DIR}/../../../config/router/tenant" && pwd)
GALACTIC_ROUTER_TENANT_CONTROL_DIR=$(cd "${SCRIPT_DIR}/../../../config/router/tenant-control" && pwd)

# copy_router_config NODE copies config/router/{base,tenant} onto NODE,
# nested under resources/galactic-router/base/ so the overlay's "../base"
# resource reference resolves.
copy_router_config() {
  local node="$1"
  docker cp "${GALACTIC_ROUTER_BASE_DIR}" "${node}:/galactic/resources/galactic-router/base/base"
  docker cp "${GALACTIC_ROUTER_TENANT_DIR}" "${node}:/galactic/resources/galactic-router/base/tenant"
}

# copy_router_control_config NODE copies config/router/{base,tenant-control}
# onto NODE, nested under resources/galactic-control/iad/ so the
# tenant-control overlay's "../base" resource reference resolves. Its node
# affinity (route-reflector role, control node only) applies as-is; the
# lab only needs to patch in the image and BGP address/port.
copy_router_control_config() {
  local node="$1"
  docker cp "${GALACTIC_ROUTER_BASE_DIR}" "${node}:/galactic/resources/galactic-control/iad/base"
  docker cp "${GALACTIC_ROUTER_TENANT_CONTROL_DIR}" "${node}:/galactic/resources/galactic-control/iad/tenant-control"
}

# apply_galactic_router applies the site's galactic-router overlay (DaemonSet
# + BGP CRDs). Shared by all three sites; iad layers its route-reflector on
# top after calling this. NADs and test workloads live under resources/ns50/
# and are applied by deploy-ns50.sh.
apply_galactic_router() {
  local node="$1" site="$2"
  apply_k "${node}" "/galactic/resources/galactic-router/${site}/"
}

for site in dfw sjc; do
  node=$(control_plane "${site}")
  echo "Applying galactic-router/${site} to ${node}..."
  copy_to "${node}" galactic-router
  copy_router_config "${node}"
  apply_galactic_router "${node}" "${site}"
done

# iad-control-plane: galactic-router resources were copied by deploy-fabric.sh —
# apply galactic-router and control overlays.
node=$(control_plane iad)
echo "Applying galactic-router/iad to ${node}..."
copy_router_config "${node}"
copy_router_control_config "${node}"
apply_galactic_router "${node}" iad
apply_k "${node}" /galactic/resources/galactic-control/iad/

echo "Done."
