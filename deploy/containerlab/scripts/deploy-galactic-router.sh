#!/bin/bash
# deploy-galactic-router.sh — Install galactic-router DaemonSets and BGP resources
# for every site. iad additionally layers its route-reflector overlay on top.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# The router DaemonSet base (config/galactic-router/base/ -- role-agnostic,
# not applied directly, shared with production) and the production
# router/control overlays (config/galactic-router/overlays/{router,control}/, each
# independently patching ../../base into its own role) live under
# config/galactic-router/ (the shared RBAC/ServiceAccount aren't needed
# here).
# resources/galactic-router/base/ and resources/galactic-control/iad/
# build on the copied base/router or base/control dirs and patch in only the
# lab-only image and env vars. Dirs are copied onto the node at deploy time
# nested under each consuming overlay's own root (kustomize requires resources
# in or below the overlay root) rather than duplicated in the repo.
GALACTIC_ROUTER_BASE_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-router/base" && pwd)
GALACTIC_ROUTER_DEFAULT_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-router/overlays/router" && pwd)
GALACTIC_ROUTER_RR_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-router/overlays/control" && pwd)

# copy_router_config NODE copies config/galactic-router/base and
# config/galactic-router/overlays/router onto NODE, nested under
# resources/galactic-router/base/ at the *same relative depth* as in
# config/ (base/base/, base/overlays/router/) -- required because
# overlays/router/kustomization.yaml's own "../../base" reference is copied
# verbatim, unmodified, so the local copy has to resolve at the same two
# levels up or that reference points outside the tree entirely. rm -rf
# first: like deploy-cni.sh's GALACTIC_CNI_DIR copy, docker cp nests SRC
# inside an already-existing DEST dir instead of overwriting it, so a
# rerun against an already-provisioned node would silently keep serving
# the prior copy from underneath the new one -- kubectl would then report
# the DaemonSet "unchanged" even after a real manifest edit.
copy_router_config() {
  local node="$1"
  docker exec "${node}" rm -rf /galactic/resources/galactic-router/base/base /galactic/resources/galactic-router/base/overlays
  docker exec "${node}" mkdir -p /galactic/resources/galactic-router/base/overlays
  docker cp "${GALACTIC_ROUTER_BASE_DIR}" "${node}:/galactic/resources/galactic-router/base/base"
  docker cp "${GALACTIC_ROUTER_DEFAULT_DIR}" "${node}:/galactic/resources/galactic-router/base/overlays/router"
}

# copy_router_control_config NODE copies config/galactic-router/base and
# config/galactic-router/overlays/control onto NODE, nested under
# resources/galactic-control/iad/ at the same relative depth as in
# config/, for the same reason copy_router_config's comment explains.
# Its node affinity (route-reflector role, control node only) applies
# as-is; the lab only needs to patch in the image and BGP address/port.
# rm -rf first -- see copy_router_config's comment.
copy_router_control_config() {
  local node="$1"
  docker exec "${node}" rm -rf /galactic/resources/galactic-control/iad/base /galactic/resources/galactic-control/iad/overlays
  docker exec "${node}" mkdir -p /galactic/resources/galactic-control/iad/overlays
  docker cp "${GALACTIC_ROUTER_BASE_DIR}" "${node}:/galactic/resources/galactic-control/iad/base"
  docker cp "${GALACTIC_ROUTER_RR_DIR}" "${node}:/galactic/resources/galactic-control/iad/overlays/control"
}

# apply_galactic_router applies the site's galactic-router overlay (DaemonSet
# + BGP CRDs). The DaemonSet's affinity
# (galactic.datumapis.com/galactic=router) matches the site's compute node
# and its edge nodes alike, and the overlay carries a BGPRouter and
# route-reflector BGPPeer for each of them. Shared by all three sites; iad layers its route-reflector on
# top after calling this. NADs and test workloads live under
# resources/tenants/ns10/ and are applied by deploy-ns.sh.
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
# apply galactic-router and the route-reflector overlay. iad-worker3 is the
# lab's single EVPN reflector; every other site's galactic-router peers with
# it.
node=$(control_plane iad)
echo "Applying galactic-router/iad to ${node}..."
copy_router_config "${node}"
copy_router_control_config "${node}"
apply_galactic_router "${node}" iad
apply_k "${node}" /galactic/resources/galactic-control/iad/

echo "Done."
