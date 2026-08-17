#!/bin/bash
# deploy-galactic-router.sh — Install galactic-router DaemonSets and BGP resources
# for every site. iad additionally layers its route-reflector overlay on top.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# The router DaemonSet base and the production tenant/tenant-control
# overlays (node affinity keeping each role on the right nodes) live in
# config/galactic-router/{base,tenant,tenant-control}/ (shared with production;
# the shared RBAC/ServiceAccount aren't needed here).
# resources/galactic-router/base/ and resources/galactic-control/iad/
# build on the copied tenant/tenant-control overlays and patch in only the
# lab-only image and env vars. Dirs are copied onto the node at deploy time
# nested under each consuming overlay's own root (kustomize requires resources
# in or below the overlay root) rather than duplicated in the repo.
GALACTIC_ROUTER_BASE_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-router/base" && pwd)
GALACTIC_ROUTER_TENANT_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-router/tenant" && pwd)
GALACTIC_ROUTER_TENANT_CONTROL_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-router/tenant-control" && pwd)
# config/galactic-gateway/base is the edge XDP NAT+LB gateway's own two-container
# pod base (galactic-router + galactic-gateway) -- self-contained, unlike
# config/galactic-router/{tenant,tenant-control}, so no matching
# config/galactic-router/base copy is needed alongside it the way copy_router_config/
# copy_router_control_config need one.
GALACTIC_GATEWAY_BASE_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-gateway/base" && pwd)

# copy_router_config NODE copies config/galactic-router/{base,tenant} onto NODE,
# nested under resources/galactic-router/base/ so the overlay's "../base"
# resource reference resolves. rm -rf first: like deploy-cni.sh's
# GALACTIC_CNI_DIR copy, docker cp nests SRC inside an already-existing
# DEST dir instead of overwriting it, so a rerun against an
# already-provisioned node would silently keep serving the prior copy
# from underneath the new one -- kubectl would then report the DaemonSet
# "unchanged" even after a real manifest edit.
copy_router_config() {
  local node="$1"
  docker exec "${node}" rm -rf /galactic/resources/galactic-router/base/base /galactic/resources/galactic-router/base/tenant
  docker cp "${GALACTIC_ROUTER_BASE_DIR}" "${node}:/galactic/resources/galactic-router/base/base"
  docker cp "${GALACTIC_ROUTER_TENANT_DIR}" "${node}:/galactic/resources/galactic-router/base/tenant"
}

# copy_router_control_config NODE copies config/galactic-router/{base,tenant-control}
# onto NODE, nested under resources/galactic-control/iad/ so the
# tenant-control overlay's "../base" resource reference resolves. Its node
# affinity (route-reflector role, control node only) applies as-is; the
# lab only needs to patch in the image and BGP address/port. rm -rf first
# -- see copy_router_config's comment.
copy_router_control_config() {
  local node="$1"
  docker exec "${node}" rm -rf /galactic/resources/galactic-control/iad/base /galactic/resources/galactic-control/iad/tenant-control
  docker cp "${GALACTIC_ROUTER_BASE_DIR}" "${node}:/galactic/resources/galactic-control/iad/base"
  docker cp "${GALACTIC_ROUTER_TENANT_CONTROL_DIR}" "${node}:/galactic/resources/galactic-control/iad/tenant-control"
}

# copy_router_gateway_config NODE copies config/galactic-gateway/base onto NODE,
# nested under resources/galactic-gateway/base/ so that overlay's
# "gateway" resource reference resolves. Each per-node overlay
# (iad-gateway1/, iad-gateway2/) references ../base, so this is only
# copied once regardless of how many gateway nodes exist. rm -rf first --
# see copy_router_config's comment.
copy_router_gateway_config() {
  local node="$1"
  docker exec "${node}" rm -rf /galactic/resources/galactic-gateway/base/gateway
  docker cp "${GALACTIC_GATEWAY_BASE_DIR}" "${node}:/galactic/resources/galactic-gateway/base/gateway"
}

# apply_galactic_router applies the site's galactic-router overlay (DaemonSet
# + BGP CRDs). Shared by all three sites; iad layers its route-reflector on
# top after calling this. NADs and test workloads live under
# resources/tenants/ns10/ and are applied by deploy-ns.sh.
apply_galactic_router() {
  local node="$1" site="$2"
  apply_k "${node}" "/galactic/resources/galactic-router/${site}/"
}

for site in dfw sjc; do
  node=$(control_plane "${site}")
  echo "Applying galactic-router/${site} to ${node}..."
  docker exec "${node}" rm -rf /galactic/resources/galactic-router
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

# iad's gateway-role canary: two dedicated nodes, iad-gateway1/
# iad-gateway2, each running its own two-container
# pod instance (config/galactic-gateway/base's per-node-unique
# GALACTIC_GATEWAY_SRV6_ADDRESS -- see config/galactic-gateway/base/kustomization.
# yaml's doc comment). galactic-gateway's own ServiceAccount/ClusterRole
# (config/galactic-gateway/{serviceaccount,rbac}.yaml, already copied onto this
# node by deploy-system.sh's copy_config) must be applied once before the
# per-node overlays below, same as galactic-cni/galactic-router's RBAC is
# applied by deploy-system.sh itself rather than by this script.
echo "Applying galactic-gateway RBAC to ${node}..."
apply_f "${node}" /galactic/config/galactic-gateway/serviceaccount.yaml
apply_f "${node}" /galactic/config/galactic-gateway/rbac.yaml

echo "Applying galactic-gateway/iad to ${node}..."
docker exec "${node}" rm -rf /galactic/resources/galactic-gateway
copy_to "${node}" galactic-gateway
copy_router_gateway_config "${node}"
apply_k "${node}" /galactic/resources/galactic-gateway/iad/

echo "Done."
