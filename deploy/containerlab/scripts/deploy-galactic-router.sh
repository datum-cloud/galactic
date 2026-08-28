#!/bin/bash
# deploy-galactic-router.sh — Install galactic-router DaemonSets and BGP resources
# for every site. iad additionally layers its route-reflector overlay on top.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# The router DaemonSet base (config/galactic-router/base/ -- role-agnostic,
# not applied directly, shared with production) and the production
# default/rr overlays (config/galactic-router/overlays/{default,rr}/, each
# independently patching ../../base into its own role) live under
# config/galactic-router/ (the shared RBAC/ServiceAccount aren't needed
# here).
# resources/galactic-router/base/ and resources/galactic-control/iad/
# build on the copied base/default or base/rr dirs and patch in only the
# lab-only image and env vars. Dirs are copied onto the node at deploy time
# nested under each consuming overlay's own root (kustomize requires resources
# in or below the overlay root) rather than duplicated in the repo.
GALACTIC_ROUTER_BASE_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-router/base" && pwd)
GALACTIC_ROUTER_DEFAULT_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-router/overlays/default" && pwd)
GALACTIC_ROUTER_RR_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-router/overlays/rr" && pwd)
# config/galactic-gateway/base is the edge XDP NAT+LB gateway's own
# single-container pod base -- self-contained, unlike
# config/galactic-router/{base,overlays/default,overlays/rr}, so no matching
# config/galactic-router/base copy is needed alongside it the way copy_router_config/
# copy_router_control_config need one. galactic-router itself reaches
# iad-gateway1/iad-gateway2 via copy_router_config's own DaemonSet below,
# whose affinity (galactic.datumapis.com/galactic=router) already matches
# those nodes' labels (node_files/iad/config.yaml) -- no separate copy or
# apply step is needed for it here.
GALACTIC_GATEWAY_BASE_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-gateway/base" && pwd)

# copy_router_config NODE copies config/galactic-router/base and
# config/galactic-router/overlays/default onto NODE, nested under
# resources/galactic-router/base/ at the *same relative depth* as in
# config/ (base/base/, base/overlays/default/) -- required because
# overlays/default/kustomization.yaml's own "../../base" reference is copied
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
  docker cp "${GALACTIC_ROUTER_DEFAULT_DIR}" "${node}:/galactic/resources/galactic-router/base/overlays/default"
}

# copy_router_control_config NODE copies config/galactic-router/base and
# config/galactic-router/overlays/rr onto NODE, nested under
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
  docker cp "${GALACTIC_ROUTER_RR_DIR}" "${node}:/galactic/resources/galactic-control/iad/overlays/rr"
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
# iad-gateway2, each running its own single-container galactic-gateway
# pod instance (config/galactic-gateway/base's per-node-unique
# GALACTIC_GATEWAY_SRV6_ADDRESS -- see config/galactic-gateway/base/kustomization.
# yaml's doc comment) -- galactic-router already reached these nodes above,
# as its own independent DaemonSet, before this section ever runs.
# galactic-gateway's own ServiceAccount/ClusterRole
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
