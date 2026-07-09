#!/bin/bash
# deploy-tenant.sh — Install tenant DaemonSets and BGP resources for every
# site. iad additionally layers route-reflector and BGP control resources
# on top.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# The router DaemonSet base and the production tenant/tenant-control
# overlays (node affinity keeping each role on the right nodes) live in
# config/router/{base,tenant,tenant-control}/ (shared with production;
# the shared RBAC/ServiceAccount aren't needed here).
# resources/tenant/base/ and resources/control/tenant/iad/ build on the
# copied tenant/tenant-control overlays and patch in only the lab-only
# image and env vars. Dirs are copied onto the node at deploy time nested
# under each consuming overlay's own root (kustomize requires resources in
# or below the overlay root) rather than duplicated in the repo.
GALACTIC_ROUTER_BASE_DIR=$(cd "${SCRIPT_DIR}/../../../config/router/base" && pwd)
GALACTIC_ROUTER_TENANT_DIR=$(cd "${SCRIPT_DIR}/../../../config/router/tenant" && pwd)
GALACTIC_ROUTER_TENANT_CONTROL_DIR=$(cd "${SCRIPT_DIR}/../../../config/router/tenant-control" && pwd)

# copy_router_config NODE copies config/router/{base,tenant} onto NODE,
# nested under resources/tenant/base/ so the tenant overlay's "../base"
# resource reference resolves.
copy_router_config() {
  local node="$1"
  docker cp "${GALACTIC_ROUTER_BASE_DIR}" "${node}:/galactic/resources/tenant/base/base"
  docker cp "${GALACTIC_ROUTER_TENANT_DIR}" "${node}:/galactic/resources/tenant/base/tenant"
}

# copy_router_control_config NODE copies config/router/{base,tenant-control}
# onto NODE, nested under resources/control/tenant/iad/ so the
# tenant-control overlay's "../base" resource reference resolves. Its node
# affinity (route-reflector role, control node only) applies as-is; the
# lab only needs to patch in the image and BGP address/port.
copy_router_control_config() {
  local node="$1"
  docker cp "${GALACTIC_ROUTER_BASE_DIR}" "${node}:/galactic/resources/control/tenant/iad/base"
  docker cp "${GALACTIC_ROUTER_TENANT_CONTROL_DIR}" "${node}:/galactic/resources/control/tenant/iad/tenant-control"
}

# apply_tenant applies the site's tenant DaemonSet overlay. Shared by all
# three sites; iad layers its route-reflector and extra BGP resources on
# top after calling this. VPC NADs live under resources/vpc/ and are
# applied by deploy-vpc.sh.
apply_tenant() {
  local node="$1" site="$2"
  apply_k "${node}" "/galactic/resources/tenant/${site}/"
}

for site in dfw sjc; do
  node=$(control_plane "${site}")
  echo "Applying tenant/${site} to ${node}..."
  copy_to "${node}" tenant
  copy_router_config "${node}"
  copy_to "${node}" bgp/tenant /galactic/resources/bgp-tenant/
  apply_tenant "${node}" "${site}"
  apply_f "${node}" "/galactic/resources/bgp-tenant/${site}/"
done

# iad-control-plane: tenant/bgp resources were copied by deploy-fabric.sh — apply tenant, control, and bgp.
node=$(control_plane iad)
echo "Applying tenant/iad to ${node}..."
copy_router_config "${node}"
copy_router_control_config "${node}"
apply_tenant "${node}" iad
apply_k "${node}" /galactic/resources/control/tenant/iad/
apply_f "${node}" /galactic/resources/bgp-tenant/iad/
apply_f "${node}" /galactic/resources/bgp-control/tenant/iad/

echo "Done."
