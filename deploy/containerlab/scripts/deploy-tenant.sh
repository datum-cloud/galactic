#!/bin/bash
# deploy-tenant.sh — Install tenant DaemonSets, NAD, and BGP resources for
# every site. iad additionally layers route-reflector and BGP control
# resources on top.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# apply_tenant creates the vpc namespace and applies the site's NADs (one
# per VPC) and tenant DaemonSet overlay. Shared by all three sites; iad
# layers its route-reflector and extra BGP resources on top after calling
# this.
apply_tenant() {
  local node="$1" site="$2"
  ensure_namespace "${node}" vpc
  apply_f "${node}" "/galactic/resources/tenant/${site}/nad-vpc10.yaml"
  apply_f "${node}" "/galactic/resources/tenant/${site}/nad-vpc20.yaml"
  apply_k "${node}" "/galactic/resources/tenant/${site}/"
}

for site in dfw sjc; do
  node=$(control_plane "${site}")
  echo "Applying tenant/${site} to ${node}..."
  copy_to "${node}" tenant
  copy_to "${node}" bgp/tenant /galactic/resources/bgp-tenant/
  apply_tenant "${node}" "${site}"
  apply_f "${node}" "/galactic/resources/bgp-tenant/${site}/"
done

# iad-control-plane: resources were copied by deploy-fabric.sh — apply tenant, control, and bgp.
node=$(control_plane iad)
echo "Applying tenant/iad to ${node}..."
apply_tenant "${node}" iad
apply_f "${node}" /galactic/resources/control/tenant/iad/
apply_f "${node}" /galactic/resources/bgp-tenant/iad/
apply_f "${node}" /galactic/resources/bgp-control/tenant/iad/

echo "Done."
