#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RESOURCES_DIR="${SCRIPT_DIR}/../resources"

apply_tenant() {
  local node="$1"
  local site="$2"
  echo "Applying tenant/${site} to ${node}..."
  docker cp "${RESOURCES_DIR}/tenant" "${node}:/galactic/resources/"
  # Apply the VPC NAD so pods can attach to the galactic network.
  # Must be in the vpc namespace (tenant kustomization targets galactic-system).
  docker exec "${node}" sh -c 'kubectl create namespace vpc --dry-run=client -o yaml | kubectl apply -f -'
  docker exec "${node}" kubectl apply -f /galactic/resources/tenant/${site}/nad.yaml
  docker exec "${node}" kubectl apply -k /galactic/resources/tenant/${site}/
  echo "Applying bgp/${site} to ${node}..."
  docker cp "${RESOURCES_DIR}/bgp/${site}" "${node}:/galactic/resources/bgp-${site}/"
  docker exec "${node}" kubectl apply -f /galactic/resources/bgp-${site}/
}

apply_tenant dfw-control-plane dfw
apply_tenant sjc-control-plane sjc
apply_tenant iad-control-plane iad
# iad-control tenant DaemonSet is included in iad's kustomization (resources: - control);
# only apply its BGP CRDs separately
echo "Applying bgp/iad-control to iad-control-plane..."
docker cp "${RESOURCES_DIR}/bgp/iad-control" "iad-control-plane:/galactic/resources/bgp-iad-control/"
docker exec iad-control-plane kubectl apply -f /galactic/resources/bgp-iad-control/

echo "Done."
