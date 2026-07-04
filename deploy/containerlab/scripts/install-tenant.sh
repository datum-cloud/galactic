#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RESOURCES_DIR="${SCRIPT_DIR}/../resources"

apply_tenant() {
  local node="$1"
  local site="$2"
  echo "Applying tenant/${site} to ${node}..."
  docker cp "${RESOURCES_DIR}/tenant" "${node}:/galactic/resources/"
  docker cp "${RESOURCES_DIR}/bgp/tenant" "${node}:/galactic/resources/bgp-tenant/"
  docker exec "${node}" sh -c 'kubectl create namespace vpc --dry-run=client -o yaml | kubectl apply -f -'
  docker exec "${node}" kubectl apply -f /galactic/resources/tenant/${site}/nad.yaml
  docker exec "${node}" kubectl apply -k /galactic/resources/tenant/${site}/daemonset/
  docker exec "${node}" kubectl apply -f /galactic/resources/bgp-tenant/${site}/
}

apply_tenant dfw-control-plane dfw
apply_tenant sjc-control-plane sjc

# iad-control-plane: resources were copied by install-fabric.sh — apply tenant, control, and bgp.
echo "Applying tenant/iad to iad-control-plane..."
docker exec iad-control-plane sh -c 'kubectl create namespace vpc --dry-run=client -o yaml | kubectl apply -f -'
docker exec iad-control-plane kubectl apply -f /galactic/resources/tenant/iad/nad.yaml
docker exec iad-control-plane kubectl apply -k /galactic/resources/tenant/iad/daemonset/
docker exec iad-control-plane kubectl apply -f /galactic/resources/control/tenant/iad/
docker exec iad-control-plane kubectl apply -f /galactic/resources/bgp-tenant/iad/
docker exec iad-control-plane kubectl apply -f /galactic/resources/bgp-control/tenant/iad/

echo "Done."
