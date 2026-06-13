#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RESOURCES_DIR="${SCRIPT_DIR}/../resources"
COSMOS_DIR="${SCRIPT_DIR}/../build/cosmos"

apply_overlay() {
  local node="$1"
  local site="$2"
  echo "Applying overlay/${site} to ${node}..."
  docker cp "${RESOURCES_DIR}/overlay" "${node}:/galactic/resources/"
  docker exec "${node}" kubectl apply -k /galactic/resources/overlay/${site}/
  echo "Applying bgp/${site} to ${node}..."
  docker cp "${RESOURCES_DIR}/bgp/${site}" "${node}:/galactic/resources/bgp-${site}/"
  docker exec "${node}" kubectl apply -f /galactic/resources/bgp-${site}/
}

deploy_cosmos() {
  local node="$1"
  echo "Deploying cosmos operator to ${node}..."
  # Copy the entire config/ directory so that the kustomization's ../crd reference resolves
  docker cp "${COSMOS_DIR}/config" "${node}:/galactic/resources/cosmos-config/"
  # Use locally built image; patch imagePullPolicy to Never
  docker exec "${node}" kubectl apply -k /galactic/resources/cosmos-config/deploy/
  docker exec "${node}" kubectl patch daemonset bgp \
    -n bgp-system \
    --type='json' \
    -p='[{"op":"replace","path":"/spec/template/spec/containers/0/image","value":"cosmos:latest"},{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Never"}]'
}

apply_overlay dfw-control-plane dfw
apply_overlay sjc-control-plane sjc
apply_overlay iad-control-plane iad

deploy_cosmos dfw-control-plane
deploy_cosmos sjc-control-plane
deploy_cosmos iad-control-plane

echo "Done."
