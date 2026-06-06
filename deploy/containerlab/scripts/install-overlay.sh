#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RESOURCES_DIR="${SCRIPT_DIR}/../resources"

apply() {
  local node="$1"
  local site="$2"
  echo "Applying overlay/${site} to ${node}..."
  docker cp "${RESOURCES_DIR}/overlay" "${node}:/galactic/resources/"
  docker exec "${node}" kubectl apply -k /galactic/resources/overlay/${site}/
  echo "Applying cosmos/${site} to ${node}..."
  docker cp "${RESOURCES_DIR}/cosmos" "${node}:/galactic/resources/"
  docker exec "${node}" kubectl apply -k /galactic/resources/cosmos/${site}/
}

apply iad-control-plane iad
apply sjc-control-plane sjc

echo "Done."
