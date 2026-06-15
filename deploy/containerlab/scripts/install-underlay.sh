#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RESOURCES_DIR="${SCRIPT_DIR}/../resources"

apply() {
  local node="$1"
  local site="$2"
  echo "Applying underlay/${site} to ${node}..."
  docker cp "${RESOURCES_DIR}/underlay" "${node}:/galactic/resources/"
  docker exec "${node}" kubectl apply -k /galactic/resources/underlay/${site}/
}

apply iad-control-plane   iad
apply iad-control-plane   iad-rr
apply sjc-control-plane   sjc
apply dfw-control-plane   dfw

echo "Done."
