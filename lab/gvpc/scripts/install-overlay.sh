#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RESOURCES_DIR="${SCRIPT_DIR}/../resources"

apply() {
  local node="$1"
  local file="$2"
  echo "Applying ${file##*/} to ${node}..."
  docker exec -i "${node}" kubectl apply -f - < "${file}"
}

apply iad-control-plane "${RESOURCES_DIR}/iad-overlay.k8s.yaml"
apply sjc-control-plane "${RESOURCES_DIR}/sjc-overlay.k8s.yaml"

echo "Done."
