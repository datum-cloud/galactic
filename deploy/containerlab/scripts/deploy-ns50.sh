#!/bin/bash
# deploy-ns50.sh — Deploy ns50 namespace, NADs, and webapp workloads to
# every cluster for cross-site connectivity verification.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Copying ns50 to ${node}..."
  copy_to "${node}" ns50
  echo "Applying ns50/${site} to ${node}..."
  apply_k "${node}" "/galactic/resources/ns50/${site}/"
done

echo "Done."
