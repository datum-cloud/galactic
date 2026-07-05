#!/bin/bash
# deploy-system.sh — Apply the galactic-system namespace and shared RBAC
# (galactic-cni, galactic-router) to every cluster.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Applying system to ${node}..."
  copy_to "${node}" system
  apply_f "${node}" /galactic/resources/system/
done

echo "Done."
