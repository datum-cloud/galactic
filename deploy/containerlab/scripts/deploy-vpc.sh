#!/bin/bash
# deploy-vpc.sh — Deploy vpc10/vpc20 NADs and test workloads to every
# cluster (one pod per VPC per site, 6 pods total) for cross-site and
# cross-VPC connectivity verification.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Copying vpc to ${node}..."
  copy_to "${node}" vpc
  echo "Applying vpc/${site} to ${node}..."
  ensure_namespace "${node}" vpc
  apply_k "${node}" "/galactic/resources/vpc/${site}/"
done

echo "Done."
