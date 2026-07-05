#!/bin/bash
# deploy-vpc.sh — Deploy vpc10 and vpc20 test workloads to every cluster
# (one pod per VPC per site, 6 pods total) for cross-site and cross-VPC
# connectivity verification.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Copying vpc/${site} to ${node}..."
  copy_to "${node}" "vpc/${site}" "/galactic/resources/vpc-${site}/"
  for vpc in vpc10 vpc20; do
    echo "Applying ${vpc}/${site} to ${node}..."
    apply_f "${node}" "/galactic/resources/vpc-${site}/${vpc}.yaml"
  done
done

echo "Done."
