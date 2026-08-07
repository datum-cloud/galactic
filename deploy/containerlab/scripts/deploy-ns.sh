#!/bin/bash
# deploy-ns.sh — Deploy a test VPC namespace, NADs, and netshoot workloads
# to the given sites.
#
# Usage: deploy-ns.sh <namespace> <site> [site...]
#   deploy-ns.sh ns10 dfw sjc iad   # 3-site
#   deploy-ns.sh ns30 dfw          # single-site
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $(basename "$0") <namespace> <site> [site...]" >&2
  exit 1
fi

NS="$1"
shift

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

for site in "$@"; do
  node=$(control_plane "${site}")
  echo "Copying ${NS} to ${node}..."
  # tenants/base/ (the shared Namespace + netshoot Deployment every tenant's
  # own base/kustomization.yaml references via "../../base") has to land
  # alongside it -- each deploy:nsNN run is independent and can't assume
  # another one already put it there.
  copy_to "${node}" tenants/base
  copy_to "${node}" "tenants/${NS}"
  echo "Applying ${NS}/${site} to ${node}..."
  apply_k "${node}" "/galactic/resources/tenants/${NS}/${site}/"
done

echo "Done."
