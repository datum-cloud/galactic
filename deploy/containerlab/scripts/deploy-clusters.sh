#!/bin/bash
# Create independent clusters without concurrent writes to the user's kubeconfig.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"
create_site() {
  local site=$1
  kind create cluster --name "${site}" --config "${SCRIPT_DIR}/../../../bin/lab-node-cache/${site}.yaml" \
    --image kindest/node:galactic --kubeconfig "${site}.kubeconfig"
}
parallel_sites create_site dfw sjc iad
# Preserve Kind's normal host contexts, merging only after all concurrent
# creators have finished writing their separate kubeconfigs.
for site in dfw sjc iad; do
  kind export kubeconfig --name "${site}"
done
