#!/bin/bash
# deploy-looking-glass.sh — Enable the Looking Glass service on dfw for
# verify:looking-glass, in the enabling order of
# docs/fabric-api/operations.md#enabling-aggregate-probe-budgets (resources/looking-glass/):
#
#   1. fabric-router sidecars verify probe permits (restarts FRR)
#   2. the gateway enforces the cell's aggregate budgets
#   3. fabric-router sidecars require permits (restarts FRR)
#   4. the gateway serves the service, then the switch turns it on
#
# and issues the service certificates the suite authenticates with
# (resources/looking-glass/pki/services.yaml). Needs deploy:fabric-api.
# undeploy-looking-glass.sh reverses it.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

site=dfw
node=$(control_plane "${site}")
kc=$(site_kubeconfig "${site}")
trap 'rm -f "${kc}"' EXIT
k() { kubectl --kubeconfig "${kc}" "$@"; }

if ! k -n galactic-system get deployment fabric-api-gateway >/dev/null; then
  echo "${site}: no fabric-api gateway; run deploy:fabric-api first" >&2
  exit 1
fi

# fabric_router STEP applies resources/looking-glass/fabric-router/dfw/STEP
# on the control-plane node and waits for every fabric-router pod and its
# underlay sessions.
fabric_router() {
  copy_to "${node}" fabric-router
  copy_fabric_config "${node}"
  copy_to "${node}" looking-glass
  apply_k "${node}" "/galactic/resources/looking-glass/fabric-router/${site}/$1/"
  k -n galactic-system rollout status daemonset/fabric-router --timeout=300s
}

gateway() {
  k apply -k "${RESOURCES_DIR}/looking-glass/gateway/${site}/$1/"
  k -n galactic-system rollout status deployment/fabric-api-gateway --timeout=180s
}

echo "${site}: 1/4 nodes verify probe permits"
fabric_router permits
echo "${site}: 2/4 gateway enforces aggregate budgets"
gateway budgets
echo "${site}: 3/4 nodes require probe permits"
fabric_router require
echo "${site}: 4/4 gateway serves the Looking Glass service"
gateway service

sed "s/CELL_NAME/${site}/g" "${RESOURCES_DIR}/looking-glass/pki/services.yaml" | k apply -f -
k -n galactic-system wait --for condition=Ready --timeout=120s \
  certificate/lg-qualify-looking-glass certificate/lg-qualify-unlisted certificate/lg-qualify-other-cell

k -n galactic-system patch configmap fabric-api-service --type merge -p '{"data":{"service":"enabled"}}'
echo "Done. The new gateway leader admits no probe for its 125-second recovery hold."
