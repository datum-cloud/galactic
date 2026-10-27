#!/bin/bash
# undeploy-looking-glass.sh — Switch the Looking Glass service off on dfw
# and roll deploy-looking-glass.sh back in the documented reverse order
# (docs/fabric-api/operations.md#upgrade-and-rollback):
#
#   1. switch the service off
#   2. remove components/service (its ConfigMap and Role go with it)
#   3. nodes stop requiring permits (restarts FRR)
#   4. remove the aggregate budgets
#   5. nodes stop verifying permits (restarts FRR)
#
# and deletes the suite's service certificates. It ends on the lab's
# ordinary fabric-router and gateway overlays.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

site=dfw
node=$(control_plane "${site}")
kc=$(site_kubeconfig "${site}")
trap 'rm -f "${kc}"' EXIT
k() { kubectl --kubeconfig "${kc}" "$@"; }

echo "${site}: 1/5 switch the service off"
k -n galactic-system patch configmap fabric-api-service --type merge \
  -p '{"data":{"service":"disabled"}}' 2>/dev/null || true

echo "${site}: 2/5 remove the service"
k apply -k "${RESOURCES_DIR}/looking-glass/gateway/${site}/budgets/"
k -n galactic-system delete configmap/fabric-api-service \
  role/fabric-api-gateway-service rolebinding/fabric-api-gateway-service --ignore-not-found
k -n galactic-system rollout status deployment/fabric-api-gateway --timeout=180s

copy_to "${node}" fabric-router
copy_fabric_config "${node}"
copy_to "${node}" looking-glass
echo "${site}: 3/5 nodes stop requiring permits"
apply_k "${node}" "/galactic/resources/looking-glass/fabric-router/${site}/permits/"
k -n galactic-system rollout status daemonset/fabric-router --timeout=300s

echo "${site}: 4/5 remove the aggregate budgets"
k apply -k "${RESOURCES_DIR}/fabric-api/gateway/${site}/"
k -n galactic-system rollout status deployment/fabric-api-gateway --timeout=180s

echo "${site}: 5/5 nodes stop verifying permits"
apply_k "${node}" "/galactic/resources/fabric-router/${site}/"
k -n galactic-system delete role/fabric-api-node-lease rolebinding/fabric-api-node-lease --ignore-not-found
k -n galactic-system rollout status daemonset/fabric-router --timeout=300s

k -n galactic-system delete certificate,secret -l app.kubernetes.io/part-of=lg-qualify --ignore-not-found
echo "Done."
