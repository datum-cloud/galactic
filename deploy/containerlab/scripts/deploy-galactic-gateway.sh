#!/bin/bash
# deploy-galactic-gateway.sh — Install galactic-gateway on every edge node, one
# NetworkGateway per node, and each site's ns60 NetworkRules and
# ServiceVIPBindings (resources/galactic-gateway/). Requires deploy:system
# (the gateway's RBAC/ServiceAccount), deploy:images (galactic-gateway:latest
# on every edge node), deploy:galactic-router (each node's BGPRouter, which
# the gateway advertises its VIPs through), and deploy:ns60 (the backends the
# ServiceVIPBindings bind).
#
# The gateway shares each edge node's uplinks with the egress shard through
# the node's XDP dispatcher, so the two can be deployed in either order.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

GALACTIC_GATEWAY_BASE_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-gateway/base" && pwd)

declare -A GATEWAY_NODES=(
  [dfw]="dfw-worker2 dfw-worker3"
  [sjc]="sjc-worker2"
  [iad]="iad-worker2"
)

# copy_gateway_config NODE copies config/galactic-gateway/base onto NODE as
# resources/galactic-gateway/base/gateway/, which the lab base names as its
# resource. rm -rf first: docker cp nests SRC inside an existing DEST dir
# rather than replacing it.
copy_gateway_config() {
  local node="$1"
  docker exec "${node}" rm -rf /galactic/resources/galactic-gateway/base/gateway
  docker cp "${GALACTIC_GATEWAY_BASE_DIR}" "${node}:/galactic/resources/galactic-gateway/base/gateway"
}

# A VIP route verify-gateway-ingress.sh pins on a transit router is removed
# when the check exits, unless it was killed outright. Clear any left over
# from such a run, so the transit forwards by BGP again.
"${SCRIPT_DIR}/verify-gateway-ingress.sh" --unpin

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Applying galactic-gateway/${site} to ${node}..."
  copy_to "${node}" galactic-gateway
  copy_gateway_config "${node}"
  apply_k "${node}" "/galactic/resources/galactic-gateway/${site}/"
  for gw in ${GATEWAY_NODES[${site}]}; do
    docker exec "${node}" kubectl -n galactic-system rollout status daemonset "galactic-gateway-${gw}" --timeout=180s
  done
  # Ready means the engine loaded every rule and advertised it, Accepted that
  # the rule found a gateway, and Bound that the backend's node rewrites the
  # VIP for it.
  docker exec "${node}" kubectl -n galactic-system wait networkgateway --all \
    --for=condition=Ready --timeout=120s
  docker exec "${node}" kubectl -n galactic-system wait networkrule --all \
    --for=condition=Accepted --timeout=60s
  docker exec "${node}" kubectl -n galactic-system wait servicevipbinding --all \
    --for=condition=Bound --timeout=60s
done

echo "Done."
