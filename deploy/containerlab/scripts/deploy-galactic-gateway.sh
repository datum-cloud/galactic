#!/bin/bash
# deploy-galactic-gateway.sh — Install galactic-gateway on every edge node, one
# NetworkGateway per node, and each site's ns60 NetworkRules
# (resources/galactic-gateway/). Requires deploy:system
# (the gateway's RBAC/ServiceAccount), deploy:images (galactic-gateway:latest
# on every edge node), deploy:galactic-router (each node's BGPRouter, which
# the gateway advertises its VIPs through), and deploy:ns60 (the backends and
# VPCAttachments the rules select). Each backend's node writes its own
# ServiceVIPBindings from the rules.
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

# NS60_BINDINGS is how many ServiceVIPBindings each site's backend node
# writes: one per rule (TCP and UDP) per ns60 backend.
NS60_BINDINGS=4

# GENERATED_BINDINGS selects the ServiceVIPBindings galactic-router writes
# from the NetworkRules. Any other binding in galactic-system is stale.
GENERATED_BINDINGS=app.kubernetes.io/managed-by=galactic-router

# wait_bindings NODE COUNT TIMEOUT waits up to TIMEOUT seconds for exactly
# COUNT generated ServiceVIPBindings to exist in galactic-system.
wait_bindings() {
  local node="$1" want="$2" deadline=$((SECONDS + $3)) have
  while :; do
    have=$(docker exec "${node}" kubectl -n galactic-system get servicevipbindings \
      -l "${GENERATED_BINDINGS}" -o name | wc -l)
    [ "${have}" -eq "${want}" ] && return 0
    if [ "${SECONDS}" -ge "${deadline}" ]; then
      echo "error: ${node}: ${have} of ${want} generated ServiceVIPBindings after $3s" >&2
      return 1
    fi
    sleep 2
  done
}

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Applying galactic-gateway/${site} to ${node}..."
  copy_to "${node}" galactic-gateway
  copy_gateway_config "${node}"
  apply_k "${node}" "/galactic/resources/galactic-gateway/${site}/"
  # The lab once hand-wrote each site's bindings (ns60-tcp-backend,
  # ns60-udp-backend). kubectl apply -k does not prune, so on a lab deployed
  # before that changed they survive without the spec.vpcRef a binding now
  # needs, report BindFailed, and would count toward the wait below. Delete
  # every binding galactic-router did not write; it writes its own from the
  # rules.
  docker exec "${node}" kubectl -n galactic-system delete servicevipbindings \
    -l "app.kubernetes.io/managed-by!=galactic-router" --ignore-not-found
  for gw in ${GATEWAY_NODES[${site}]}; do
    docker exec "${node}" kubectl -n galactic-system rollout status daemonset "galactic-gateway-${gw}" --timeout=180s
  done
  # Ready means the engine loaded every rule and advertised it, Accepted that
  # the rule found a gateway, and Bound that the backend's node rewrites the
  # VIP for it. The bindings appear only once each backend's node has seen
  # its accepted rule, so wait for all of them to exist first.
  docker exec "${node}" kubectl -n galactic-system wait networkgateway --all \
    --for=condition=Ready --timeout=120s
  docker exec "${node}" kubectl -n galactic-system wait networkrule --all \
    --for=condition=Accepted --timeout=60s
  wait_bindings "${node}" "${NS60_BINDINGS}" 60
  docker exec "${node}" kubectl -n galactic-system wait servicevipbinding \
    -l "${GENERATED_BINDINGS}" --for=condition=Bound --timeout=60s
done

echo "Done."
