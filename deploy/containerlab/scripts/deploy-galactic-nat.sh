#!/bin/bash
# deploy-galactic-nat.sh — Install the sharded egress translation DaemonSet and
# one EgressShard per edge node (resources/galactic-nat/README.md). Requires
# deploy:system (galactic-nat RBAC/ServiceAccount, applied there alongside
# galactic-cni/galactic-router's own), deploy:images (galactic-nat:latest
# loaded onto every edge node), and deploy:galactic-router: the shard
# advertises its SID through the edge node's BGPRouter, which that step
# creates. No lab node runs galactic-gateway, so each shard attaches its own
# XDP program to its uplinks (GALACTIC_NAT_XDP_ATTACH=direct).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# config/galactic-nat/base is self-contained (its own full
# single-container DaemonSet spec, not a patch onto some other config/
# base). Nested under resources/galactic-nat/base/nat/ so that
# overlay's own "nat" resource reference (see its kustomization.yaml's
# doc comment) resolves.
GALACTIC_NAT_BASE_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-nat/base" && pwd)

# copy_nat_config NODE copies config/galactic-nat/base onto NODE,
# nested under resources/galactic-nat/base/nat/. rm -rf first, as
# deploy-galactic-router.sh's copy_router_config does: docker cp nests SRC
# inside an already-existing DEST dir instead of overwriting it.
copy_nat_config() {
  local node="$1"
  docker exec "${node}" rm -rf /galactic/resources/galactic-nat/base/nat
  docker cp "${GALACTIC_NAT_BASE_DIR}" "${node}:/galactic/resources/galactic-nat/base/nat"
}

# delete_stale_shards NODE deletes every EgressShard not targeting a NAT
# node (galactic.datumapis.com/nat=enabled). Shards used to live on the compute workers, and a shard's identity is
# write-once, so a lab brought up before the move cannot be edited into the
# new layout: the old objects have to go. Deleting one clears that node's
# datapath and withdraws its advertisement. A fresh lab has none to delete.
delete_stale_shards() {
  local node="$1" edge shard target
  edge=$(docker exec "${node}" kubectl get nodes -l galactic.datumapis.com/nat=enabled \
    -o jsonpath='{.items[*].metadata.name}')
  docker exec "${node}" kubectl -n galactic-system get egressshards \
    -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.targetRef.name}{"\n"}{end}' |
    while read -r shard target; do
      [ -n "${shard}" ] || continue
      if ! grep -qw -- "${target}" <<<"${edge}"; then
        echo "Deleting EgressShard ${shard}: it targets ${target}, not a NAT node"
        docker exec "${node}" kubectl -n galactic-system delete egressshard "${shard}" --wait
      fi
    done
}

# delete_gateway NODE removes everything the lab used to deploy for
# galactic-gateway: its per-node DaemonSets, the NetworkGateway/NetworkRule/
# ServiceVIPBinding objects that drove them, and ns60, their backend tenant.
# The shards used to run chained behind the gateway and now attach their own
# XDP program, which fails while a gateway still holds an uplink's hook. Its
# XDP links are not pinned, so deleting the pod releases them. --wait makes
# sure that has happened before the shard DaemonSet below rolls out in direct
# mode. A fresh lab has none to delete.
delete_gateway() {
  local node="$1"
  docker exec "${node}" kubectl -n galactic-system delete daemonset \
    -l app.kubernetes.io/name=galactic-gateway --ignore-not-found --wait
  docker exec "${node}" kubectl -n galactic-system delete \
    networkrules,servicevipbindings,networkgateways --all --ignore-not-found --wait
  docker exec "${node}" kubectl delete namespace ns60 --ignore-not-found --wait
}

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Applying galactic-nat/${site} to ${node}..."
  delete_gateway "${node}"
  delete_stale_shards "${node}"
  docker exec "${node}" rm -rf /galactic/resources/galactic-nat
  copy_to "${node}" galactic-nat
  copy_nat_config "${node}"
  apply_k "${node}" "/galactic/resources/galactic-nat/${site}/"
  docker exec "${node}" kubectl -n galactic-system rollout status daemonset galactic-nat
  # Rollout means attached, not translating: a shard turns ready before its
  # identity is programmed. Programmed is what a tenant's egress route needs.
  docker exec "${node}" kubectl -n galactic-system wait egressshard --all \
    --for=condition=Programmed --timeout=120s
done

echo "Done."
