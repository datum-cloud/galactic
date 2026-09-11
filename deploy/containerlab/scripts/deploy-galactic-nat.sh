#!/bin/bash
# deploy-galactic-nat.sh — Install the sharded egress translation DaemonSet and
# each site's own EgressShard object, reusing that site's existing worker
# node as its shard (design plan §3/§8, resources/galactic-nat/README.md)
# rather than a new dedicated node. Requires deploy:system (galactic-nat
# RBAC/ServiceAccount, applied there alongside galactic-cni/galactic-router's
# own) and deploy:images (galactic-nat:latest loaded onto every site's
# worker) first.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# config/galactic-nat/base is self-contained (its own full
# single-container DaemonSet spec, not a patch onto some other config/
# base) -- same shape config/galactic-gateway/base already has, copied by
# deploy-galactic-router.sh's copy_router_gateway_config for the identical
# reason. Nested under resources/galactic-nat/base/nat/ so that
# overlay's own "nat" resource reference (see its kustomization.yaml's
# doc comment) resolves.
GALACTIC_NAT_BASE_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-nat/base" && pwd)

# copy_nat_config NODE copies config/galactic-nat/base onto NODE,
# nested under resources/galactic-nat/base/nat/. Mirrors
# copy_router_gateway_config in deploy-galactic-router.sh; rm -rf first
# for the same reason that comment gives (docker cp nests SRC inside an
# already-existing DEST dir instead of overwriting it).
copy_nat_config() {
  local node="$1"
  docker exec "${node}" rm -rf /galactic/resources/galactic-nat/base/nat
  docker cp "${GALACTIC_NAT_BASE_DIR}" "${node}:/galactic/resources/galactic-nat/base/nat"
}

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Applying galactic-nat/${site} to ${node}..."
  docker exec "${node}" rm -rf /galactic/resources/galactic-nat
  copy_to "${node}" galactic-nat
  copy_nat_config "${node}"
  apply_k "${node}" "/galactic/resources/galactic-nat/${site}/"
  docker exec "${node}" kubectl -n galactic-system rollout status daemonset galactic-nat
done

echo "Done."
