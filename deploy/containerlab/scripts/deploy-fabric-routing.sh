#!/bin/bash
# deploy-fabric-routing.sh — Install fabric routing through the typed API
# in every cluster: fabric-router-controller with its rollout manager, and
# each fabric router node's frr.conf imported into BGPRouter and the
# objects it reads.
#
# Runs after deploy:fabric and deploy:traffic-policy (which installs the
# galactic.datumapis.com CRDs). Nothing changes on a node: the rollout
# manager gives every compiled router a FabricRouterDeployment on the
# ConfigMap source, and verify:fabric-routing moves nodes from there.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

CONFIG=$(cd "${SCRIPT_DIR}/../../../config" && pwd)
FABRIC_CONF="${RESOURCES_DIR}/fabric-router"

# import_router CONF NODE writes NODE's typed resources, imported from its
# frr.conf by the fabric-router-controller image itself. Every node's
# import carries the same BGPRouterClass and FRRRouterParameters, so
# applying them again changes nothing.
import_router() {
  docker run --rm -i fabric-router-controller:latest import /dev/stdin --node "$2" <"$1"
}

# without_peers drops the BGPPeers from an import's YAML stream.
without_peers() {
  python3 -c '
import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.stdin) if d and d.get("kind") != "BGPPeer"]
yaml.safe_dump_all(docs, sys.stdout, sort_keys=False)
'
}

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Installing fabric-router-controller on ${site}..."
  # ServiceAccount and RBAC only; the Deployment comes from the lab overlay,
  # which nests the production base and the rollout component as
  # deploy-traffic-policy.sh does.
  docker exec "${node}" rm -rf /galactic/fabric-router-controller
  docker cp "${CONFIG}/fabric-router-controller" "${node}:/galactic/fabric-router-controller"
  apply_k "${node}" /galactic/fabric-router-controller/
  copy_to "${node}" fabric-router-controller
  docker cp "${CONFIG}/fabric-router-controller/base" "${node}:/galactic/resources/fabric-router-controller/base"
  docker cp "${CONFIG}/fabric-router-controller/components/rollout" \
    "${node}:/galactic/resources/fabric-router-controller/rollout"
  docker cp "${CONFIG}/fabric-router-controller/components/topology" \
    "${node}:/galactic/resources/fabric-router-controller/topology"
  apply_k "${node}" /galactic/resources/fabric-router-controller/
  docker exec "${node}" kubectl -n galactic-system rollout status deployment/fabric-router-controller --timeout=180s

  # A site whose peers come from a FabricTopology (deploy:fabric-topology)
  # keeps them: importing its peers again would conflict with every
  # generated one.
  keep=cat
  if [[ -n "$(docker exec "${node}" kubectl -n galactic-system get fabrictopologies -o name 2>/dev/null)" ]]; then
    keep=without_peers
  fi
  for conf in "${FABRIC_CONF}/${site}"/frr.conf.*; do
    router=${conf##*/frr.conf.}
    echo "Importing ${router}..."
    import_router "${conf}" "${router}" | "${keep}" | apply_f "${node}" -
  done
done
