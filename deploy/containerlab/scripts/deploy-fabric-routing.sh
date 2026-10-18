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

# IMPORTED labels every peer the import writes, so deploy:fabric-topology
# deletes those and nothing else.
IMPORTED=lab.galactic.datumapis.com/imported

# without_peers drops the BGPPeers from an import's YAML stream, whose
# documents each start with "---" and carry a top-level kind.
without_peers() {
  python3 -c '
import re, sys
docs = re.split(r"^---$", sys.stdin.read(), flags=re.M)
sys.stdout.write("---".join(d for d in docs if not re.search(r"^kind: BGPPeer$", d, re.M)))
'
}

# label_imported marks every BGPPeer in an import's YAML stream as imported.
# The importer writes no labels, so each peer gains a labels map.
label_imported() {
  python3 -c '
import re, sys
docs = re.split(r"^---$", sys.stdin.read(), flags=re.M)
out = []
for d in docs:
    if re.search(r"^kind: BGPPeer$", d, re.M):
        if re.search(r"^  labels:$", d, re.M):
            sys.exit("an imported BGPPeer already has labels")
        d = re.sub(r"^metadata:$", "metadata:\n  labels:\n    " + sys.argv[1] + ": \"true\"", d, count=1, flags=re.M)
    out.append(d)
sys.stdout.write("---".join(out))
' "${IMPORTED}"
}

# topology_members prints the BGPRouters a FabricTopology in the namespace
# selects as members, by name or by label selector.
topology_members() {
  local node="$1"
  {
    docker exec "${node}" kubectl -n galactic-system get fabrictopologies -o json
    echo "---"
    docker exec "${node}" kubectl -n galactic-system get bgprouters -o json
  } | python3 -c '
import json, sys
topos, routers = (json.loads(d) for d in sys.stdin.read().split("\n---\n"))
def matches(sel, labels):
    for k, v in (sel.get("matchLabels") or {}).items():
        if labels.get(k) != v:
            return False
    for e in sel.get("matchExpressions") or []:
        k, op, vals = e["key"], e["operator"], e.get("values") or []
        ok = {"In": k in labels and labels[k] in vals, "NotIn": labels.get(k) not in vals,
              "Exists": k in labels, "DoesNotExist": k not in labels}[op]
        if not ok:
            return False
    return True
members = set()
for t in topos["items"]:
    m = t["spec"]["members"]
    members.update(r["name"] for r in m.get("routers") or [])
    if m.get("routerSelector") is not None:
        for r in routers["items"]:
            if matches(m["routerSelector"], r["metadata"].get("labels") or {}):
                members.add(r["metadata"]["name"])
print("\n".join(sorted(members)))
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

  # A router whose peers come from a FabricTopology (deploy:fabric-topology)
  # keeps them: importing its peers again would conflict with every
  # generated one. Every other router's peers are imported, labelled.
  members=$(topology_members "${node}")
  for conf in "${FABRIC_CONF}/${site}"/frr.conf.*; do
    router=${conf##*/frr.conf.}
    keep=cat
    if grep -qx "${router}" <<<"${members}"; then
      keep=without_peers
      echo "Importing ${router}, whose peers its topology generates..."
    else
      echo "Importing ${router}..."
    fi
    import_router "${conf}" "${router}" | "${keep}" | label_imported | apply_f "${node}" -
  done
done
