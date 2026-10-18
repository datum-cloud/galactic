#!/bin/bash
# deploy-fabric-topology.sh — Generate a site's fabric peers from its
# FabricEndpoints and FabricTopology instead of the peers deploy:fabric-routing
# imported.
#
# Applies the site's records and topology from
# resources/fabric-topology/<site>/ (deploy:fabric-routing runs
# fabric-router-controller with its topology generator on), and deletes
# the imported peers of the site's fabric routers, which the topology reports
# as conflicts until they are gone. The generated peers compile to the same
# configuration, so each router's candidate stages with no change; nothing
# reaches FRR until a release promotes it. EVPN peers of galactic-router are
# never touched: only peers of routers in the fabric router class are.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# dfw keeps its imported peers by default: verify:fabric-routing's failure
# step breaks a peer, which a topology would rewrite.
SITES=${SITES:-"sjc iad"}
CLASS=fabric-frr
NS=galactic-system

for site in ${SITES}; do
  node=$(control_plane "${site}")
  echo "Generating ${site}'s fabric peers from its topology..."
  copy_to "${node}" "fabric-topology/${site}"
  apply_k "${node}" "/galactic/resources/fabric-topology/${site}/"

  # The imported peers: unmanaged peers of this site's fabric-class routers.
  routers=$(docker exec "${node}" kubectl -n "${NS}" get bgprouters \
    -o jsonpath="{range .items[?(@.spec.routerClassName==\"${CLASS}\")]}{.metadata.name}{\"\\n\"}{end}")
  imported=$(docker exec "${node}" kubectl -n "${NS}" get bgppeers -o json | python3 -c '
import json, sys
routers = set(sys.argv[1].split())
for p in json.load(sys.stdin)["items"]:
    labels = p["metadata"].get("labels") or {}
    ref = (p["spec"].get("routerRef") or {}).get("name")
    if ref in routers and "app.kubernetes.io/managed-by" not in labels:
        print(p["metadata"]["name"])
' "${routers}")
  if [[ -n "${imported}" ]]; then
    # shellcheck disable=SC2086
    docker exec "${node}" kubectl -n "${NS}" delete bgppeers ${imported}
  fi
  for i in $(seq 1 60); do
    if [[ "$(docker exec "${node}" kubectl -n "${NS}" get fabrictopology lab \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')" == True ]]; then
      echo "${site}: topology Ready"
      break
    fi
    [[ "${i}" -eq 60 ]] && { echo "error: ${site}'s topology is not Ready" >&2; exit 1; }
    sleep 2
  done
done
