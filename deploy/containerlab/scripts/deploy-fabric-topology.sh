#!/bin/bash
# deploy-fabric-topology.sh — Generate a site's fabric peers from its
# FabricEndpoints and FabricTopology instead of the peers deploy:fabric-routing
# imported.
#
# Applies the site's records and topology from
# resources/fabric-topology/<site>/ (deploy:fabric-routing runs
# fabric-router-controller with its topology generator on), and deletes
# the imported peers of the site's fabric routers (the peers
# deploy:fabric-routing labelled lab.galactic.datumapis.com/imported), which
# the topology reports as conflicts until they are gone. A site imported
# before that label existed needs deploy:fabric-routing again first. The
# generated peers compile to the same configuration, so each router's
# candidate stages with no change; nothing
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
# The label deploy:fabric-routing gives every peer it imports.
IMPORTED=lab.galactic.datumapis.com/imported

for site in ${SITES}; do
  node=$(control_plane "${site}")
  echo "Generating ${site}'s fabric peers from its topology..."
  copy_to "${node}" "fabric-topology/${site}"
  apply_k "${node}" "/galactic/resources/fabric-topology/${site}/"

  # The imported peers of this site's fabric-class routers, by the label the
  # import gives them. A peer without it, hand-authored or generated, stays.
  routers=$(docker exec "${node}" kubectl -n "${NS}" get bgprouters \
    -o jsonpath="{range .items[?(@.spec.routerClassName==\"${CLASS}\")]}{.metadata.name}{\"\\n\"}{end}")
  imported=$(docker exec "${node}" kubectl -n "${NS}" get bgppeers -l "${IMPORTED}=true" \
    -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.routerRef.name}{"\n"}{end}' |
    while read -r peer router; do
      if grep -qx "${router}" <<<"${routers}"; then echo "${peer}"; fi
    done)
  if [[ -n "${imported}" ]]; then
    # shellcheck disable=SC2086
    docker exec "${node}" kubectl -n "${NS}" delete bgppeers ${imported}
  fi
  for i in $(seq 1 60); do
    ready=$(docker exec "${node}" kubectl -n "${NS}" get fabrictopologies \
      -o jsonpath='{range .items[*]}{.metadata.name}={.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}')
    if [[ -n "${ready}" ]] && ! grep -qv '=True$' <<<"${ready}"; then
      echo "${site}: every topology Ready"
      break
    fi
    [[ "${i}" -eq 60 ]] && { echo "error: ${site}'s topologies are not all Ready: ${ready}" >&2; exit 1; }
    sleep 2
  done
done
