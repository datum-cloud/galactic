#!/bin/bash
# verify-fabric-metrics.sh — confirm every fabric-router pod's frr-exporter
# sidecar is serving metrics, that each of its collectors succeeded, and that
# every underlay session it reports is Established. Also confirm its
# config-agent serves the next-hop check's metrics, that no session announces
# an IPv4-mapped next hop, and that every BGP route is installed.
#
# The exporter listens on the node itself (the pod uses hostNetwork), so each
# node is scraped from inside its own Kind container rather than through the
# API. Nodes are discovered from the running fabric-router pods instead of a
# fixed list, so a node that should run fabric-router but has no pod shows up
# in verify:bgp-fabric rather than being silently skipped here.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

PORT=9342
AGENT_PORT=9343
fail=0

for site in dfw iad sjc; do
  cp=$(control_plane "${site}")
  nodes=$(docker exec "${cp}" kubectl get pods -n galactic-system \
    -l app.kubernetes.io/name=fabric-router \
    -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}')
  for node in ${nodes}; do
    if ! metrics=$(docker exec "${node}" curl -sf "localhost:${PORT}/metrics"); then
      echo "FAIL ${node}: no response on :${PORT}/metrics"
      fail=1
      continue
    fi
    # frr_collector_up is 0 for any collector whose last scrape failed, such
    # as one that could not open its daemon's vty socket.
    down=$(awk '/^frr_collector_up/ && $NF != 1' <<<"${metrics}")
    # frr_bgp_peer_state is 1 for Established; anything else is not (0 for
    # any other FSM state, 2 for a peer that is administratively shut down).
    peers=$(grep -c '^frr_bgp_peer_state' <<<"${metrics}" || true)
    notup=$(awk '/^frr_bgp_peer_state/ && $NF != 1' <<<"${metrics}")
    if [[ -n "${down}" || -n "${notup}" || "${peers}" -eq 0 ]]; then
      echo "FAIL ${node}: peers=${peers}"
      [[ -n "${down}" ]] && echo "${down}"
      [[ -n "${notup}" ]] && echo "${notup}"
      fail=1
    else
      echo "ok   ${node}: ${peers} sessions Established, all collectors up"
    fi

    if ! agent=$(docker exec "${node}" curl -sf "localhost:${AGENT_PORT}/metrics"); then
      echo "FAIL ${node}: no response on :${AGENT_PORT}/metrics"
      fail=1
      continue
    fi
    # The agent sets fabric_router_bgp_uninstalled_routes for both families on
    # every check, so its absence means no check has completed.
    afis=$(grep -c '^fabric_router_bgp_uninstalled_routes' <<<"${agent}" || true)
    mapped=$(awk '/^fabric_router_bgp_mapped_nexthop\{/ && $NF != 0' <<<"${agent}")
    uninstalled=$(awk '/^fabric_router_bgp_uninstalled_routes/ && $NF != 0' <<<"${agent}")
    if [[ "${afis}" -ne 2 || -n "${mapped}" || -n "${uninstalled}" ]]; then
      echo "FAIL ${node}: next-hop check families=${afis}"
      [[ -n "${mapped}" ]] && echo "${mapped}"
      [[ -n "${uninstalled}" ]] && echo "${uninstalled}"
      fail=1
    else
      echo "ok   ${node}: no IPv4-mapped next hops, every BGP route installed"
    fi
  done
done

exit "${fail}"
