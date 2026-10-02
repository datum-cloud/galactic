#!/bin/bash
# verify-bmp.sh — confirm everything that should stream to the lab's BMP
# collector does, and that the collector's view of each BGP session matches
# the router's: the EVPN route reflector's station gauge reads up, every
# fabric-router's FRR reports its BMP session up, the collector's latest Peer
# Up/Down for every Established session is a Peer Up, and for every fabric
# session that is not Established it is not.
#
# A BMP session being up only proves the TCP connection to the collector is
# open. The per-peer check proves the collector actually parsed what came
# over it. A BGP session that is down is reported by verify:fabric-metrics
# and verify:bgp-peers; here it only has to be reported down to the
# collector too.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

RR_NODE=iad-worker3
RR_ADDR=fc00:0:8::1
STATION="[${RR_ADDR}]:5000"
METRICS_PORT=9179
# GoBMP's message type for BMP Peer Up/Down (pkg/bmp PeerStateChangeMsg).
PEER_STATE_MSG=10

fail=0

gauge=$(docker exec "${RR_NODE}" curl -sf "localhost:${METRICS_PORT}/metrics" |
  awk -v st="station=\"${STATION}\"" '/^galactic_router_bmp_station_up/ && index($0, st) {print $NF}')
if [[ "${gauge}" == "1" ]]; then
  echo "ok   ${RR_NODE} galactic-router: BMP session to ${STATION} is up"
else
  echo "FAIL ${RR_NODE} galactic-router: galactic_router_bmp_station_up for ${STATION} = '${gauge:-missing}'"
  fail=1
fi

# GoBMP writes one JSON message per line. The last Peer Up/Down for each BGP
# session, keyed by the session's local and remote addresses, says whether it
# is currently up. GoBMP does not export which router sent a message, but a
# session's address pair is unique to the router holding it. The local address
# is GoBMP's router_ip, which both Peer Up and Peer Down carry; local_ip is
# only on a Peer Up.
states=$(docker exec "$(control_plane iad)" kubectl logs -n galactic-system deploy/bmp-collector |
  PEER_STATE_MSG="${PEER_STATE_MSG}" python3 -c '
import json, os, sys
want = int(os.environ["PEER_STATE_MSG"])
last = {}
for line in sys.stdin:
    if not line.startswith("{"):
        continue
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("msg_type") == want:
        d = m["msg_data"]
        last[(d["router_ip"], d["remote_ip"])] = d["action"]
for (local, remote), action in sorted(last.items()):
    print(local, remote, action)
')

# check_session WHO LOCAL REMOTE reports whether the collector's latest Peer
# Up/Down for the LOCAL→REMOTE session is a Peer Up.
check_session() {
  local who="$1" local_ip="$2" remote_ip="$3" action
  action=$(awk -v l="${local_ip}" -v r="${remote_ip}" '$1 == l && $2 == r {print $3}' <<<"${states}")
  if [[ "${action}" == "add" ]]; then
    echo "ok   ${who}: ${local_ip} -> ${remote_ip} Peer Up reported"
  else
    echo "FAIL ${who}: ${local_ip} -> ${remote_ip} latest Peer Up/Down is '${action:-none}'"
    fail=1
  fi
}

# check_session_down WHO REMOTE STATE reports whether the collector agrees that
# WHO's session to REMOTE, which WHO reports in STATE, is down: its latest Peer
# Up/Down must not be a Peer Up. The local address of a session that is down
# is unknown, so this matches on REMOTE alone, which in the lab identifies the
# session, since each link address belongs to exactly one interface.
check_session_down() {
  local who="$1" remote_ip="$2" state="$3" actions
  actions=$(awk -v r="${remote_ip}" '$2 == r {print $3}' <<<"${states}")
  if grep -qx add <<<"${actions}"; then
    echo "FAIL ${who}: -> ${remote_ip} is ${state}, but the collector last saw a Peer Up"
    fail=1
  else
    echo "ok   ${who}: -> ${remote_ip} is ${state}, and the collector agrees it is down"
  fi
}

# The route reflector's EVPN sessions all run from its loopback.
rr_peers=$(docker exec "$(control_plane iad)" kubectl get bgppeers -n galactic-system \
  -o jsonpath='{range .items[?(@.spec.routerRef.name=="galactic-control")]}{.spec.address}{"\n"}{end}')
for peer in ${rr_peers}; do
  check_session "${RR_NODE} galactic-router" "${RR_ADDR}" "${peer}"
done

# fabric_vtysh NODE CMD runs vtysh CMD in NODE's fabric-router.
fabric_vtysh() {
  local node="$1" site="${1%%-*}" pod
  pod=$(docker exec "$(control_plane "${site}")" kubectl get pods -n galactic-system \
    -l app.kubernetes.io/name=fabric-router --field-selector "spec.nodeName=${node}" -o name)
  docker exec "$(control_plane "${site}")" kubectl exec -n galactic-system "${pod}" -c frr -- vtysh -c "$2"
}

for site in dfw iad sjc; do
  nodes=$(docker exec "$(control_plane "${site}")" kubectl get pods -n galactic-system \
    -l app.kubernetes.io/name=fabric-router \
    -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}')
  for node in ${nodes}; do
    if fabric_vtysh "${node}" "show bmp" | grep -Eq "${RR_ADDR}:5000 +Up"; then
      echo "ok   ${node} fabric-router: BMP session to ${STATION} is up"
    else
      echo "FAIL ${node} fabric-router: BMP session to ${STATION} is not up"
      fail=1
    fi
    # Every configured neighbor as "remote state local", from FRR's own view.
    # A neighbor that is not Established has no local address.
    sessions=$(fabric_vtysh "${node}" "show bgp neighbors json" | python3 -c '
import json, sys
for remote, n in json.load(sys.stdin).items():
    print(remote, n.get("bgpState"), n.get("hostLocal", "-"))
')
    while read -r remote_ip state local_ip; do
      [[ -z "${remote_ip}" ]] && continue
      if [[ "${state}" == "Established" ]]; then
        check_session "${node} fabric-router" "${local_ip}" "${remote_ip}"
      else
        check_session_down "${node} fabric-router" "${remote_ip}" "${state}"
      fi
    done <<<"${sessions}"
  done
done

exit "${fail}"
