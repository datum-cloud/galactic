#!/bin/bash
# verify-bmp.sh — confirm the EVPN route reflector streams to the lab's BMP
# collector: its station gauge reads up, and the collector's latest Peer
# Up/Down message for every one of the reflector's BGPPeers is a Peer Up.
#
# The gauge alone only proves the TCP session to the collector is open. The
# per-peer check proves the collector actually parsed what came over it, and
# catches a peer whose session to the reflector is down, since GoBGP reports
# that to the collector as a Peer Down.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NODE=iad-worker3
STATION="[fc00:0:8::1]:5000"
METRICS_PORT=9179
# GoBMP's message type for BMP Peer Up/Down (pkg/bmp PeerStateChangeMsg).
PEER_STATE_MSG=10

cp=$(control_plane iad)
fail=0

gauge=$(docker exec "${NODE}" curl -sf "localhost:${METRICS_PORT}/metrics" |
  awk -v st="station=\"${STATION}\"" '/^galactic_router_bmp_station_up/ && index($0, st) {print $NF}')
if [[ "${gauge}" == "1" ]]; then
  echo "ok   ${NODE}: BMP session to ${STATION} is up"
else
  echo "FAIL ${NODE}: galactic_router_bmp_station_up for ${STATION} = '${gauge:-missing}'"
  fail=1
fi

peers=$(docker exec "${cp}" kubectl get bgppeers -n galactic-system \
  -o jsonpath='{range .items[?(@.spec.routerRef.name=="galactic-control")]}{.spec.address}{"\n"}{end}')

# GoBMP writes one JSON message per line; the last Peer Up/Down for each peer
# says whether its session to the reflector is currently up.
states=$(docker exec "${cp}" kubectl logs -n galactic-system deploy/bmp-collector |
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
        last[d["remote_ip"]] = d["action"]
for ip, action in sorted(last.items()):
    print(ip, action)
')

for peer in ${peers}; do
  action=$(awk -v p="${peer}" '$1 == p {print $2}' <<<"${states}")
  if [[ "${action}" == "add" ]]; then
    echo "ok   ${peer}: Peer Up reported"
  else
    echo "FAIL ${peer}: latest Peer Up/Down is '${action:-none}'"
    fail=1
  fi
done

exit "${fail}"
