#!/bin/bash
# verify-gateway-detach.sh — prove verify-gateway-ingress.sh fails when a
# gateway's XDP program is off its uplinks, that the site's other gateway node
# keeps serving meanwhile, and that the check passes again once it is back.
#
# Turning dfw-worker2's datapath off (GALACTIC_GATEWAY_DATAPATH_ENABLED=false)
# clears its load-balancing slot in the node's XDP dispatcher, so nothing on
# its uplinks claims a VIP packet any more. The NAT shard's slot is untouched.
# The ingress check through that node must then fail.
#
# dfw-worker sends every VIP reply to dfw-worker2, its first uplink, whichever
# gateway node took the request. So the ingress check through dfw-worker3 must
# still pass while dfw-worker2 is off: that proves dfw-worker2 kept edge_return
# on its compute-facing link and forwarded those replies, rather than handing
# them to the kernel, whose connection tracking drops every TCP one as
# INVALID. Then the datapath is turned back on, and the check through
# dfw-worker2 must pass.
#
# Not part of `task verify`: dfw-worker2 serves no VIP while it runs.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

CP=$(control_plane dfw)
NODE=dfw-worker2
OTHER=dfw-worker3
DS="galactic-gateway-${NODE}"

set_datapath() {
  docker exec "${CP}" kubectl -n galactic-system set env daemonset "${DS}" \
    "GALACTIC_GATEWAY_DATAPATH_ENABLED=$1"
  docker exec "${CP}" kubectl -n galactic-system rollout status daemonset "${DS}" --timeout=120s
}

restore() {
  docker exec "${CP}" kubectl -n galactic-system set env daemonset "${DS}" \
    GALACTIC_GATEWAY_DATAPATH_ENABLED- >/dev/null 2>&1 || true
}
trap restore EXIT

echo "--- turn ${NODE}'s gateway datapath off ---"
set_datapath false
docker exec "${CP}" kubectl -n galactic-system wait networkgateway "${NODE}" \
  --for=jsonpath='{.status.conditions[?(@.type=="Ready")].reason}'=DatapathDisabled --timeout=60s

echo "--- the ingress check through ${NODE} must fail ---"
if "${SCRIPT_DIR}/verify-gateway-ingress.sh" --node "${NODE}"; then
  echo "FAIL: verify-gateway-ingress.sh passed with ${NODE}'s datapath off" >&2
  exit 1
fi
echo "  ok   it failed, as it should"

echo "--- the ingress check through ${OTHER} must pass while ${NODE} is off ---"
if ! "${SCRIPT_DIR}/verify-gateway-ingress.sh" --node "${OTHER}"; then
  echo "FAIL: ${OTHER} did not serve while ${NODE}'s datapath was off" >&2
  exit 1
fi

echo "--- turn it back on ---"
docker exec "${CP}" kubectl -n galactic-system set env daemonset "${DS}" GALACTIC_GATEWAY_DATAPATH_ENABLED-
docker exec "${CP}" kubectl -n galactic-system rollout status daemonset "${DS}" --timeout=120s
trap - EXIT
docker exec "${CP}" kubectl -n galactic-system wait networkgateway "${NODE}" \
  --for=condition=Ready --timeout=120s

echo "--- the same check must pass again ---"
"${SCRIPT_DIR}/verify-gateway-ingress.sh" --node "${NODE}"
echo "PASS: the ingress check fails through ${NODE} while its datapath is off, passes through ${OTHER}" \
  "meanwhile, and passes through ${NODE} once it is back"
