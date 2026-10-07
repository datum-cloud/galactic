#!/bin/bash
# verify-gateway-detach.sh — prove verify-gateway-ingress.sh fails when a
# gateway's XDP program is off its uplinks, and passes again once it is back.
#
# Turning dfw-worker2's datapath off (GALACTIC_GATEWAY_DATAPATH_ENABLED=false)
# clears its slot in the node's XDP dispatcher, so nothing on its uplinks
# claims a VIP packet any more. The NAT shard's slot is untouched. The ingress
# check through that node must then fail; then the datapath is turned back
# on, and the same check must pass.
#
# Not part of `task verify`: dfw-worker2 serves no VIP while it runs.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

CP=$(control_plane dfw)
NODE=dfw-worker2
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

echo "--- turn it back on ---"
docker exec "${CP}" kubectl -n galactic-system set env daemonset "${DS}" GALACTIC_GATEWAY_DATAPATH_ENABLED-
docker exec "${CP}" kubectl -n galactic-system rollout status daemonset "${DS}" --timeout=120s
trap - EXIT
docker exec "${CP}" kubectl -n galactic-system wait networkgateway "${NODE}" \
  --for=condition=Ready --timeout=120s

echo "--- the same check must pass again ---"
"${SCRIPT_DIR}/verify-gateway-ingress.sh" --node "${NODE}"
echo "PASS: the ingress check fails while ${NODE}'s datapath is off and passes once it is back"
