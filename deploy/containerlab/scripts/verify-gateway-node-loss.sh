#!/bin/bash
# verify-gateway-node-loss.sh — prove a gateway node that goes away entirely
# leaves the VIP serving through the site's other gateway node.
#
# dfw-worker is dual-homed to dfw-worker2 (its bond0) and dfw-worker3 (its
# bond1), and sends every VIP reply out one uplink. This takes every one of
# dfw-worker2's fabric links down, to tr1 and to dfw-worker, as a node that
# lost power would: tr1 withdraws dfw-worker2's routes and dfw-worker's bond0
# loses carrier. Once tr1 routes dfw's VIP only through dfw-worker3, the
# ingress check through dfw-worker3 must pass. It does only if dfw-worker
# moved its replies to bond1; replies left on bond0 go nowhere. Then the links
# come back and, once tr1 routes the VIP through dfw-worker2 again and every
# bond on those links has all its members collecting and distributing in one
# LACP aggregator, the check through dfw-worker2 must pass too. Until LACP has
# settled, a bond hashes some flows to a member its partner does not collect
# from yet, and drops them.
#
# Not part of `task verify`: dfw-worker2 is cut off from the fabric while it
# runs.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

LAB=${LAB:-gvpc}
NODE=dfw-worker2
OTHER=dfw-worker3
LINKS=(eth1 eth2 eth3 eth4)
VIP_PREFIX=2001:db8:6060:1::/64
# tr1's bond facing dfw-worker2; keep in step with gvpc.clab.yaml.
TR_DEV=bond1
# "<container> <bond>" for both ends of every link taken down.
BONDS=("${NODE} bond0" "${NODE} bond1" "clab-${LAB}-tr1 ${TR_DEV}" "dfw-worker bond0")

set_links() {
  local l
  for l in "${LINKS[@]}"; do
    docker exec "${NODE}" ip link set "${l}" "$1"
  done
}

restore() { set_links up >/dev/null 2>&1 || true; }
trap restore EXIT

# via_node reports whether tr1 routes the VIP prefix through dfw-worker2.
via_node() {
  docker exec "clab-${LAB}-tr1" ip -6 route show "${VIP_PREFIX}" | grep -q "dev ${TR_DEV}"
}
not_via_node() { ! via_node; }

# lacp_settled reports whether every bond in BONDS has each member in its
# active aggregator with sync, collecting and distributing set (0x38) on both
# the actor and the partner side.
lacp_settled() {
  local b
  for b in "${BONDS[@]}"; do
    read -r container bond <<<"${b}"
    docker exec "${container}" cat "/proc/net/bonding/${bond}" | awk '
      /^Active Aggregator Info:/ {active = 1; next}
      active && /Aggregator ID:/ {agg = $3; active = 0; next}
      /^Slave Interface:/ {members++}
      /^Aggregator ID:/ && $3 != agg {bad = 1}
      /port state:/ && int($3 / 8) % 8 != 7 {bad = 1}
      END {exit bad || members == 0 || agg == ""}' || return 1
  done
}

# wait_for DESC SECONDS CMD... polls CMD once a second until it succeeds.
wait_for() {
  local desc=$1 secs=$2
  shift 2
  for _ in $(seq "${secs}"); do
    "$@" && return 0
    sleep 1
  done
  echo "FAIL: ${desc} within ${secs}s" >&2
  exit 1
}

echo "--- take every fabric link of ${NODE} down ---"
set_links down
wait_for "tr1 did not withdraw ${NODE}'s route to ${VIP_PREFIX}" 90 not_via_node
echo "  ok   tr1 routes ${VIP_PREFIX} through ${OTHER} only"

echo "--- the ingress check through ${OTHER} must pass with ${NODE} gone ---"
if ! "${SCRIPT_DIR}/verify-gateway-ingress.sh" --node "${OTHER}"; then
  echo "FAIL: ${OTHER} did not serve with ${NODE} gone" >&2
  exit 1
fi

echo "--- bring ${NODE}'s links back ---"
set_links up
trap - EXIT
wait_for "tr1 did not route ${VIP_PREFIX} through ${NODE} again" 120 via_node
start=${SECONDS}
wait_for "LACP did not settle on ${NODE}'s links" 60 lacp_settled
echo "  ok   tr1 routes ${VIP_PREFIX} through ${NODE} again; LACP settled $((SECONDS - start))s after that"

echo "--- the ingress check through ${NODE} must pass again ---"
"${SCRIPT_DIR}/verify-gateway-ingress.sh" --node "${NODE}"
echo "PASS: ${OTHER} served while ${NODE} was gone, and ${NODE} serves again once it is back"
