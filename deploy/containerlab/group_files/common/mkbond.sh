#!/bin/sh
# mkbond.sh BOND MEMBER... -- enslave MEMBERs to an 802.3ad (LACP) bond named
# BOND, creating it first. Shared by both halves of every bonded link in the
# lab: the transit routers bind-mount it (gvpc.clab.yaml) and the Kind nodes
# have it baked into the kindest-node-galactic image, so the two ends of one
# aggregate can never disagree on its LACP parameters.
#
# Why these parameters:
#   mode 802.3ad       what production gateway uplinks run, and what
#                      galactic-gateway's per-slave attach gate waits on (it
#                      reads each slave's LACP actor state -- see
#                      internal/plumbing/ebpf/edgeattach/gate.go).
#   miimon 100         non-zero is load-bearing: with miimon 0 the bonding
#                      driver never re-polls carrier, so a slave that bounces
#                      while a native XDP program attaches stays failed.
#   lacp_rate fast     1s LACPDUs, so a member rejoins its aggregate in a few
#                      seconds rather than the 90s slow-rate timeout.
#   layer3+4           spreads flows across both members; the default layer2
#                      hash puts every packet on one member of a point-to-point
#                      link, which would leave the other member's datapath
#                      attachment untested.
#
# Members keep whatever MTU the topology gave their link -- bonding copies the
# bond's MTU onto each member as it is enslaved, and a new bond starts at 1500,
# which is what every bonded link in the lab runs (see gvpc.clab.yaml for why).
#
# Idempotent: re-running it leaves an existing bond and already-enslaved
# members alone.
set -eu

if [ "$#" -lt 2 ]; then
  echo "usage: $0 BOND MEMBER..." >&2
  exit 2
fi

bond="$1"
shift

# Members are containerlab veths, created by containerlab rather than by this
# node, so wait for each rather than assume it is already there.
for member in "$@"; do
  i=0
  until ip link show dev "$member" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge 60 ]; then
      echo "mkbond: member $member of $bond did not appear within 60s" >&2
      exit 1
    fi
    sleep 1
  done
done

if ! ip link show dev "$bond" >/dev/null 2>&1; then
  ip link add "$bond" type bond mode 802.3ad miimon 100 lacp_rate fast xmit_hash_policy layer3+4
fi

for member in "$@"; do
  if ip -o link show dev "$member" | grep -q " master $bond "; then
    continue
  fi
  # A member has to be down to be enslaved.
  ip link set dev "$member" down
  ip link set dev "$member" master "$bond"
  ip link set dev "$member" up
done

ip link set dev "$bond" up
