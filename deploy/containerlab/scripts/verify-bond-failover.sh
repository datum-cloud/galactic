#!/bin/bash
# verify-bond-failover.sh — take each member of each bond down in turn and
# confirm the fabric does not notice.
#
# That is the point of bonding the lab's uplinks: losing one member of an
# aggregate must cost neither the BGP session riding the bond nor
# reachability through it. For each bond, one member at a time, this:
#   1. takes the member down (on the side that is not a Kind node where there
#      is one, so the Kind node's datapath attachments stay untouched);
#   2. pings the loopback behind the bond from tr1's own loopback, the same
#      way verify:underlay does;
#   3. for a transit bond, checks the eBGP session over it was not re-
#      established while the member was down, by comparing FRR's
#      connectionsEstablished counter before and after;
#   4. brings the member back and waits for it to rejoin the aggregate
#      before moving on, so the next member is never taken down while this
#      one is still out.
#
# Pings are ICMP, which layer3+4 hashing places by address alone, so any one
# flow uses one member. Taking each member down in turn is what guarantees
# the flow is moved at least once.
#
# Disruptive, if briefly: run it against a lab nobody else is using.
set -euo pipefail

LAB="${LAB:-gvpc}"
TR1="clab-${LAB}-tr1"
TR1_LO="fc00:0:1::1"
REJOIN_TIMEOUT=30

# container bond "member member" loopback-behind-it [bgp-neighbor]
BONDS=(
  "clab-${LAB}-tr1|bond1|eth1 eth6|fc00:0:a::1|2001:db8:1:11::2"
  "clab-${LAB}-tr1|bond2|eth5 eth7|fc00:0:b::1|2001:db8:1:12::2"
  "clab-${LAB}-tr2|bond1|eth1 eth5|fc00:0:c::1|2001:db8:1:21::2"
  "clab-${LAB}-tr3|bond1|eth4 eth5|fc00:0:9::1|2001:db8:1:32::2"
  # Compute-facing bonds, taken down on the edge end. dfw-worker stays
  # reachable over its other edge node regardless, so for dfw this proves
  # less than for sjc and iad, where the bond is the only way in.
  "dfw-worker2|bond1|eth2 eth4|fc00:0:2::1|"
  "dfw-worker3|bond1|eth2 eth4|fc00:0:2::1|"
  "sjc-worker2|bond1|eth2 eth4|fc00:0:3::1|"
  "iad-worker2|bond1|eth2 eth5|fc00:0:4::1|"
)

# Collecting (0x10) and distributing (0x20), as verify-bonds.sh checks.
CARRYING=$((0x30))

connections_established() {
  docker exec "$1" vtysh -c "show bgp neighbors $2 json" |
    grep -o '"connectionsEstablished":[0-9]*' | head -1 | cut -d: -f2
}

carrying() {
  local state
  state=$(docker exec "$1" ip -d link show dev "$2" |
    grep -o 'ad_actor_oper_port_state [0-9]*' | awk '{print $2}')
  [ -n "${state}" ] && [ $((state & CARRYING)) -eq "${CARRYING}" ]
}

fail=0
for entry in "${BONDS[@]}"; do
  IFS='|' read -r node bond members loopback neighbor <<<"${entry}"

  for member in ${members}; do
    label="${node}:${bond} without ${member}"

    before=""
    [ -n "${neighbor}" ] && before=$(connections_established "${node}" "${neighbor}")

    docker exec "${node}" ip link set dev "${member}" down
    # Give the bond a moment to notice -- miimon is 100ms.
    sleep 1

    if docker exec "${TR1}" ping -6 -c3 -i0.3 -W2 -I "${TR1_LO}" "${loopback}" >/dev/null 2>&1; then
      reach="reachable"
    else
      reach="UNREACHABLE"
      fail=1
    fi

    session=""
    if [ -n "${neighbor}" ]; then
      after=$(connections_established "${node}" "${neighbor}")
      if [ -n "${before}" ] && [ "${before}" = "${after}" ]; then
        session=", BGP ${neighbor} held"
      else
        session=", BGP ${neighbor} RE-ESTABLISHED (${before:-?} -> ${after:-?})"
        fail=1
      fi
    fi

    docker exec "${node}" ip link set dev "${member}" up
    i=0
    until carrying "${node}" "${member}"; do
      i=$((i + 1))
      if [ "${i}" -ge "${REJOIN_TIMEOUT}" ]; then
        echo "FAIL  ${node}:${bond}: ${member} did not rejoin the aggregate within ${REJOIN_TIMEOUT}s" >&2
        fail=1
        break
      fi
      sleep 1
    done

    if [ "${reach}" = "reachable" ] && [[ "${session}" != *RE-ESTABLISHED* ]]; then
      echo "ok    ${label}: ${loopback} ${reach}${session}"
    else
      echo "FAIL  ${label}: ${loopback} ${reach}${session}"
    fi
  done
done

exit "${fail}"
