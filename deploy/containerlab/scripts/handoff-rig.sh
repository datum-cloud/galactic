#!/bin/bash
# handoff-rig.sh: build and remove the scratch rig the Local handoff checks
# run on (docs/handoffs.md). It runs inside the rig container, which shares
# the compute node's network and PID namespaces, so every interface it makes
# is on the node, and the client namespace is the rig's own.
#
# Usage, inside the rig:
#
#   handoff-rig.sh dut-up plain|bond|vlan [MTU]   receiving device and client
#   handoff-rig.sh dut-down
#   handoff-rig.sh pairs-up GRO                   internal veth pairs, GRO on|off on the tenant ends
#   handoff-rig.sh pairs-down
#   handoff-rig.sh vpair-up | vpair-down          a pair for VPC 80's veth guest
#   handoff-rig.sh links-up PID                   routed links into the pod whose process is PID
#   handoff-rig.sh links-down
#   handoff-rig.sh client-up                      the client namespace alone
#   handoff-rig.sh down                           everything above
#
# The receiving device is always reached as hp-dut (its L3 interface name is
# printed by dut-up), the client namespace is hp-client and the client's end
# of the link carries 2001:db8:4144:1::2.
set -euo pipefail

CLIENT_NS=hp-client
NODE_ADDR=2001:db8:4144:1::1
CLIENT_ADDR=2001:db8:4144:1::2
VLAN_ID=120
VRF_A=G000000080V
VRF_B=G000000081V
LINK_HOST=fd20:80:ff04::
LINK_POD=fd20:80:ff04::1

client() { ip netns exec "${CLIENT_NS}" "$@"; }

# lacp_bond NETNS BOND MEMBER... builds the lab's bond (mkbond.sh's
# parameters) in NETNS, or on the node when NETNS is empty.
lacp_bond() {
  local ns="$1" bond="$2" m
  shift 2
  local run=()
  [ -n "${ns}" ] && run=(ip netns exec "${ns}")
  "${run[@]}" ip link add "${bond}" type bond mode 802.3ad miimon 100 lacp_rate fast xmit_hash_policy layer3+4
  for m in "$@"; do
    "${run[@]}" ip link set "${m}" down
    "${run[@]}" ip link set "${m}" master "${bond}"
    "${run[@]}" ip link set "${m}" up
  done
  "${run[@]}" ip link set "${bond}" up
}

dut_up() {
  local kind="$1" mtu="${2:-1500}" l3 cl3
  ip netns add "${CLIENT_NS}" 2>/dev/null || true
  client ip link set lo up
  case "${kind}" in
    plain)
      ip link add hp-dut0 mtu "${mtu}" type veth peer name hp-cl0 mtu "${mtu}" netns "${CLIENT_NS}"
      l3=hp-dut0
      cl3=hp-cl0
      ip link set hp-dut0 up
      client ip link set hp-cl0 up
      ;;
    bond)
      ip link add hp-dut0 mtu "${mtu}" type veth peer name hp-cl0 mtu "${mtu}" netns "${CLIENT_NS}"
      ip link add hp-dut1 mtu "${mtu}" type veth peer name hp-cl1 mtu "${mtu}" netns "${CLIENT_NS}"
      lacp_bond "" hp-bond hp-dut0 hp-dut1
      lacp_bond "${CLIENT_NS}" hp-cbond hp-cl0 hp-cl1
      ip link set hp-bond mtu "${mtu}"
      client ip link set hp-cbond mtu "${mtu}"
      l3=hp-bond
      cl3=hp-cbond
      ;;
    vlan)
      ip link add hp-dut0 mtu "${mtu}" type veth peer name hp-cl0 mtu "${mtu}" netns "${CLIENT_NS}"
      ip link set hp-dut0 up
      client ip link set hp-cl0 up
      ip link add link hp-dut0 name hp-dut0.${VLAN_ID} type vlan id "${VLAN_ID}"
      client ip link add link hp-cl0 name hp-cl0.${VLAN_ID} type vlan id "${VLAN_ID}"
      ip link set hp-dut0.${VLAN_ID} up
      client ip link set hp-cl0.${VLAN_ID} up
      l3=hp-dut0.${VLAN_ID}
      cl3=hp-cl0.${VLAN_ID}
      ;;
    *)
      echo "dut-up: unknown kind ${kind}" >&2
      return 2
      ;;
  esac
  # A native XDP_REDIRECT into a veth needs NAPI on its peer; GRO turns it
  # on. The client's ends stand in for the far side of a physical link,
  # which needs nothing of the kind, so they get it unconditionally.
  # They also stand in for a physical link in what they send: a NIC delivers
  # complete checksums, while a veth from a local sender carries offloaded,
  # partial ones (docs/handoffs.md). CLIENT_TX=on keeps the offload, for the
  # measurement of that case.
  for m in hp-cl0 hp-cl1; do
    if client ip link show "${m}" >/dev/null 2>&1; then
      client ethtool -K "${m}" gro on >/dev/null
      client ethtool -K "${m}" tx "${CLIENT_TX:-off}" >/dev/null
    fi
  done
  for m in hp-cbond hp-cl0.${VLAN_ID}; do
    if client ip link show "${m}" >/dev/null 2>&1; then
      client ethtool -K "${m}" tx "${CLIENT_TX:-off}" >/dev/null 2>&1 || true
    fi
  done
  ip -6 addr add "${NODE_ADDR}/64" dev "${l3}" nodad
  client ip -6 addr add "${CLIENT_ADDR}/64" dev "${cl3}" nodad
  client ip -6 route add 2001:db8:4144::/48 via "${NODE_ADDR}" dev "${cl3}"
  if [ "${kind}" = bond ]; then
    wait_lacp hp-bond hp-dut0 hp-dut1
  fi
  # Resolve both neighbors now, so the first probe is not the one that
  # waits for Neighbor Discovery.
  client ping -6 -c 1 -W 2 "${NODE_ADDR}" >/dev/null 2>&1 || true
  ping -6 -c 1 -W 2 "${CLIENT_ADDR}" >/dev/null 2>&1 || true
  echo "${l3}"
}

# wait_lacp BOND MEMBER... waits until every member is distributing.
wait_lacp() {
  local bond="$1" i n
  shift
  for i in $(seq 1 60); do
    # Members whose own (actor) LACP state is collecting and distributing.
    n=$(awk '/details actor lacp pdu:/ { actor = 1; next }
             /details partner lacp pdu:/ { actor = 0 }
             actor && /port state:/ { if (int($3 / 16) % 4 == 3) n++ }
             END { print n + 0 }' "/proc/net/bonding/${bond}" 2>/dev/null || echo 0)
    if [ "${n}" -ge "$#" ]; then
      return 0
    fi
    sleep 0.5
  done
  echo "bond ${bond} did not aggregate" >&2
  cat "/proc/net/bonding/${bond}" >&2 || true
  return 1
}

# dut_down removes the receiving device and the client's links, and keeps
# the client namespace, so listeners started in it survive between cells.
dut_down() {
  local l
  for l in hp-bond hp-dut0 hp-dut1; do
    ip link del "${l}" 2>/dev/null || true
  done
  client ip link del hp-cbond 2>/dev/null || true
}

pairs_up() {
  local gro="$1" v vrf
  for v in 80 81; do
    vrf=${VRF_A}
    [ "${v}" = 81 ] && vrf=${VRF_B}
    ip link add "hpn${v}t" type veth peer name "hpn${v}n"
    ip link set "hpn${v}t" master "${vrf}"
    ip link set "hpn${v}t" up
    ip link set "hpn${v}n" up
    ethtool -K "hpn${v}t" gro "${gro}" >/dev/null
  done
}

pairs_down() {
  ip link del hpn80t 2>/dev/null || true
  ip link del hpn81t 2>/dev/null || true
}

# vpair_up: one more internal veth pair in VPC 80, for flows from ns80's veth
# guest, whose sends carry offloaded checksums.
vpair_up() {
  ip link add hpv80t type veth peer name hpv80n
  ip link set hpv80t master "${VRF_A}"
  ip link set hpv80t up
  ip link set hpv80n up
  ethtool -K hpv80t gro on >/dev/null
}

# links_up PID: a routed link from each tenant VRF into the pod, ending in a
# VRF of the pod's own (vrf80, vrf81), as the galactic-vrf sidecar gives
# Envoy. Both VPCs use the same link addresses.
links_up() {
  local pid="$1" v vrf table
  for v in 80 81; do
    vrf=${VRF_A}
    [ "${v}" = 81 ] && vrf=${VRF_B}
    table=$((1000 + v))
    ip link add "hpr${v}h" type veth peer name "hpr${v}p" netns "${pid}"
    ip link set "hpr${v}h" master "${vrf}"
    ip -6 addr add "${LINK_HOST}/127" dev "hpr${v}h" nodad
    ip link set "hpr${v}h" up
    nsenter -t "${pid}" -n sh -ec "
      ip link show vrf${v} >/dev/null 2>&1 || ip link add vrf${v} type vrf table ${table}
      ip link set vrf${v} up
      ip link set hpr${v}p master vrf${v}
      ip -6 addr add ${LINK_POD}/127 dev hpr${v}p nodad
      ip link set hpr${v}p up
      ip -6 route replace fd20:80::/32 via ${LINK_HOST} dev hpr${v}p vrf vrf${v}
      ip -6 route replace unreachable default vrf vrf${v} metric 4278198272
    "
  done
}

links_down() {
  ip link del hpr80h 2>/dev/null || true
  ip link del hpr81h 2>/dev/null || true
}

case "${1:-}" in
  client-up)
    ip netns add "${CLIENT_NS}" 2>/dev/null || true
    client ip link set lo up
    ;;
  dut-up) dut_up "${2:?kind}" "${3:-1500}" ;;
  dut-down) dut_down ;;
  pairs-up) pairs_up "${2:?gro on|off}" ;;
  pairs-down) pairs_down ;;
  vpair-up) vpair_up ;;
  vpair-down) ip link del hpv80t 2>/dev/null || true ;;
  links-up) links_up "${2:?pid}" ;;
  links-down) links_down ;;
  down)
    links_down
    pairs_down
    ip link del hpv80t 2>/dev/null || true
    dut_down
    ip netns del "${CLIENT_NS}" 2>/dev/null || true
    ;;
  *)
    sed -n '2,20p' "$0" >&2
    exit 2
    ;;
esac
