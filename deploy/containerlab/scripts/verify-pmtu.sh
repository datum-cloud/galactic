#!/bin/bash
# verify-pmtu.sh — prove a tenant packet too big for the fabric draws an ICMP
# error from its own node, and that the sender's path MTU discovery adapts.
#
# Every lab link is 1500 bytes and the fabric adds a 40-byte outer IPv6
# header, so the largest tenant packet that crosses is 1460 bytes. Before
# #641 a bigger one that was not TCP left the compute node's uplink and was
# dropped there, with no error and no counter.
#
#   1. Every galactic-cni node reports a limit of 1460.
#   2. A 1500-byte ping between two sites, from an IPv6 (ns10) and an IPv4
#      (ns20) tenant, draws a Packet Too Big or a Fragmentation Needed: the
#      sender's route learns MTU 1460, and a 1460-byte ping then gets through.
#   3. From each site's ns10 tenant, a 1500-byte UDP datagram to the
#      off-fabric host over NAT66 draws a Packet Too Big, and the route learns
#      MTU 1460.
#   4. Each sending node counted every error it sent in
#      galactic_usid_pmtu_packets_total, and refused none.
#
# A learned MTU is flushed before and after each check, from the pod's node,
# since a pod has no NET_ADMIN. Left behind, it lowers the MSS the pod
# advertises for ten minutes and fails verify:mss-clamp.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

WANT_LIMIT=1460
CNI_METRICS_PORT=9180
CNI_NODES=(dfw-worker dfw-worker2 dfw-worker3 sjc-worker sjc-worker2 iad-worker iad-worker2)
SITES=(dfw sjc iad)
HOST6="2001:db8:1:40::2"
# ICMP payload sizes that make a 1500-byte and a 1460-byte packet.
PING6_BIG=$((1500 - 48))
PING6_FIT=$((WANT_LIMIT - 48))
PING4_BIG=$((1500 - 28))
PING4_FIT=$((WANT_LIMIT - 28))
# A UDP payload that makes a 1500-byte IPv6 packet.
UDP6_BIG=$((1500 - 48))

rc=0
fail() { echo "  FAIL $*" >&2; rc=1; }

running_pod() {
  docker exec "$(control_plane "$1")" kubectl -n "$2" get pods \
    --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}'
}

in_pod() {
  local site="$1" ns="$2" pod="$3"
  shift 3
  docker exec "$(control_plane "${site}")" kubectl -n "${ns}" exec "${pod}" -- "$@"
}

pod_node() {
  docker exec "$(control_plane "$1")" kubectl -n "$2" get pod "$3" -o jsonpath='{.spec.nodeName}'
}

# flush_pmtu SITE NS POD clears every path MTU POD has learned, in both
# families.
flush_pmtu() {
  local site="$1" ns="$2" pod="$3" node sandbox netns
  node=$(pod_node "${site}" "${ns}" "${pod}")
  sandbox=$(docker exec "${node}" crictl pods --name "${pod}" -q | head -1)
  netns=$(docker exec "${node}" crictl inspectp "${sandbox}" | grep -m1 -oE '/var/run/netns/cni-[0-9a-f-]+')
  docker exec "${node}" ip netns exec "$(basename "${netns}")" ip -6 route flush cache
  docker exec "${node}" ip netns exec "$(basename "${netns}")" ip -4 route flush cache
}

# learned_mtu SITE NS POD FAMILY DST prints the MTU POD's route to DST has
# learned, or nothing.
learned_mtu() {
  in_pod "$1" "$2" "$3" ip "$4" route get "$5" | grep -oE 'mtu [0-9]+' | awk '{print $2}'
}

# pmtu_count NODE RESULT prints NODE's galactic_usid_pmtu_packets_total for
# RESULT.
pmtu_count() {
  docker exec "$1" curl -s --max-time 4 "http://localhost:${CNI_METRICS_PORT}/metrics" |
    awk -v r="$2" '$1 == "galactic_usid_pmtu_packets_total{result=\"" r "\"}" {print $2; found=1} END {if (!found) print 0}'
}

declare -A SENT_BEFORE REFUSED_BEFORE
REFUSALS="dropped_no_df dropped_icmp_error rate_limited no_gateway build_failed"

echo "--- 1. limit configured on every galactic-cni node ---"
for node in "${CNI_NODES[@]}"; do
  limit=$(docker exec "${node}" curl -s --max-time 4 "http://localhost:${CNI_METRICS_PORT}/metrics" |
    awk '/^galactic_usid_pmtu_limit_bytes / {print $2}' || true)
  if [ "${limit}" = "${WANT_LIMIT}" ]; then
    echo "  ok   ${node}: ${limit}"
  else
    fail "${node}: limit is '${limit:-missing}', want ${WANT_LIMIT}"
  fi
  sent=0
  for r in too_big_sent_ipv6 frag_needed_sent_ipv4; do
    sent=$((sent + $(pmtu_count "${node}" "${r}")))
  done
  SENT_BEFORE[${node}]=${sent}
  refused=0
  for r in ${REFUSALS}; do
    refused=$((refused + $(pmtu_count "${node}" "${r}")))
  done
  REFUSED_BEFORE[${node}]=${refused}
done

echo "--- 2. 1500-byte ping between sites ---"
# cross_site_ping NS FAMILY BIG FIT TARGET pings TARGET in sjc from dfw.
cross_site_ping() {
  local ns="$1" family="$2" big="$3" fit="$4" target="$5" pod learned
  pod=$(running_pod dfw "${ns}")
  flush_pmtu dfw "${ns}" "${pod}"
  in_pod dfw "${ns}" "${pod}" ping "${family}" -c 2 -W 1 -M do -s "${big}" "${target}" >/dev/null 2>&1 || true
  learned=$(learned_mtu dfw "${ns}" "${pod}" "${family}" "${target}")
  if [ "${learned}" = "${WANT_LIMIT}" ]; then
    echo "  ok   ${ns} dfw -> sjc: route learned MTU ${learned}"
  else
    fail "${ns} dfw -> sjc: route learned MTU '${learned:-none}', want ${WANT_LIMIT}"
  fi
  if in_pod dfw "${ns}" "${pod}" ping "${family}" -c 2 -W 2 -M do -s "${fit}" "${target}" >/dev/null 2>&1; then
    echo "  ok   ${ns} dfw -> sjc: a ${WANT_LIMIT}-byte ping gets through"
  else
    fail "${ns} dfw -> sjc: a ${WANT_LIMIT}-byte ping did not get through"
  fi
  flush_pmtu dfw "${ns}" "${pod}"
}

sjc6=$(pod_ip6 "$(control_plane sjc)" ns10 "$(running_pod sjc ns10)")
sjc4=$(pod_ip4 "$(control_plane sjc)" ns20 "$(running_pod sjc ns20)")
cross_site_ping ns10 -6 "${PING6_BIG}" "${PING6_FIT}" "${sjc6}"
cross_site_ping ns20 -4 "${PING4_BIG}" "${PING4_FIT}" "${sjc4}"

echo "--- 3. 1500-byte UDP over NAT66 ---"
for site in "${SITES[@]}"; do
  pod=$(running_pod "${site}" ns10)
  flush_pmtu "${site}" ns10 "${pod}"
  in_pod "${site}" ns10 "${pod}" sh -c \
    "head -c ${UDP6_BIG} /dev/zero | timeout 3 socat -u - UDP6:[${HOST6}]:9" >/dev/null 2>&1 || true
  sleep 1
  learned=$(learned_mtu "${site}" ns10 "${pod}" -6 "${HOST6}")
  if [ "${learned}" = "${WANT_LIMIT}" ]; then
    echo "  ok   ${site}: route to ${HOST6} learned MTU ${learned}"
  else
    fail "${site}: route to ${HOST6} learned MTU '${learned:-none}', want ${WANT_LIMIT}"
  fi
  flush_pmtu "${site}" ns10 "${pod}"
done

echo "--- 4. errors counted on the sending nodes ---"
sending=()
for ns in ns10 ns20; do
  sending+=("$(pod_node dfw "${ns}" "$(running_pod dfw "${ns}")")")
done
for site in sjc iad; do
  sending+=("$(pod_node "${site}" ns10 "$(running_pod "${site}" ns10)")")
done
for node in $(printf '%s\n' "${sending[@]}" | sort -u); do
  sent=0
  for r in too_big_sent_ipv6 frag_needed_sent_ipv4; do
    sent=$((sent + $(pmtu_count "${node}" "${r}")))
  done
  refused=0
  for r in ${REFUSALS}; do
    refused=$((refused + $(pmtu_count "${node}" "${r}")))
  done
  if [ "${sent}" -gt "${SENT_BEFORE[${node}]}" ]; then
    echo "  ok   ${node}: sent $((sent - SENT_BEFORE[${node}])) errors"
  else
    fail "${node}: sent no errors"
  fi
  if [ "${refused}" -ne "${REFUSED_BEFORE[${node}]}" ]; then
    fail "${node}: refused $((refused - REFUSED_BEFORE[${node}])) packets without an error"
  fi
done

if [ "${rc}" -ne 0 ]; then
  echo "FAIL: a packet too big for the fabric does not reliably draw an ICMP error" >&2
  exit 1
fi
echo "PASS: a packet too big for the fabric draws an ICMP error, and the sender adapts"
