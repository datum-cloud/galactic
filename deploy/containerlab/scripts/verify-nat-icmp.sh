#!/bin/bash
# verify-nat-icmp.sh — prove ICMP crosses each site's egress shard.
#
# Every check runs from each site's IPv6-only tenant (ns10) toward the
# off-fabric host, through the site's first egress shard.
#
#   1. NAT66 ping: the tenant's Echo Requests are answered.
#   2. NAT66 Time Exceeded: mtr names at least one transit router between the
#      shard and the host. Those routers' errors quote an Echo Request the
#      shard sent, so each one the tenant sees was matched and translated.
#   3. NAT66 Packet Too Big: with the transit link to the host narrowed to
#      1300 bytes, a 1398-byte packet sent with DF draws a Packet Too Big from
#      the transit router, and the tenant's route learns MTU 1300 from it.
#
# Throughout, a site's shard must count no ICMP drop reason and no malformed
# packet. hop_limit_exceeded is expected to move: mtr's first probe expires at
# the shard itself, which drops it without an error of its own.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NAT_METRICS_PORT=9182
SITES=(dfw sjc iad)
declare -A FIRST_SHARD=([dfw]=dfw-worker2 [sjc]=sjc-worker2 [iad]=iad-worker2)

HOST6="2001:db8:1:40::2"
# The transit router and interface the off-fabric host hangs off
# (gvpc.clab.yaml: remote-host:eth1 <-> tr4:eth4).
NARROW_ROUTER=clab-gvpc-tr4
NARROW_IFACE=eth4
NARROW_MTU=1300
# 1350 bytes of ICMP payload makes a 1398-byte IPv6 packet: past the narrowed
# link, inside the fabric's own limit once encapsulated.
BIG_PAYLOAD=1350

# Drop reasons none of these probes may move.
WATCHED_DROPS="nat66_icmp_malformed nat66_icmp_no_conn icmp_untranslatable icmp_unsolicited nat66_malformed_forward nat66_malformed_return"

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

# flush_pmtu SITE NS POD clears the path MTUs POD has learned. A pod cannot
# do this itself without NET_ADMIN, so it is done from the pod's node, in the
# pod's network namespace. Left behind, a learned MTU of 1300 would lower the
# MSS the pod advertises for ten minutes and fail verify:mss-clamp.
flush_pmtu() {
  local site="$1" ns="$2" pod="$3" node sandbox netns
  node=$(docker exec "$(control_plane "${site}")" kubectl -n "${ns}" get pod "${pod}" -o jsonpath='{.spec.nodeName}')
  sandbox=$(docker exec "${node}" crictl pods --name "${pod}" -q | head -1)
  netns=$(docker exec "${node}" crictl inspectp "${sandbox}" | grep -m1 -oE '/var/run/netns/cni-[0-9a-f-]+')
  docker exec "${node}" ip netns exec "$(basename "${netns}")" ip -6 route flush cache
}

# drops SHARD prints every drop counter on SHARD as "reason value" lines.
drops() {
  docker exec "$1" curl -s --max-time 4 "http://localhost:${NAT_METRICS_PORT}/metrics" |
    sed -n 's/^galactic_nat_drops_total{reason="\([a-z0-9_]*\)"} \(.*\)$/\1 \2/p' | sort
}

# check_drops SITE SHARD BEFORE fails for every watched reason that moved on
# SHARD since BEFORE, a file drops wrote.
check_drops() {
  local site="$1" shard="$2" before="$3" moved
  moved=$(join -a2 -e 0 -o '0,1.2,2.2' "${before}" <(drops "${shard}") |
    awk -v watched="${WATCHED_DROPS}" '
      BEGIN { n = split(watched, w, " "); for (i = 1; i <= n; i++) keep[w[i]] = 1 }
      keep[$1] && $3 > $2 { printf "%s %s -> %s; ", $1, $2, $3 }')
  if [ -n "${moved}" ]; then
    fail "${site}: ${shard} dropped ICMP it should have translated: ${moved}"
  else
    echo "  ok   ${site}: ${shard} counted no ICMP drop"
  fi
}

snap=$(mktemp -d)
trap 'docker exec "${NARROW_ROUTER}" ip link set "${NARROW_IFACE}" mtu 1500; rm -rf "${snap}"' EXIT

declare -A POD
for site in "${SITES[@]}"; do
  POD[${site}]=$(running_pod "${site}" ns10)
  flush_pmtu "${site}" ns10 "${POD[${site}]}"
  drops "${FIRST_SHARD[${site}]}" >"${snap}/${site}"
done

echo "--- 1. NAT66 ping ---"
for site in "${SITES[@]}"; do
  if in_pod "${site}" ns10 "${POD[${site}]}" ping -6 -c 3 -W 2 "${HOST6}" >/dev/null 2>&1; then
    echo "  ok   ${site}: ${HOST6} answered"
  else
    fail "${site}: no Echo Reply from ${HOST6}"
  fi
done

echo "--- 2. NAT66 Time Exceeded ---"
for site in "${SITES[@]}"; do
  hops=$(in_pod "${site}" ns10 "${POD[${site}]}" mtr -6 -n -r -c 2 "${HOST6}" 2>/dev/null |
    awk -v dst="${HOST6}" '$1 ~ /\|--$/ && $2 != "???" && $2 != dst {print $2}' | tr '\n' ' ')
  if [ -n "${hops}" ]; then
    echo "  ok   ${site}: transit hops ${hops}"
  else
    fail "${site}: mtr named no transit hop, so no Time Exceeded reached the tenant"
  fi
done

echo "--- 3. NAT66 Packet Too Big ---"
docker exec "${NARROW_ROUTER}" ip link set "${NARROW_IFACE}" mtu "${NARROW_MTU}"
for site in "${SITES[@]}"; do
  pod=${POD[${site}]}
  # The first packet draws the Packet Too Big; any after it fail locally,
  # which is the point.
  in_pod "${site}" ns10 "${pod}" ping -6 -c 2 -W 1 -M do -s "${BIG_PAYLOAD}" "${HOST6}" >/dev/null 2>&1 || true
  learned=$(in_pod "${site}" ns10 "${pod}" ip -6 route get "${HOST6}" | grep -oE 'mtu [0-9]+' | awk '{print $2}')
  if [ "${learned}" = "${NARROW_MTU}" ]; then
    echo "  ok   ${site}: route to ${HOST6} learned MTU ${learned}"
  else
    fail "${site}: route to ${HOST6} has MTU '${learned:-none}', want ${NARROW_MTU} from a Packet Too Big"
  fi
  flush_pmtu "${site}" ns10 "${pod}"
done
docker exec "${NARROW_ROUTER}" ip link set "${NARROW_IFACE}" mtu 1500

echo "--- drop counters ---"
for site in "${SITES[@]}"; do
  check_drops "${site}" "${FIRST_SHARD[${site}]}" "${snap}/${site}"
done

if [ "${rc}" -eq 0 ]; then
  echo "PASS: ICMP crosses every site's egress shard"
fi
exit "${rc}"
