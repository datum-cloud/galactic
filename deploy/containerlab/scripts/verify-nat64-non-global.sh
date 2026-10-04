#!/bin/bash
# verify-nat64-non-global.sh — prove a shard refuses NAT64 to non-global IPv4.
#
# From each site's IPv6-only tenant (ns10), Echo Requests and a UDP datagram
# go to the synthesized form of IPv4 addresses that are not globally
# reachable. The site's first shard must refuse every one and count it as
# nat64_non_global_dest. tr4's loopback is one of the targets on purpose: the
# lab can route to it, so a refusal there is the shard's doing and not a
# missing route.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NAT_METRICS_PORT=9182
NAT64_PREFIX="2001:db8:64::"
SITES=(dfw sjc iad)
declare -A FIRST_SHARD=([dfw]=dfw-worker2 [sjc]=sjc-worker2 [iad]=iad-worker2)
TARGETS=(10.255.255.103 192.168.0.1 100.64.0.1)
PINGS=2
# Each target draws PINGS Echo Requests and one UDP datagram.
WANT_PER_TARGET=$((PINGS + 1))

rc=0
fail() { echo "  FAIL $*" >&2; rc=1; }

# synth A.B.C.D prints A.B.C.D embedded in the low 32 bits of NAT64_PREFIX.
synth() {
  local a b c d
  IFS=. read -r a b c d <<<"$1"
  printf '%s%x:%x\n' "${NAT64_PREFIX}" $(((a << 8) | b)) $(((c << 8) | d))
}

non_global_drops() {
  docker exec "$1" curl -s --max-time 4 "http://localhost:${NAT_METRICS_PORT}/metrics" |
    awk '/^galactic_nat_drops_total\{reason="nat64_non_global_dest"\}/ {print $2; found=1} END {if (!found) print 0}'
}

for site in "${SITES[@]}"; do
  cp=$(control_plane "${site}")
  shard=${FIRST_SHARD[${site}]}
  pod=$(docker exec "${cp}" kubectl -n ns10 get pods \
    --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
  echo "--- ${site}: ${pod} through ${shard} ---"
  before=$(non_global_drops "${shard}")
  answered=""
  for v4 in "${TARGETS[@]}"; do
    dst=$(synth "${v4}")
    if docker exec "${cp}" kubectl -n ns10 exec "${pod}" -- \
      ping -6 -c "${PINGS}" -W 1 "${dst}" >/dev/null 2>&1; then
      answered="${answered} ${v4}"
    fi
    docker exec "${cp}" kubectl -n ns10 exec "${pod}" -- \
      sh -c "echo probe | nc -u -w1 ${dst} 9999" >/dev/null 2>&1 || true
  done
  after=$(non_global_drops "${shard}")
  moved=$(awk -v a="${after}" -v b="${before}" 'BEGIN {print a - b}')
  want=$((WANT_PER_TARGET * ${#TARGETS[@]}))

  if [ -n "${answered}" ]; then
    fail "${site}: answered through ${shard} for${answered}, which it must refuse"
  fi
  if awk -v m="${moved}" -v w="${want}" 'BEGIN {exit !(m >= w)}'; then
    echo "  ok   ${site}: ${shard} refused ${TARGETS[*]} (nat64_non_global_dest +${moved})"
  else
    fail "${site}: ${shard} counted nat64_non_global_dest +${moved}, want at least +${want}"
  fi
done

if [ "${rc}" -eq 0 ]; then
  echo "PASS: every site's shard refuses NAT64 to non-global IPv4"
fi
exit "${rc}"
