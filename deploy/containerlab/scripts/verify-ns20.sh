#!/bin/bash
# verify-ns20.sh — confirm dual-stack (IPv6 + IPv4) ping connectivity between
# ns20 pods on every pair of sites, in both directions (full mesh).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NS=ns20
SITES=(dfw sjc iad)

declare -A NODE POD IP6 IP4
for s in "${SITES[@]}"; do
  NODE[$s]=$(control_plane "${s}")
  POD[$s]=$(pod_name "${NODE[$s]}" "${NS}")
  IP6[$s]=$(pod_ip6 "${NODE[$s]}" "${NS}" "${POD[$s]}")
  IP4[$s]=$(pod_ip4 "${NODE[$s]}" "${NS}" "${POD[$s]}")
  echo "${s}: pod=${POD[$s]} ipv6=${IP6[$s]} ipv4=${IP4[$s]}"
done

for src in "${SITES[@]}"; do
  for dst in "${SITES[@]}"; do
    [ "${src}" = "${dst}" ] && continue
    echo "--- ${src} -> ${dst} IPv6 (${IP6[$dst]}) ---"
    ping_pod "${NODE[$src]}" "${NS}" "${POD[$src]}" -6 "${IP6[$dst]}"
    echo "--- ${src} -> ${dst} IPv4 (${IP4[$dst]}) ---"
    ping_pod "${NODE[$src]}" "${NS}" "${POD[$src]}" -4 "${IP4[$dst]}"
  done
done

echo "ns20: ping OK (both families) between all site pairs"
