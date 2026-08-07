#!/bin/bash
# verify-ns10.sh — confirm IPv6 ping connectivity between ns10 pods on every
# pair of sites, in both directions (full mesh). ns10 is IPv6-only, fd20 ULA.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NS=ns10
SITES=(dfw sjc iad)

declare -A NODE POD IP6
for s in "${SITES[@]}"; do
  NODE[$s]=$(control_plane "${s}")
  POD[$s]=$(pod_name "${NODE[$s]}" "${NS}")
  IP6[$s]=$(pod_ip6 "${NODE[$s]}" "${NS}" "${POD[$s]}")
  echo "${s}: pod=${POD[$s]} ip=${IP6[$s]}"
done

for src in "${SITES[@]}"; do
  for dst in "${SITES[@]}"; do
    [ "${src}" = "${dst}" ] && continue
    echo "--- ${src} -> ${dst} (${IP6[$dst]}) ---"
    ping_pod "${NODE[$src]}" "${NS}" "${POD[$src]}" -6 "${IP6[$dst]}"
  done
done

echo "ns10: ping OK between all site pairs"
