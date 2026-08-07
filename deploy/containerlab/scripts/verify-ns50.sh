#!/bin/bash
# verify-ns50.sh — confirm IPv4 ping connectivity between ns50 pods on every
# pair of sites, in both directions (full mesh). ns50 is IPv4, 3-site.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NS=ns50
SITES=(dfw sjc iad)

declare -A NODE POD IP4
for s in "${SITES[@]}"; do
  NODE[$s]=$(control_plane "${s}")
  POD[$s]=$(pod_name "${NODE[$s]}" "${NS}")
  IP4[$s]=$(pod_ip4 "${NODE[$s]}" "${NS}" "${POD[$s]}")
  echo "${s}: pod=${POD[$s]} ip=${IP4[$s]}"
done

for src in "${SITES[@]}"; do
  for dst in "${SITES[@]}"; do
    [ "${src}" = "${dst}" ] && continue
    echo "--- ${src} -> ${dst} (${IP4[$dst]}) ---"
    ping_pod "${NODE[$src]}" "${NS}" "${POD[$src]}" -4 "${IP4[$dst]}"
  done
done

echo "ns50: ping OK between all site pairs"
