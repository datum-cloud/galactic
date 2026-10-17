#!/bin/bash
# deploy-node-addresses.sh — Address each fabric router node's interfaces.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# The node owns its interface addresses, as Talos does in production; FRR's
# config carries routing only. resources/node-addresses/<node>.addrs lists
# one "IFACE ADDRESS/LEN" or "IFACE alias TEXT" per line. Applied with
# "ip addr replace", so a rerun changes nothing. It runs before
# deploy:fabric, so FRR starts on addressed interfaces. A lab deployed when
# FRR's config still carried "interface" blocks loses these addresses when
# its agents reload the config without them, since zebra removes what it
# configured; rerun this once those reloads finish.
for file in "${RESOURCES_DIR}"/node-addresses/*.addrs; do
  node=$(basename "${file}" .addrs)
  echo "Addressing ${node}..."
  while read -r iface key rest; do
    case "${iface}" in '' | '#'*) continue ;; esac
    if [ "${key}" = alias ]; then
      docker exec "${node}" ip link set dev "${iface}" alias "${rest}"
    else
      docker exec "${node}" ip addr replace "${key}" dev "${iface}"
    fi
  done <"${file}"
done
