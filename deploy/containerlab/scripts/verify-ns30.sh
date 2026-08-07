#!/bin/bash
# verify-ns30.sh — confirm IPv6 ping connectivity between ns30's two pods on
# dfw (same node, same VPC), in both directions. ns30 is single-site (dfw).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NS=ns30
NODE=$(control_plane dfw)

mapfile -t PODS < <(pod_names "${NODE}" "${NS}" | tr ' ' '\n')
if [ "${#PODS[@]}" -ne 2 ]; then
  echo "expected 2 ns30 pods on dfw, found ${#PODS[@]}: ${PODS[*]:-none}" >&2
  exit 1
fi

IP0=$(pod_ip6 "${NODE}" "${NS}" "${PODS[0]}")
IP1=$(pod_ip6 "${NODE}" "${NS}" "${PODS[1]}")
echo "${PODS[0]}: ${IP0}"
echo "${PODS[1]}: ${IP1}"

echo "--- ${PODS[0]} -> ${PODS[1]} ---"
ping_pod "${NODE}" "${NS}" "${PODS[0]}" -6 "${IP1}"
echo "--- ${PODS[1]} -> ${PODS[0]} ---"
ping_pod "${NODE}" "${NS}" "${PODS[1]}" -6 "${IP0}"

echo "ns30: ping OK between both pods"
