#!/bin/bash
# verify-ns40.sh — confirm IPv4 ping connectivity between ns40's two pods on
# iad (same node, same VPC), in both directions. ns40 is single-site (iad).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NS=ns40
NODE=$(control_plane iad)

mapfile -t PODS < <(pod_names "${NODE}" "${NS}" | tr ' ' '\n')
if [ "${#PODS[@]}" -ne 2 ]; then
  echo "expected 2 ns40 pods on iad, found ${#PODS[@]}: ${PODS[*]:-none}" >&2
  exit 1
fi

IP0=$(pod_ip4 "${NODE}" "${NS}" "${PODS[0]}")
IP1=$(pod_ip4 "${NODE}" "${NS}" "${PODS[1]}")
echo "${PODS[0]}: ${IP0}"
echo "${PODS[1]}: ${IP1}"

echo "--- ${PODS[0]} -> ${PODS[1]} ---"
ping_pod "${NODE}" "${NS}" "${PODS[0]}" -4 "${IP1}"
echo "--- ${PODS[1]} -> ${PODS[0]} ---"
ping_pod "${NODE}" "${NS}" "${PODS[1]}" -4 "${IP0}"

echo "ns40: ping OK between both pods"
