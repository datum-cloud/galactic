#!/bin/bash
# verify-ns40.sh — confirm IPv4 ping connectivity between ns40's two pods on
# iad (same node, same VPC, two distinct attachments sharing one VRF), in
# both directions. ns40 is single-site (iad).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NS=ns40
NODE=$(control_plane iad)

# ns40's two pods are two distinct attachments (see
# resources/tenants/ns40/base/kustomization.yaml), each its own Deployment
# with its own label — not two replicas of one Deployment — so each is
# fetched by its own label rather than via pod_names' default "app=private".
LABELS=(app=private app=private-b)
PODS=()
for label in "${LABELS[@]}"; do
  pod=$(pod_name "${NODE}" "${NS}" "${label}")
  if [ -z "${pod}" ]; then
    echo "ns40 pod (label ${label}) not found on iad" >&2
    exit 1
  fi
  PODS+=("${pod}")
done

IP0=$(pod_ip4 "${NODE}" "${NS}" "${PODS[0]}")
IP1=$(pod_ip4 "${NODE}" "${NS}" "${PODS[1]}")
echo "${PODS[0]}: ${IP0}"
echo "${PODS[1]}: ${IP1}"

echo "--- ${PODS[0]} -> ${PODS[1]} ---"
ping_pod "${NODE}" "${NS}" "${PODS[0]}" -4 "${IP1}"
echo "--- ${PODS[1]} -> ${PODS[0]} ---"
ping_pod "${NODE}" "${NS}" "${PODS[1]}" -4 "${IP0}"

echo "ns40: ping OK between both pods"
