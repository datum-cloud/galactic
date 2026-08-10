#!/bin/bash
# verify-ns30.sh — confirm IPv6 ping connectivity between ns30's two pods on
# dfw (same node, same VPC, two distinct attachments sharing one VRF), in
# both directions. ns30 is single-site (dfw).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NS=ns30
NODE=$(control_plane dfw)

# ns30's two pods are two distinct attachments (see
# resources/tenants/ns30/base/kustomization.yaml), each its own Deployment
# with its own label — not two replicas of one Deployment — so each is
# fetched by its own label rather than via pod_names' default "app=private".
LABELS=(app=private app=private-b)
PODS=()
for label in "${LABELS[@]}"; do
  pod=$(pod_name "${NODE}" "${NS}" "${label}")
  if [ -z "${pod}" ]; then
    echo "ns30 pod (label ${label}) not found on dfw" >&2
    exit 1
  fi
  PODS+=("${pod}")
done

# ns30 exists to prove two attachments on one VPC share a single kernel VRF on
# one worker, so both pods landing on the same node is the subject of the test,
# not an incidental detail. Nothing in the fixture pins them together — dfw
# just happens to have exactly one schedulable worker — so if that ever changes
# the pings below would still pass over the cross-node path and quietly stop
# testing what ns30 is named for. Assert it instead.
SCHED0=$(pod_scheduling_node "${NODE}" "${NS}" "${PODS[0]}")
SCHED1=$(pod_scheduling_node "${NODE}" "${NS}" "${PODS[1]}")
if [ "${SCHED0}" != "${SCHED1}" ]; then
  echo "expected both ns30 pods on one node, found ${PODS[0]} on ${SCHED0} and ${PODS[1]} on ${SCHED1}" >&2
  exit 1
fi
echo "both pods scheduled on ${SCHED0}"

IP0=$(pod_ip6 "${NODE}" "${NS}" "${PODS[0]}")
IP1=$(pod_ip6 "${NODE}" "${NS}" "${PODS[1]}")
echo "${PODS[0]}: ${IP0}"
echo "${PODS[1]}: ${IP1}"

echo "--- ${PODS[0]} -> ${PODS[1]} ---"
ping_pod "${NODE}" "${NS}" "${PODS[0]}" -6 "${IP1}"
echo "--- ${PODS[1]} -> ${PODS[0]} ---"
ping_pod "${NODE}" "${NS}" "${PODS[1]}" -6 "${IP0}"

echo "ns30: ping OK between both pods"
