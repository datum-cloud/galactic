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

# ns40 exists to prove two attachments on one VPC share a single kernel VRF on
# one worker, so both pods landing on the same node is the subject of the test,
# not an incidental detail. Nothing in the fixture pins them together — iad has
# a second worker, and only the route-reflector NoSchedule taint on
# iad-worker-control keeps the pair on iad-worker — so if that taint goes away
# the pings below would still pass over the cross-node path and quietly stop
# testing what ns40 is named for. Assert it instead.
SCHED0=$(pod_scheduling_node "${NODE}" "${NS}" "${PODS[0]}")
SCHED1=$(pod_scheduling_node "${NODE}" "${NS}" "${PODS[1]}")
if [ "${SCHED0}" != "${SCHED1}" ]; then
  echo "expected both ns40 pods on one node, found ${PODS[0]} on ${SCHED0} and ${PODS[1]} on ${SCHED1}" >&2
  exit 1
fi
echo "both pods scheduled on ${SCHED0}"

IP0=$(pod_ip4 "${NODE}" "${NS}" "${PODS[0]}")
IP1=$(pod_ip4 "${NODE}" "${NS}" "${PODS[1]}")
echo "${PODS[0]}: ${IP0}"
echo "${PODS[1]}: ${IP1}"

echo "--- ${PODS[0]} -> ${PODS[1]} ---"
ping_pod "${NODE}" "${NS}" "${PODS[0]}" -4 "${IP1}"
echo "--- ${PODS[1]} -> ${PODS[0]} ---"
ping_pod "${NODE}" "${NS}" "${PODS[1]}" -4 "${IP0}"

echo "ns40: ping OK between both pods"
