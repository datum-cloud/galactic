#!/bin/bash
# handoff-fixture.sh: deploy or remove the Local handoff fixture, ns80-tap
# (resources/tenants/ns80-tap, docs/handoffs.md), on dfw.
#
# Usage: handoff-fixture.sh up|down
#
# up applies its traffic policy, its pods and its attachments' status, then
# waits until both TAP guests have bridged their TAP and the Envoy stand-in
# runs. down deletes the namespace and waits until galactic-tap has removed
# both host TAPs, so nothing of it is left on dfw-worker.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NS=ns80-tap
CP=$(control_plane dfw)
NODE=dfw-worker
TAPS=(G000000080082H G000000081082H)

case "${1:-}" in
  up)
    "${SCRIPT_DIR}/deploy-tenant-policy.sh" "${NS}" dfw
    "${SCRIPT_DIR}/deploy-ns.sh" "${NS}" dfw
    "${SCRIPT_DIR}/publish-attachments.sh" "${NS}" dfw
    docker exec "${CP}" kubectl -n "${NS}" wait --for=condition=Ready pod \
      -l 'app in (vpc-a-tap,vpc-b-tap,envoy-standin)' --timeout=240s
    ;;
  down)
    docker exec "${CP}" kubectl delete namespace "${NS}" --ignore-not-found --wait=true --timeout=240s
    for tap in "${TAPS[@]}"; do
      for i in $(seq 1 60); do
        docker exec "${NODE}" ip link show "${tap}" >/dev/null 2>&1 || break
        if [ "${i}" -eq 60 ]; then
          echo "handoff-fixture: ${tap} is still on ${NODE} after the namespace went" >&2
          exit 1
        fi
        sleep 1
      done
    done
    echo "ns80-tap removed"
    ;;
  *)
    echo "usage: $(basename "$0") up|down" >&2
    exit 2
    ;;
esac
