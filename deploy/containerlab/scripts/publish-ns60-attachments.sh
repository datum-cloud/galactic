#!/bin/bash
# publish-ns60-attachments.sh — write the status of ns60's VPCAttachments,
# the job the attachment controller does in production.
#
# Each site's NetworkRules select ns60's backends through these attachments
# (resources/tenants/ns60/<site>/vpcattachments.yaml). An attachment is a
# backend only once its status names its VPC and its node, so this waits for
# each attachment's pod (same "instance" label) to be scheduled and copies its
# node into the attachment's status.
#
# Usage: publish-ns60-attachments.sh <site> [site...]
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $(basename "$0") <site> [site...]" >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NS=ns60
VPC=60

for site in "$@"; do
  cp=$(control_plane "${site}")
  for attachment in $(docker exec "${cp}" kubectl get vpcattachments -n "${NS}" -l app=backend \
    -o jsonpath='{.items[*].metadata.name}'); do
    instance=$(docker exec "${cp}" kubectl get vpcattachment -n "${NS}" "${attachment}" \
      -o jsonpath='{.metadata.labels.instance}')
    docker exec "${cp}" kubectl wait -n "${NS}" --for=condition=PodScheduled pod \
      -l "app=backend,instance=${instance}" --timeout=120s >/dev/null
    pod=$(docker exec "${cp}" kubectl get pods -n "${NS}" -l "app=backend,instance=${instance}" \
      -o jsonpath='{.items[0].metadata.name}')
    node=$(docker exec "${cp}" kubectl get pod -n "${NS}" "${pod}" -o jsonpath='{.spec.nodeName}')
    docker exec "${cp}" kubectl patch vpcattachment -n "${NS}" "${attachment}" --subresource=status --type=merge \
      -p "{\"status\":{\"vpc\":\"${VPC}\",\"vpcAttachment\":\"${VPC}${instance}\",\"node\":\"${node}\",\"podName\":\"${pod}\"}}" >/dev/null
    echo "${site}: ${NS}/${attachment} -> ${node} (${pod})"
  done
done
