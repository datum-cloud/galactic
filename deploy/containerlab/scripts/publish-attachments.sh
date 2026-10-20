#!/bin/bash
# publish-attachments.sh — make a tenant's VPCAttachments and write their
# status, the job the attachment controller does in production.
#
# Every galactic NetworkAttachmentDefinition in the namespace is one
# attachment, named after the NAD. One the tenant's own manifests do not
# define (only ns60's do, for the labels its NetworkServices select by) is
# created from the NAD's vpc. Each one's status then gets what its pod
# reports once scheduled:
#
#   - vpc, vpcAttachment: the NAD's identifiers;
#   - node, podName: where the pod using the NAD (as its
#     v1.multus-cni.io/default-network) runs;
#   - hostInterface: the host side of its veth, G<vpc><vpcattachment>H
#     (internal/plumbing/intf), which galactic-router's traffic policy
#     reconciler binds the attachment's policies to.
#
# ns60's NetworkServices wait on node to select a backend; every tenant
# interface waits on hostInterface, since the lab enforces traffic policy and
# an interface with no published bindings denies everything.
#
# Usage: publish-attachments.sh <namespace> <site> [site...]
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $(basename "$0") <namespace> <site> [site...]" >&2
  exit 1
fi

NS="$1"
shift

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

for site in "$@"; do
  cp=$(control_plane "${site}")
  for nad in $(docker exec "${cp}" kubectl get network-attachment-definitions -n "${NS}" \
    -o jsonpath='{.items[*].metadata.name}'); do
    config=$(docker exec "${cp}" kubectl get network-attachment-definitions -n "${NS}" "${nad}" \
      -o jsonpath='{.spec.config}')
    vpc=$(jq -r '[.plugins[] | select(.type == "galactic-veth" or .type == "galactic-tap")][0].vpc // empty' <<<"${config}")
    attachment=$(jq -r '[.plugins[] | select(.type == "galactic-veth" or .type == "galactic-tap")][0].vpcattachment // empty' <<<"${config}")
    if [ -z "${vpc}" ] || [ -z "${attachment}" ]; then
      continue # not a galactic network
    fi

    if ! docker exec "${cp}" kubectl get vpcattachment -n "${NS}" "${nad}" >/dev/null 2>&1; then
      docker exec -i "${cp}" kubectl apply -f - >/dev/null <<EOF
apiVersion: galactic.datumapis.com/v1alpha1
kind: VPCAttachment
metadata:
  name: ${nad}
  namespace: ${NS}
spec:
  vpc:
    name: "${vpc}"
  interface:
    name: eth0
EOF
    fi

    # The pod naming this NAD as its default network, by bare name or
    # namespace/name: one that is running and not being deleted when there
    # is one, so a rollout's old pod is never the one published.
    pod=""
    for i in $(seq 1 60); do
      pod=$(docker exec "${cp}" kubectl get pods -n "${NS}" -o json |
        jq -r --arg nad "${nad}" --arg qualified "${NS}/${nad}" '
          [.items[]
           | select(.metadata.annotations["v1.multus-cni.io/default-network"] as $n
                    | $n == $nad or $n == $qualified)
           | select(.spec.nodeName != null and .metadata.deletionTimestamp == null)]
          | (map(select(.status.phase == "Running")) + .)[0].metadata.name // empty')
      [ -n "${pod}" ] && break
      if [ "${i}" -eq 60 ]; then
        echo "error: no scheduled pod in ${site}/${NS} uses ${nad} after 120s" >&2
        exit 1
      fi
      sleep 2
    done
    node=$(docker exec "${cp}" kubectl get pod -n "${NS}" "${pod}" -o jsonpath='{.spec.nodeName}')
    host=$(printf 'G%09s%03sH' "${vpc}" "${attachment}" | tr ' ' '0')

    docker exec "${cp}" kubectl patch vpcattachment -n "${NS}" "${nad}" --subresource=status --type=merge \
      -p "{\"status\":{\"vpc\":\"${vpc}\",\"vpcAttachment\":\"${attachment}\",\"node\":\"${node}\",\"podName\":\"${pod}\",\"hostInterface\":\"${host}\"}}" >/dev/null
    echo "${site}: ${NS}/${nad} -> ${node} (${pod}, ${host})"
  done
done
