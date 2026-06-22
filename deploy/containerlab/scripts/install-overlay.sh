#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RESOURCES_DIR="${SCRIPT_DIR}/../resources"

apply_overlay() {
  local node="$1"
  local site="$2"
  echo "Applying overlay/${site} to ${node}..."
  docker cp "${RESOURCES_DIR}/overlay" "${node}:/galactic/resources/"
  docker exec "${node}" kubectl apply -k /galactic/resources/overlay/${site}/
  # Patch CRD maximum boundaries: kubebuilder v0.18.0 generates
  # maximum: 4294967295 for uint32 ASN fields, but JSON Schema
  # maximum is limited to int32 (2147483647). Without this patch
  # the API server rejects all BGPRouter/BGPPeer resources.
  bash "${RESOURCES_DIR}/bgp/patches/fix-asn-maximum.sh" "${node}"
  echo "Applying bgp/${site} to ${node}..."
  docker cp "${RESOURCES_DIR}/bgp/${site}" "${node}:/galactic/resources/bgp-${site}/"
  docker exec "${node}" kubectl apply -f /galactic/resources/bgp-${site}/
}

apply_overlay dfw-control-plane dfw
apply_overlay sjc-control-plane sjc
apply_overlay iad-control-plane iad
# iad-rr overlay DaemonSet is included in iad's kustomization (resources: - rr);
# only apply its BGP CRDs separately
echo "Applying bgp/iad-rr to iad-control-plane..."
docker cp "${RESOURCES_DIR}/bgp/iad-rr" "iad-control-plane:/galactic/resources/bgp-iad-rr/"
docker exec iad-control-plane kubectl apply -f /galactic/resources/bgp-iad-rr/

echo "Done."
