#!/bin/bash
# deploy-system.sh — Install BGP CRDs (datum-cloud/network) and VPC CRDs
# (datum-cloud/cloud), then apply the galactic-system namespace and shared
# RBAC (galactic-cni, galactic-router) to every cluster. The namespace and
# ServiceAccount/RBAC manifests are applied straight from the repo's
# config/ — the same ones used in production — so the lab never forks them.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# Network CRDs track datum-cloud/network's latest commit on NETWORK_REF
# (default main), not the version go.mod requires -- the lab exercises
# galactic against network's current API, and a go.mod pin routinely lags
# the schema changes the lab needs (e.g. BGPRouter's 16-bit spec.nodeID).
# The ref is resolved to a SHA once up front so every site installs the
# same schema even if the branch moves mid-deploy; set NETWORK_SHA to pin
# a specific commit instead.
NETWORK_REF="${NETWORK_REF:-main}"
if [[ -z "${NETWORK_SHA:-}" ]]; then
  NETWORK_SHA=$(git ls-remote https://github.com/datum-cloud/network.git "refs/heads/${NETWORK_REF}" | cut -f1)
  if [[ -z "${NETWORK_SHA}" ]]; then
    echo "error: could not resolve datum-cloud/network ref ${NETWORK_REF}" >&2
    exit 1
  fi
fi
echo "Using datum-cloud/network CRDs at ${NETWORK_SHA} (${NETWORK_REF})"
NETWORK_CRD_URL="https://raw.githubusercontent.com/datum-cloud/network/${NETWORK_SHA}/config/crd"

# VPC/VPCAttachment CRDs come from the separate companion VPC operator,
# datum-cloud/cloud. Nothing in this repo's Go code imports it (the CNI
# plugin only reads VPC/VPCAttachment identifiers as plain JSON fields off
# the NAD), so there's no go.mod pseudo-version to derive a SHA from — pin
# one explicitly here and bump it by hand when the VPC CRD schema changes.
CLOUD_SHA="71a4f0f9c12166a758da4e2b90c80a17709804f2"
CLOUD_CRD_URL="https://raw.githubusercontent.com/datum-cloud/cloud/${CLOUD_SHA}/config/crd"

# Install whatever network's own config/crd/kustomization.yaml lists at
# NETWORK_SHA, so a CRD added upstream is picked up without editing this
# script. A missing CRD isn't benign: galactic-router's manager registers
# watches unconditionally and crash-loops on a cache-sync timeout if any
# watched kind is absent.
mapfile -t network_crds < <(
  curl -fsSL --retry 3 --retry-delay 2 --retry-connrefused "${NETWORK_CRD_URL}/kustomization.yaml" |
    awk '$1 == "-" && $2 ~ /\.yaml$/ {print $2}'
)
if [[ ${#network_crds[@]} -eq 0 ]]; then
  echo "error: no CRDs listed in ${NETWORK_CRD_URL}/kustomization.yaml" >&2
  exit 1
fi

cloud_crds=(
  cloud.datumapis.com_vpcs.yaml
  cloud.datumapis.com_vpcattachments.yaml
)

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Applying system to ${node}..."

  # Install CRDs from GitHub before any namespace-scoped resources.
  # -f makes curl exit non-zero on a 4xx/5xx instead of piping an empty/
  # error body into "kubectl apply -f -" (which fails opaquely with
  # "no objects passed to apply"); --retry rides out transient GitHub
  # hiccups (rate-limits, cold CDN cache) instead of failing the deploy.
  for crd in "${network_crds[@]}"; do
    curl -fsSL --retry 3 --retry-delay 2 --retry-connrefused "${NETWORK_CRD_URL}/${crd}" | docker exec -i "${node}" kubectl apply -f -
  done
  for crd in "${cloud_crds[@]}"; do
    curl -fsSL --retry 3 --retry-delay 2 --retry-connrefused "${CLOUD_CRD_URL}/${crd}" | docker exec -i "${node}" kubectl apply -f -
  done

  copy_config "${node}"
  apply_f "${node}" /galactic/config/galactic-system/namespace.yaml
  apply_f "${node}" /galactic/config/galactic-cni/serviceaccount.yaml
  apply_f "${node}" /galactic/config/galactic-cni/rbac.yaml
  apply_f "${node}" /galactic/config/galactic-router/serviceaccount.yaml
  apply_f "${node}" /galactic/config/galactic-router/rbac.yaml
  apply_f "${node}" /galactic/config/galactic-nat/serviceaccount.yaml
  apply_f "${node}" /galactic/config/galactic-nat/rbac.yaml
done

echo "Done."
