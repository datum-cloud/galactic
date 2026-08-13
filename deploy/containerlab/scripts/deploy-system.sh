#!/bin/bash
# deploy-system.sh — Install BGP CRDs (datum-cloud/network) and VPC CRDs
# (datum-cloud/cloud), then apply the galactic-system namespace and shared
# RBAC (galactic-cni, galactic-router) to every cluster. The namespace and
# ServiceAccount/RBAC manifests are applied straight from the repo's
# config/ — the same ones used in production — so the lab never forks them.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# Extract the datum-cloud/network commit SHA from go.mod (pseudo-version
# suffix after the last hyphen, e.g. v0.0.0-20260708202618-77cf276d17f1 →
# 77cf276d17f1). $1 must match the require line's module path exactly, not
# just a substring, so an unrelated line can't corrupt NETWORK_SHA.
NETWORK_SHA=$(awk '$1 == "go.datum.net/network" {print $2}' "${SCRIPT_DIR}/../../../go.mod" | sed 's/.*-//')
NETWORK_CRD_URL="https://raw.githubusercontent.com/datum-cloud/network/${NETWORK_SHA}/config/crd"

# VPC/VPCAttachment CRDs come from the separate companion VPC operator,
# datum-cloud/cloud. Nothing in this repo's Go code imports it (the CNI
# plugin only reads VPC/VPCAttachment identifiers as plain JSON fields off
# the NAD), so there's no go.mod pseudo-version to derive a SHA from — pin
# one explicitly here and bump it by hand when the VPC CRD schema changes.
CLOUD_SHA="71a4f0f9c12166a758da4e2b90c80a17709804f2"
CLOUD_CRD_URL="https://raw.githubusercontent.com/datum-cloud/cloud/${CLOUD_SHA}/config/crd"

network_crds=(
  network.datumapis.com_bgpadvertisements.yaml
  network.datumapis.com_bgppeers.yaml
  network.datumapis.com_bgppolicies.yaml
  network.datumapis.com_bgprouters.yaml
  network.datumapis.com_bgpvrfinstances.yaml
  network.datumapis.com_networkgateways.yaml
  network.datumapis.com_networkrules.yaml
  network.datumapis.com_networkegresspolicies.yaml
)

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
  apply_f "${node}" /galactic/config/system/namespace.yaml
  apply_f "${node}" /galactic/config/cni/serviceaccount.yaml
  apply_f "${node}" /galactic/config/cni/rbac.yaml
  apply_f "${node}" /galactic/config/router/serviceaccount.yaml
  apply_f "${node}" /galactic/config/router/rbac.yaml
done

echo "Done."
