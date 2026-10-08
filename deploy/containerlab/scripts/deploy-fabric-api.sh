#!/bin/bash
# deploy-fabric-api.sh — Install the fabric-api looking glass's cell side in
# every cluster: the FabricQuery CRD, the gateway's and janitor's RBAC, the
# lab PKI (a stand-in for the per-cell issuer infra owns in production), and
# the gateway and janitor. The node sidecars come with deploy:fabric, through
# config/fabric-router/components/fabric-api.
#
# Each lab site is one cell; its cell, site and Karmada member cluster name
# are all the site name. Runs host-side through a fresh kubeconfig per site,
# since kustomize can then reach config/ directly.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

for site in dfw iad sjc; do
  kc=$(site_kubeconfig "${site}")
  k() { kubectl --kubeconfig "${kc}" "$@"; }
  echo "Installing fabric-api on ${site}..."
  # The CRD is the lab's copy until the kind ships in the network
  # repository; infra owns it in production.
  k apply --server-side -f "${CONFIG_DIR}/fabric-api/crd/"
  k wait --for condition=established --timeout=60s crd/fabricqueries.network.datumapis.com
  k apply -k "${CONFIG_DIR}/fabric-api/"
  sed "s/CELL_NAME/${site}/g" "${RESOURCES_DIR}/fabric-api/pki/pki.yaml" | k apply -f -
  k -n galactic-system wait --for condition=Ready --timeout=120s certificate/fabric-api-ca certificate/fabric-api-operator
  k apply -k "${RESOURCES_DIR}/fabric-api/gateway/${site}/"
  k -n galactic-system rollout status deployment/fabric-api-gateway --timeout=180s
  rm -f "${kc}"
done
echo "Done."
