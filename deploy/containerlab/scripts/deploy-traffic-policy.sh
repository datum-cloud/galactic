#!/bin/bash
# deploy-traffic-policy.sh — install interface traffic policy's cell side in
# every cluster: the galactic.datumapis.com CRDs and galactic-controller
# --role=cell (its ServiceAccount, RBAC, and the lab overlay of
# config/galactic-controller/base), then wait until its fail-closed webhook
# admits a policy.
#
# Runs after deploy:cert-manager, which issues the webhook's serving
# certificate, and before deploy:galactic-router, whose traffic policy
# reconciler (GALACTIC_ROUTER_TRAFFIC_POLICY) watches these CRDs and never
# syncs without them. Each tenant's own policies and bindings are applied
# with the tenant (scripts/deploy-tenant-policy.sh).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

CONFIG=$(cd "${SCRIPT_DIR}/../../../config" && pwd)

# A server-side dry run of a valid policy goes through the webhook and stores
# nothing, so it succeeds only once the webhook serves.
PROBE='apiVersion: galactic.datumapis.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: webhook-probe
  namespace: galactic-system
spec:
  rules:
    - name: probe
      action: Deny'

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Installing traffic policy CRDs and galactic-controller on ${site}..."
  docker exec "${node}" rm -rf /galactic/traffic-policy
  docker exec "${node}" mkdir -p /galactic/traffic-policy
  docker cp "${CONFIG}/crd" "${node}:/galactic/traffic-policy/crd"
  docker cp "${CONFIG}/galactic-controller" "${node}:/galactic/traffic-policy/galactic-controller"
  apply_k "${node}" /galactic/traffic-policy/crd/
  docker exec "${node}" kubectl wait --for=condition=Established --timeout=60s \
    crd/trafficpolicies.galactic.datumapis.com crd/trafficpolicybindings.galactic.datumapis.com
  # ServiceAccount and RBAC only; the Deployment comes from the lab overlay.
  apply_k "${node}" /galactic/traffic-policy/galactic-controller/

  # Same nesting as deploy-cni.sh: copy_to replaces the overlay, then the
  # production base lands in its base/ leaf.
  copy_to "${node}" galactic-controller
  docker cp "${CONFIG}/galactic-controller/base" "${node}:/galactic/resources/galactic-controller/base"
  apply_k "${node}" /galactic/resources/galactic-controller/
  docker exec "${node}" kubectl -n galactic-system rollout status deployment/galactic-controller --timeout=180s

  echo "Waiting for ${site}'s webhook to admit a policy..."
  for i in $(seq 1 60); do
    if printf '%s\n' "${PROBE}" | docker exec -i "${node}" kubectl create --dry-run=server -f - >/dev/null 2>&1; then
      echo "${site}: webhook serving"
      break
    fi
    if [ "${i}" -eq 60 ]; then
      echo "error: ${site}'s galactic-controller webhook did not admit a policy within 120s" >&2
      printf '%s\n' "${PROBE}" | docker exec -i "${node}" kubectl create --dry-run=server -f - >&2 || true
      exit 1
    fi
    sleep 2
  done
done

echo "Done."
