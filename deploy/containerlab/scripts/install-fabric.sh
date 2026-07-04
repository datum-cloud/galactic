#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
RESOURCES_DIR="${SCRIPT_DIR}/../resources"

# Copy the fabric tree once — all sites share the same source.
docker cp "${RESOURCES_DIR}/fabric" dfw-control-plane:/galactic/resources/
docker cp "${RESOURCES_DIR}/fabric" sjc-control-plane:/galactic/resources/

# Apply fabric per site (kustomize overlays).
docker exec dfw-control-plane kubectl apply -k /galactic/resources/fabric/dfw/
docker exec sjc-control-plane kubectl apply -k /galactic/resources/fabric/sjc/

# iad-control-plane needs fabric + control/fabric — batch all copies together.
echo "Copying resources to iad-control-plane..."
docker cp "${RESOURCES_DIR}/fabric" iad-control-plane:/galactic/resources/
docker cp "${RESOURCES_DIR}/control" iad-control-plane:/galactic/resources/
docker cp "${RESOURCES_DIR}/tenant" iad-control-plane:/galactic/resources/
docker cp "${RESOURCES_DIR}/bgp/tenant" iad-control-plane:/galactic/resources/bgp-tenant/
docker cp "${RESOURCES_DIR}/bgp/control" iad-control-plane:/galactic/resources/bgp-control/

# iad fabric is a kustomize overlay; control/fabric is raw manifests.
docker exec iad-control-plane kubectl apply -k /galactic/resources/fabric/iad/
docker exec iad-control-plane kubectl apply -f /galactic/resources/control/fabric/iad/

echo "Done."
