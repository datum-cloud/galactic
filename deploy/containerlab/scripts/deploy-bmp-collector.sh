#!/bin/bash
# deploy-bmp-collector.sh — Install the lab's single BMP collector on
# iad-worker3, where every galactic-router reaches it over the underlay. Must
# run before deploy-galactic-router.sh starts the routers that stream to it,
# though a router started first only retries until the collector is up.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# config/bmp-collector/ (shared with production) is copied onto the node
# nested under the lab overlay's own root, so its "collector" resource
# reference resolves. copy_to replaces resources/bmp-collector/ first, so
# the docker cp below never lands in an existing DEST (see lib.sh).
COLLECTOR_DIR=$(cd "${SCRIPT_DIR}/../../../config/bmp-collector" && pwd)

node=$(control_plane iad)
copy_to "${node}" bmp-collector
docker cp "${COLLECTOR_DIR}" "${node}:/galactic/resources/bmp-collector/iad/collector"
apply_k "${node}" /galactic/resources/bmp-collector/iad/
docker exec "${node}" kubectl -n galactic-system rollout status deploy/bmp-collector --timeout=180s

echo "Done."
