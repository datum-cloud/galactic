#!/bin/bash
# deploy-galactic-edge.sh — run Galactic Edge on dfw, whose two edge nodes
# let a provider move between nodes:
#
#   1. label dfw-worker2 and dfw-worker3 galactic.datumapis.com/edge=enabled;
#   2. apply config/galactic-edge (the agent's and the controller's RBAC, the
#      provider role and the admission policies), which --edge needs first;
#   3. run the device plugin that gives the agent and provider pods
#      /dev/net/tun (config/galactic-edge/tun-device-plugin), which the
#      agent's pods request and so cannot start without;
#   4. run the galactic-edge DaemonSet (resources/galactic-edge, the lab
#      overlay of config/galactic-edge/base);
#   5. restart galactic-controller with --edge (resources/galactic-edge/controller);
#   6. create the VPC objects of ns10 and ns20 and write their fabric
#      identifier, the job datum-cloud/cloud does in production.
#
# Runs after deploy:galactic-router (galactic-edge needs a router with the
# edge-ownership mount, so GC never reclaims a VRF an attachment uses) and
# deploy:scenarios (the tenants' namespaces and policies).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

SITE=dfw
EDGE_NODES="dfw-worker2 dfw-worker3"
node=$(control_plane "${SITE}")

for n in ${EDGE_NODES}; do
  docker exec "${node}" kubectl label node "${n}" galactic.datumapis.com/edge=enabled --overwrite
done

echo "Applying config/galactic-edge on ${SITE}..."
docker exec "${node}" rm -rf /galactic/galactic-edge-config
docker cp "${CONFIG_DIR}/galactic-edge" "${node}:/galactic/galactic-edge-config"
apply_k "${node}" /galactic/galactic-edge-config/

echo "Deploying the TUN device plugin on ${SITE}'s edge nodes..."
# Labs deployed before the plugin moved into config/ run it in kube-system;
# two plugins serving devic.es/tun on one node replace each other's socket.
docker exec "${node}" kubectl -n kube-system delete daemonset tun-device-plugin --ignore-not-found
apply_k "${node}" /galactic/galactic-edge-config/tun-device-plugin/
docker exec "${node}" kubectl -n galactic-system rollout status daemonset/tun-device-plugin --timeout=180s

echo "Deploying the galactic-edge agent on ${SITE}..."
copy_to "${node}" galactic-edge
docker cp "${CONFIG_DIR}/galactic-edge/base" "${node}:/galactic/resources/galactic-edge/agent"
apply_k "${node}" /galactic/resources/galactic-edge/
docker exec "${node}" kubectl -n galactic-system rollout status daemonset/galactic-edge --timeout=180s

echo "Enabling --edge on ${SITE}'s galactic-controller..."
apply_k "${node}" /galactic/resources/galactic-edge/controller/
docker exec "${node}" kubectl -n galactic-system rollout status deployment/galactic-controller --timeout=180s

echo "Creating the VPC objects of ns10 and ns20..."
apply_k "${node}" /galactic/resources/galactic-edge/vpcs/
for vpc in 10 20; do
  docker exec "${node}" kubectl -n "ns${vpc}" patch vpc "${vpc}" --subresource=status --type=merge \
    -p "{\"status\":{\"vpc\":\"${vpc}\"}}"
done
echo "${SITE}: Galactic Edge deployed"
