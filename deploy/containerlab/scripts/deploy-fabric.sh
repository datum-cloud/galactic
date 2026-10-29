#!/bin/bash
# deploy-fabric.sh — Install the FRR fabric DaemonSet on every cluster.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# config/fabric-router/ (shared with production) is a single DaemonSet whose
# affinity allows any node carrying galactic.datumapis.com/fabric=router,
# regardless of its galactic.datumapis.com/node value or
# galactic.datumapis.com/galactic mode. resources/fabric-router/base/ builds
# on a copy of it and patches in nothing but the lab-only
# image/imagePullPolicy -- one DaemonSet per cluster covers every role,
# since fabric-config-agent reads each node's own fabric-router.<nodename>
# ConfigMap via NODE_NAME and each site's kustomization generates one such
# ConfigMap per matching node. Re-running this after editing one node's
# frr.conf changes only that node's ConfigMap, which its config-agent
# sidecar reloads in place -- no pod restarts. copy_to (lib.sh) copies
# resources/fabric-router/ onto the control-plane node, replacing an
# already-provisioned copy, and copy_fabric_config (lib.sh) nests
# config/fabric-router/ under it as base/fabric, inside the overlay's own
# root, since kustomize requires resources in or below that root.
for site in dfw iad sjc; do
  node=$(control_plane "${site}")
  copy_to "${node}" fabric-router
  copy_fabric_config "${node}"
  apply_k "${node}" "/galactic/resources/fabric-router/${site}/"
done

# iad-control-plane also carries the galactic-router route-reflector
# resources, applied by deploy-galactic-router.sh -- copied here so both
# land in one pass.
node=$(control_plane iad)
echo "Copying resources to ${node}..."
copy_to "${node}" galactic-router
copy_to "${node}" galactic-control

echo "Done."
