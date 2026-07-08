#!/bin/bash
# deploy-cni.sh — Install the galactic-cni DaemonSet on every cluster. The
# DaemonSet copies the galactic-cni and host-device binaries onto each
# node's /opt/cni/bin via a hostPath mount and maintains a kubeconfig built
# from its own ServiceAccount token, so pod attach (CNI ADD/DEL) works
# without any manual credential setup. Requires deploy:system (galactic-cni
# RBAC) and deploy:images (galactic-cni:latest loaded) first.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Installing galactic-cni on ${site}..."
  copy_to "${node}" cni
  apply_f "${node}" /galactic/resources/cni/configmap.yaml
  apply_f "${node}" /galactic/resources/cni/daemonset.yaml
  docker exec "${node}" kubectl -n galactic-system rollout status daemonset galactic-cni
done

echo "Done."
