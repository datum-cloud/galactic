#!/bin/bash
# lib.sh — shared helpers for containerlab deploy-*.sh scripts. Sourced, not executed.

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RESOURCES_DIR="${SCRIPT_DIR}/../resources"
CONFIG_DIR="${SCRIPT_DIR}/../../../config"

control_plane() {
  echo "$1-control-plane"
}

# copy_to NODE SRC [DEST]
# SRC is relative to RESOURCES_DIR; DEST defaults to the same path under
# /galactic/resources/ on the node.
copy_to() {
  local node="$1" src="$2" dest="${3:-/galactic/resources/${2}/}"
  docker cp "${RESOURCES_DIR}/${src}" "${node}:${dest}"
}

# copy_config NODE
# Copies the repo's production config/ (system, router, cni manifests) onto
# NODE at /galactic/config/, alongside /galactic/resources/. deploy-system.sh
# applies the namespace/RBAC/ServiceAccount manifests straight from here
# instead of maintaining lab copies. DaemonSet bases are handled separately
# (see deploy-cni.sh and deploy-tenant.sh): they're copied into a base/
# subdirectory nested under the consuming kustomization's own root, since
# kubectl apply -k refuses to load resource files from outside that root.
copy_config() {
  local node="$1"
  docker cp "${CONFIG_DIR}" "${node}:/galactic/config"
}

apply_k() {
  local node="$1" path="$2"
  docker exec "${node}" kubectl apply -k "${path}"
}

apply_f() {
  local node="$1" path="$2"
  docker exec -i "${node}" kubectl apply -f "${path}"
}

ensure_namespace() {
  local node="$1" ns="$2"
  docker exec "${node}" sh -c "kubectl create namespace ${ns} --dry-run=client -o yaml | kubectl apply -f -"
}
