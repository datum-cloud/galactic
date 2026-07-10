#!/bin/bash
# lib.sh — shared helpers for containerlab deploy-*.sh scripts. Sourced, not executed.

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CONFIG_DIR="${SCRIPT_DIR}/../../../config"

# GALACTIC_CNI_IMAGE / GALACTIC_ROUTER_IMAGE (set by the Taskfile from the
# GALACTIC_TAG var) select which published ghcr.io/datum-cloud image tag
# the lab pulls; galactic-cni/galactic-router are no longer built locally.
# resources/cni/daemonset-patch.yaml and resources/{tenant/base,control/
# tenant/iad}/router-lab-patch.yaml reference these as literal
# __GALACTIC_*_IMAGE__ placeholders so the checked-in files stay
# tag-agnostic; render them into a scratch copy of resources/ so copy_to
# ships the substituted files instead of the placeholders.
: "${GALACTIC_CNI_IMAGE:?GALACTIC_CNI_IMAGE must be set (see Taskfile)}"
: "${GALACTIC_ROUTER_IMAGE:?GALACTIC_ROUTER_IMAGE must be set (see Taskfile)}"

RESOURCES_DIR=$(mktemp -d)
trap 'rm -rf "${RESOURCES_DIR}"' EXIT
cp -r "${SCRIPT_DIR}/../resources/." "${RESOURCES_DIR}/"

for f in "${RESOURCES_DIR}/cni/daemonset-patch.yaml" \
         "${RESOURCES_DIR}/tenant/base/router-lab-patch.yaml" \
         "${RESOURCES_DIR}/control/tenant/iad/router-lab-patch.yaml"; do
  content=$(<"${f}")
  content="${content//__GALACTIC_CNI_IMAGE__/${GALACTIC_CNI_IMAGE}}"
  content="${content//__GALACTIC_ROUTER_IMAGE__/${GALACTIC_ROUTER_IMAGE}}"
  printf '%s\n' "${content}" > "${f}"
done

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
