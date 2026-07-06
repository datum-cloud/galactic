#!/bin/bash
# lib.sh — shared helpers for containerlab deploy-*.sh scripts. Sourced, not executed.

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RESOURCES_DIR="${SCRIPT_DIR}/../resources"

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
