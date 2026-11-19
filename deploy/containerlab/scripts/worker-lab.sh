#!/bin/bash
# worker-lab.sh: install galactic-worker from this checkout's manifests on a
# lab site, inspect it, and remove it with the handback
# (docs/worker/operations.md). Images galactic-worker:latest and
# worker-claim:latest must be loaded on the site's nodes (task
# worker:images).
#
# Usage:
#   worker-lab.sh install SITE PROFILE   apply dedicated or combined, wait ready
#   worker-lab.sh uninstall SITE         delete Worker, hand back every node's
#                                        scopes, restart galactic-router there
#   worker-lab.sh inspect SITE NODE      print galactic-worker inspect on NODE
#   worker-lab.sh client-up SITE NODE    start the claim client pod on NODE
#   worker-lab.sh client-down SITE       delete every claim client pod
#   worker-lab.sh nodes SITE             print the nodes Worker runs on
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NS=galactic-system
WORKER_LABEL=app.kubernetes.io/name=galactic-worker
ROUTER_LABEL=app.kubernetes.io/name=galactic-router
DEST=/galactic/resources/galactic-worker

kc() {
  local cp="$1"
  shift
  docker exec -i "${cp}" kubectl "$@"
}

# copy_worker CP copies the lab overlays and this checkout's
# config/galactic-worker, at ${DEST}/config, onto the control plane.
copy_worker() {
  local cp="$1"
  copy_to "${cp}" galactic-worker
  docker cp "${CONFIG_DIR}/galactic-worker" "${cp}:${DEST}/config"
}

# nodes SITE prints the nodes Worker's affinity selects.
nodes() {
  kc "$(control_plane "$1")" get nodes \
    -l 'galactic.datumapis.com/galactic=router,galactic.datumapis.com/node in (compute,edge),!node-role.kubernetes.io/control-plane' \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
}

install() {
  local site="$1" profile="$2" cp
  cp=$(control_plane "${site}")
  case "${profile}" in
    dedicated | combined) ;;
    *)
      echo "worker-lab: profile must be dedicated or combined, not ${profile}" >&2
      return 2
      ;;
  esac
  copy_worker "${cp}"
  apply_k "${cp}" "${DEST}/${profile}"
  kc "${cp}" -n "${NS}" rollout status ds/galactic-worker --timeout=300s
}

# handback SITE NODE runs the handback pod on NODE and prints its log.
handback() {
  local site="$1" node="$2" cp pod phase
  cp=$(control_plane "${site}")
  pod="galactic-worker-handback-${node}"
  kc "${cp}" kustomize "${DEST}/handback" | sed "s/REPLACE_WITH_NODE_NAME/${node}/g" |
    kc "${cp}" apply -f -
  for _ in $(seq 120); do
    phase=$(kc "${cp}" -n "${NS}" get pod "${pod}" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    case "${phase}" in Succeeded | Failed) break ;; esac
    sleep 1
  done
  kc "${cp}" -n "${NS}" logs "${pod}" || true
  kc "${cp}" -n "${NS}" delete pod "${pod}" --wait=true >/dev/null
  if [ "${phase}" != Succeeded ]; then
    echo "worker-lab: handback on ${node} ended ${phase:-without finishing}" >&2
    return 1
  fi
}

uninstall() {
  local site="$1" cp node
  cp=$(control_plane "${site}")
  copy_worker "${cp}"
  kc "${cp}" -n "${NS}" delete ds galactic-worker --ignore-not-found --wait=true
  local left=""
  for _ in $(seq 120); do
    left=$(kc "${cp}" -n "${NS}" get pod -l "${WORKER_LABEL}" -o name)
    [ -z "${left}" ] && break
    sleep 1
  done
  if [ -n "${left}" ]; then
    echo "worker-lab: Worker pods remain: ${left}" >&2
    return 1
  fi
  for node in $(nodes "${site}"); do
    echo "--- handback on ${node} ---"
    handback "${site}" "${node}"
    kc "${cp}" -n "${NS}" delete pod -l "${ROUTER_LABEL}" --field-selector "spec.nodeName=${node}" --wait=true
  done
  kc "${cp}" -n "${NS}" rollout status ds/galactic-router --timeout=300s
  # The rest of config/galactic-worker: RBAC, ServiceAccount, allowlist.
  kc "${cp}" kustomize "${DEST}/dedicated" | kc "${cp}" delete --ignore-not-found -f -
  local cm
  for cm in $(kc "${cp}" -n "${NS}" get configmap -o name); do
    case "${cm}" in
      configmap/galactic-worker-allowlist-*) kc "${cp}" -n "${NS}" delete "${cm}" ;;
    esac
  done
}

inspect() {
  local site="$1" node="$2" cp pod
  cp=$(control_plane "${site}")
  pod=$(kc "${cp}" -n "${NS}" get pod -l "${WORKER_LABEL}" --field-selector "spec.nodeName=${node}" \
    -o jsonpath='{.items[0].metadata.name}')
  kc "${cp}" -n "${NS}" exec "${pod}" -- /galactic-worker inspect "${@:3}"
}

client_up() {
  local site="$1" node="$2" cp
  cp=$(control_plane "${site}")
  copy_worker "${cp}"
  kc "${cp}" kustomize "${DEST}/lab-client" | sed "s/REPLACE_WITH_NODE_NAME/${node}/g" | kc "${cp}" apply -f -
  kc "${cp}" -n "${NS}" wait --for=condition=Ready "pod/worker-lab-client-${node}" --timeout=120s
}

client_down() {
  local cp
  cp=$(control_plane "$1")
  kc "${cp}" -n "${NS}" delete pod -l app.kubernetes.io/name=worker-lab-client --ignore-not-found --wait=true
  kc "${cp}" -n "${NS}" delete serviceaccount galactic-worker-lab-client --ignore-not-found
}

case "${1:-}" in
  install) install "${2:?site}" "${3:?profile}" ;;
  uninstall) uninstall "${2:?site}" ;;
  inspect) inspect "${2:?site}" "${3:?node}" "${@:4}" ;;
  client-up) client_up "${2:?site}" "${3:?node}" ;;
  client-down) client_down "${2:?site}" ;;
  nodes) nodes "${2:?site}" ;;
  *)
    sed -n '2,16p' "$0" >&2
    exit 2
    ;;
esac
