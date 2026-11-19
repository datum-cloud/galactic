#!/bin/bash
# edge-worker.sh: run galactic-edge on dfw's edge nodes against Galactic
# Worker (docs/worker/connector.md), and roll it back.
#
# Lab-only, like worker-fabric.sh: Worker has no manifests yet, so it runs as
# a process inside each edge node, with an allowlist letting galactic-router
# hand it routes and galactic-edge claim its edge links. galactic-edge's
# DaemonSet is patched with --worker-socket, the /run/galactic-worker mount and
# a projected token with audience galactic-worker.
#
# Usage:
#   edge-worker.sh enable    start Worker on dfw-worker2 and dfw-worker3,
#                            switch galactic-edge to Worker, and wait until every
#                            dfw edge attachment is Programmed and every VPC
#                            scope of one is Worker's
#   edge-worker.sh disable   stop Worker, hand its scopes back with
#                            HANDBACK_BIN (a binary run inside each node with
#                            the fence directory as its argument, as
#                            galactic-worker handback does), undo the patch, and
#                            wait until galactic-edge owns its scopes again
#   edge-worker.sh status    print the fence records and edge attachments
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

SITE=dfw
EDGE_NODES="dfw-worker2 dfw-worker3"
FENCE_DIR=/var/lib/galactic-edge/ownership
SOCKET=/run/galactic-worker/worker.sock
cp_node=$(control_plane "${SITE}")

k() { docker exec "${cp_node}" kubectl "$@"; }

# attachments prints each dfw edge attachment on an edge node: name, node, VPC
# and Programmed condition.
attachments() {
  k get edgeattachments -A -o json | jq -r '.items[] | select(.status.nodeName != null) |
    "\(.metadata.namespace)/\(.metadata.name) \(.status.nodeName) \(.status.vpc) \((.status.conditions // [])
      | map(select(.type == "Programmed")) | .[0].status // "Unknown")"'
}

# vpc_scopes prints NODE's fence records of the VPCs its edge attachments use.
vpc_scopes() {
  local node=$1 vpc
  for vpc in $(k get edgeattachments -A -o json |
    jq -r --arg n "${node}" '.items[] | select(.status.nodeName == $n) | .status.vpc' | sort -u); do
    vpc=$(echo "${vpc}" | sed 's/^0*//')
    docker exec "${node}" sh -c "cat ${FENCE_DIR}/vpc-${vpc}.json 2>/dev/null || echo '{}'" |
      jq -c --arg s "vpc-${vpc}" '{scope: $s, owner, generation, pending}'
  done
}

# wait_for runs the check named by its arguments until it succeeds, for up to
# five minutes.
wait_for() {
  local what=$1
  shift
  for _ in $(seq 150); do
    if "$@"; then
      echo "${what}: yes"
      return 0
    fi
    sleep 2
  done
  echo "${what}: timed out" >&2
  status >&2
  return 1
}

# all_programmed checks that every dfw edge attachment is Programmed. With
# none, as on a fresh deploy before a provider attaches, there is nothing to
# wait for.
all_programmed() {
  local out
  out=$(attachments)
  [ -z "${out}" ] || ! grep -qv ' True$' <<<"${out}"
}

# scopes_owned_by checks that every edge VPC scope on the edge nodes has an
# owner starting with $1.
scopes_owned_by() {
  local node
  for node in ${EDGE_NODES}; do
    if vpc_scopes "${node}" | jq -e --arg p "$1" '(.owner // "") | startswith($p) | not' >/dev/null; then
      return 1
    fi
  done
  return 0
}

status() {
  local node
  echo "== edge attachments"
  attachments
  for node in ${EDGE_NODES}; do
    echo "== ${node} edge VPC scopes"
    vpc_scopes "${node}"
  done
}

enable() {
  local allow
  allow=$(mktemp)
  trap 'rm -f "${allow}"' RETURN
  cat >"${allow}" <<'EOF'
serviceAccounts:
  - serviceAccount: galactic-system/galactic-router
    capabilities: [fabric.routes]
  - serviceAccount: galactic-system/galactic-edge
    capabilities: [local.routed_link]
EOF
  NODES="${EDGE_NODES}" WORKER_ALLOWLIST="${allow}" "${SCRIPT_DIR}/worker-fabric.sh" start
  k -n galactic-system patch daemonset galactic-edge --type=json -p "$(
    cat <<EOF
[
  {"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--worker-socket=${SOCKET}"},
  {"op": "add", "path": "/spec/template/spec/containers/0/volumeMounts/-",
   "value": {"name": "galactic-worker", "mountPath": "/run/galactic-worker"}},
  {"op": "add", "path": "/spec/template/spec/containers/0/volumeMounts/-",
   "value": {"name": "galactic-worker-token", "mountPath": "/var/run/secrets/galactic-worker", "readOnly": true}},
  {"op": "add", "path": "/spec/template/spec/volumes/-",
   "value": {"name": "galactic-worker", "hostPath": {"path": "/run/galactic-worker", "type": "DirectoryOrCreate"}}},
  {"op": "add", "path": "/spec/template/spec/volumes/-",
   "value": {"name": "galactic-worker-token", "projected": {"sources": [{"serviceAccountToken":
     {"audience": "galactic-worker", "expirationSeconds": 3600, "path": "token"}}]}}}
]
EOF
  )"
  k -n galactic-system rollout status daemonset/galactic-edge --timeout=180s
  wait_for "every dfw edge attachment Programmed" all_programmed
  wait_for "every edge VPC scope Worker's" scopes_owned_by "galactic-worker:"
  status
}

disable() {
  local node
  : "${HANDBACK_BIN:?HANDBACK_BIN must name the handback binary}"
  NODES="${EDGE_NODES}" "${SCRIPT_DIR}/worker-fabric.sh" stop
  for node in ${EDGE_NODES}; do
    docker cp "${HANDBACK_BIN}" "${node}:/opt/galactic-worker/handback"
    docker exec "${node}" /opt/galactic-worker/handback "${FENCE_DIR}"
    docker exec "${node}" rm -f /opt/galactic-worker/handback
  done
  if k -n galactic-system get daemonset galactic-edge -o json |
    jq -e '.spec.template.spec.containers[0].args | any(startswith("--worker-socket"))' >/dev/null; then
    k -n galactic-system rollout undo daemonset/galactic-edge
  fi
  k -n galactic-system rollout status daemonset/galactic-edge --timeout=180s
  if k -n galactic-system get daemonset galactic-edge -o json |
    jq -e '.spec.template.spec.containers[0].args | any(startswith("--worker-socket"))' >/dev/null; then
    echo "galactic-edge still runs with --worker-socket" >&2
    return 1
  fi
  wait_for "every dfw edge attachment Programmed" all_programmed
  wait_for "every edge VPC scope galactic-edge's" scopes_owned_by "galactic-edge/"
  status
}

case "${1:-}" in
  enable) enable ;;
  disable) disable ;;
  status) status ;;
  *)
    sed -n '2,21p' "$0" >&2
    exit 2
    ;;
esac
