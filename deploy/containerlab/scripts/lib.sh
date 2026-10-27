#!/bin/bash
# lib.sh — shared helpers for containerlab deploy-*.sh/verify-*.sh scripts. Sourced, not executed.

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RESOURCES_DIR="${SCRIPT_DIR}/../resources"
CONFIG_DIR="${SCRIPT_DIR}/../../../config"

control_plane() {
  echo "$1-control-plane"
}

# copy_to NODE SRC [DEST]
# SRC is relative to RESOURCES_DIR; DEST defaults to the same path under
# /galactic/resources/ on the node. DEST is replaced, not merged into: docker
# cp copies SRC *into* a DEST that already exists, nesting it one level down,
# so a rerun against a provisioned node would leave the old copy where
# kustomize reads it and `kubectl apply` would report it unchanged. docker cp
# also requires DEST's parent to exist, which matters once SRC nests more
# than one level deep (e.g. "tenants/ns10"), so that is created first.
copy_to() {
  local node="$1" src="$2" dest="${3:-/galactic/resources/${2}/}"
  case "${dest}" in
    *..*)
      echo "copy_to: refusing to replace ${dest}: it contains .." >&2
      return 1
      ;;
    /galactic/?*) ;;
    *)
      echo "copy_to: refusing to replace ${dest}: not under /galactic/" >&2
      return 1
      ;;
  esac
  docker exec "${node}" rm -rf "${dest}"
  docker exec "${node}" mkdir -p "$(dirname "${dest}")"
  docker cp "${RESOURCES_DIR}/${src}" "${node}:${dest}"
}

# copy_config NODE
# Copies the repo's production config/ (system, router, cni manifests) onto
# NODE at /galactic/config/, alongside /galactic/resources/. deploy-system.sh
# applies the namespace/RBAC/ServiceAccount manifests straight from here
# instead of maintaining lab copies. DaemonSet bases are handled separately
# (see deploy-cni.sh and deploy-galactic-router.sh): they're copied into a base/
# subdirectory nested under the consuming kustomization's own root, since
# kubectl apply -k refuses to load resource files from outside that root.
copy_config() {
  local node="$1"
  docker cp "${CONFIG_DIR}" "${node}:/galactic/config"
}

# copy_fabric_config NODE copies config/fabric-router/ onto NODE, nested under
# resources/fabric-router/base/ so the base overlay's "fabric" resource
# reference resolves. rm -rf first: like deploy-galactic-router.sh's
# copy_router_config, docker cp nests SRC inside an already-existing DEST
# dir instead of overwriting it, so a rerun against an already-provisioned
# node would silently keep serving the prior copy from underneath the new
# one -- kubectl would then report the DaemonSet "unchanged" even after a
# real manifest edit (found live: a fabric-lab-patch.yaml affinity fix
# never took effect on a redeploy until this guard was added).
copy_fabric_config() {
  local node="$1"
  docker exec "${node}" rm -rf /galactic/resources/fabric-router/base/fabric
  docker cp "${CONFIG_DIR}/fabric-router" "${node}:/galactic/resources/fabric-router/base/fabric"
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

# pod_name NODE NAMESPACE [LABEL]
# First matching pod's name. LABEL defaults to the "private" NAD's app label.
pod_name() {
  local node="$1" ns="$2" label="${3:-app=private}"
  docker exec "${node}" kubectl get pods -n "${ns}" -l "${label}" -o jsonpath='{.items[0].metadata.name}'
}

# pod_names NODE NAMESPACE [LABEL]
# Space-separated list of all matching pod names.
pod_names() {
  local node="$1" ns="$2" label="${3:-app=private}"
  docker exec "${node}" kubectl get pods -n "${ns}" -l "${label}" -o jsonpath='{.items[*].metadata.name}'
}

# pod_scheduling_node NODE NAMESPACE POD
# The Kubernetes node POD is scheduled onto (.spec.nodeName), e.g. "dfw-worker".
# Not to be confused with this helper's own NODE argument, which — as everywhere
# else in this file — is the docker container kubectl runs in (a site's Kind
# control-plane container), not a scheduling target.
pod_scheduling_node() {
  local node="$1" ns="$2" pod="$3"
  docker exec "${node}" kubectl get pod -n "${ns}" "${pod}" -o jsonpath='{.spec.nodeName}'
}

# pod_ip4 NODE NAMESPACE POD
# POD's IPv4 address on eth0 (the VPC interface). Every ns*/base/pod.yaml
# attaches its NAD via the v1.multus-cni.io/default-network annotation, which
# replaces the pod's primary interface rather than adding a net1 alongside
# it, so the VPC address always lands on eth0.
pod_ip4() {
  local node="$1" ns="$2" pod="$3"
  docker exec "${node}" kubectl exec -n "${ns}" "${pod}" \
    -- ip -4 addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1
}

# pod_ip6 NODE NAMESPACE POD
# POD's global (non-link-local) IPv6 address on eth0 (the VPC interface); see
# pod_ip4 for why eth0 rather than net1.
pod_ip6() {
  local node="$1" ns="$2" pod="$3"
  docker exec "${node}" kubectl exec -n "${ns}" "${pod}" \
    -- ip -6 addr show eth0 | grep 'inet6 ' | grep -v 'scope link' | awk '{print $2}' | cut -d'/' -f1
}

# ping_pod NODE NAMESPACE POD FAMILY_FLAG TARGET_IP
# Ping TARGET_IP from POD. FAMILY_FLAG is -4 or -6.
ping_pod() {
  local node="$1" ns="$2" pod="$3" family="$4" ip="$5"
  docker exec "${node}" kubectl exec -n "${ns}" "${pod}" -- ping "${family}" -c 3 -W 2 "${ip}"
}

# site_kubeconfig SITE writes a current kubeconfig for SITE's Kind cluster to
# a temporary file and prints its path, for host-side tools (helm, kubectl)
# that cannot run inside a node. The kubeconfigs `deploy:clusters` exports go
# stale whenever Kind restarts a cluster on a new API port.
site_kubeconfig() {
  local f
  f=$(mktemp "${TMPDIR:-/tmp}/${1}.kubeconfig.XXXXXX")
  kind get kubeconfig --name "$1" > "${f}"
  echo "${f}"
}

# pick_port sets PORT_PICKED to a client source port in 20000-59999 that no
# earlier call in this run returned. The VIP checks draw each flow's port at
# random rather than counting up: the gateway's flow hash maps consecutive
# ports to correlated Maglev slots, so a run of consecutive ports often lands
# on one backend and proves nothing about the spread. It sets a variable
# rather than printing, so the record of used ports survives the call.
declare -gA PORTS_USED=()
pick_port() {
  local p
  while :; do
    p=$((((RANDOM << 15) | RANDOM) % 40000 + 20000))
    [ -n "${PORTS_USED[${p}]:-}" ] || break
  done
  PORTS_USED[${p}]=1
  PORT_PICKED=${p}
}
