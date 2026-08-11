#!/bin/bash
# deploy-cni.sh — Install Cilium and Multus, then the galactic-cni
# DaemonSet, on every cluster. The DaemonSet copies the galactic-cni and
# host-device binaries onto each node's /opt/cni/bin via a hostPath mount
# and maintains a kubeconfig built from its own ServiceAccount token, so pod
# attach (CNI ADD/DEL) works without any manual credential setup. Requires
# deploy:system (galactic-cni RBAC) and deploy:images (galactic-cni:latest
# loaded) first.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# The configmap/daemonset base lives in config/cni/ (shared with
# production); resources/galactic-cni/kustomization.yaml patches in the
# lab-only image. It's copied into resources/galactic-cni/base/ on the
# node at deploy time (kustomize requires resources in or below the overlay
# root) rather than duplicated in the repo.
GALACTIC_CNI_DIR=$(cd "${SCRIPT_DIR}/../../../config/cni" && pwd)

CILIUM_VERSION="v0.18.8"
MULTUS_VERSION="v4.2.3"

ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then ARCH=arm64; fi

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Installing galactic-cni on ${site}..."

  # Cilium — explicit IPv6 flags required: the clusters are IPv6-only
  # (ipFamily: ipv6) and without these flags Cilium may allocate IPv4
  # addresses from its 10.0.0.0/8 default pool. Pods with IPv4 can't
  # reach the IPv6 API server ([fd00:200::1]:443) and crash-loop.
  docker exec "${node}" bash -c "
    curl -sL https://github.com/cilium/cilium-cli/releases/download/${CILIUM_VERSION}/cilium-linux-${ARCH}.tar.gz | tar xz -C /usr/local/bin
    chmod +x /usr/local/bin/cilium
    cilium install \
      --set ipv4.enabled=false \
      --set ipv6.enabled=true \
      --set ipv6.clusterPoolIPv6ClusterCIDR=fd00:100::/48 \
      --set ipv6.clusterPoolIPv6MaskSize=64 \
      --set cni.exclusive=false \
      --set kubeProxyReplacement=true \
      --set kubeProxyReplacement.healthzBindAddress=:9879
    cilium status --wait
  "

  # Kind installs local-path-provisioner by default (disableDefaultCNI
  # only disables kindnet, not the storage provisioner). It gets an IPv4
  # address and can't reach the IPv6 API server — delete it before it
  # starts crash-looping. Cilium replaces kindnet; we don't need local-path.
  docker exec "${node}" kubectl delete deployment local-path-provisioner -n local-path-storage --ignore-not-found

  # Multus
  docker exec "${node}" kubectl apply -f "https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/refs/tags/${MULTUS_VERSION}/deployments/multus-daemonset-thick.yml"
  docker exec "${node}" kubectl -n kube-system rollout status daemonset kube-multus-ds

  # docker cp nests SRC inside an existing DEST dir instead of overwriting
  # it, so a rerun against an already-provisioned node would silently keep
  # serving the prior kustomization.yaml/base/ from underneath the new copy.
  docker exec "${node}" rm -rf /galactic/resources/galactic-cni
  copy_to "${node}" galactic-cni
  docker cp "${GALACTIC_CNI_DIR}" "${node}:/galactic/resources/galactic-cni/base"

  apply_k "${node}" /galactic/resources/galactic-cni/
  docker exec "${node}" kubectl -n galactic-system rollout status daemonset galactic-cni
done

echo "Done."
