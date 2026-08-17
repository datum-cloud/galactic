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

# The configmap/daemonset base lives in config/galactic-cni/ (shared with
# production); resources/galactic-cni/kustomization.yaml patches in the
# lab-only image. It's copied into resources/galactic-cni/base/ on the
# node at deploy time (kustomize requires resources in or below the overlay
# root) rather than duplicated in the repo.
GALACTIC_CNI_DIR=$(cd "${SCRIPT_DIR}/../../../config/galactic-cni" && pwd)

CILIUM_VERSION="v0.18.8"
MULTUS_VERSION="v4.2.3"

ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then ARCH=arm64; fi

for site in dfw sjc iad; do
  node=$(control_plane "${site}")
  echo "Installing galactic-cni on ${site}..."

  # Cilium — installed via the cilium CLI (no Helm binary/repo needed;
  # the CLI vendors the chart itself). What looked like the CLI
  # "ignoring --set" was actually stale value keys: Cilium's chart
  # flattened ipv4.enabled/ipv6.enabled into top-level enableIPv4/
  # enableIPv6, so the old nested --set was a silent no-op against the
  # current chart and Cilium fell back to its IPv4 default, allocating
  # from 10.0.0.0/8 — unreachable from these IPv6-only clusters
  # (ipFamily: ipv6). The clusters need Cilium told to disable IPv4 via
  # the current flat keys. Tunnel mode is used since Cilium v1.20
  # requires IPv4 for native routing mode with cluster-pool IPAM.
  docker exec "${node}" bash -c "
    curl -sL https://github.com/cilium/cilium-cli/releases/download/${CILIUM_VERSION}/cilium-linux-${ARCH}.tar.gz | tar xz -C /usr/local/bin
    chmod +x /usr/local/bin/cilium
    cilium install \
      --set enableIPv4=false \
      --set enableIPv6=true \
      --set ipam.mode=cluster-pool \
      --set clusterPoolIPv6.clusterCIDR=fd00:100::/48 \
      --set clusterPoolIPv6.maskSize=64 \
      --set cni.exclusive=false \
      --set kubeProxyReplacement=true \
      --set tunnelProtocol=vxlan \
      --wait --wait-duration 5m
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

  # docker cp copies SRC *into* an already-existing DEST directory
  # (nesting SRC's basename underneath it) instead of overwriting it,
  # which would break kustomize's "../base" resource reference — so
  # rm -rf first and only docker cp into paths that don't yet exist:
  # copy_to lands resources/galactic-cni/ fresh, then the config/galactic-cni/
  # copy targets "base", a leaf copy_to didn't create. A rerun without
  # the rm -rf would otherwise silently keep serving the prior copy from
  # underneath the new nested directory.
  docker exec "${node}" rm -rf /galactic/resources/galactic-cni
  copy_to "${node}" galactic-cni
  docker cp "${GALACTIC_CNI_DIR}" "${node}:/galactic/resources/galactic-cni/base"

  apply_k "${node}" /galactic/resources/galactic-cni/
  docker exec "${node}" kubectl -n galactic-system rollout status daemonset galactic-cni
done

echo "Done."
