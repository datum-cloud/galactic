#!/bin/bash
# deploy-cert-manager.sh — Install cert-manager and its csi-driver in every
# cluster, ahead of deploy:fabric.
#
# The fabric-api Component's fabric-api-certs DaemonSet gets each node's
# certificate from a csi-driver volume and hands it to the fabric-router pod
# through a hostPath, so the driver must run on every fabric node before
# deploy:fabric. A csi-driver volume blocks its pod until the certificate is
# issued, even with the driver's continueOnNotReady (which only covers the
# driver's own readiness gates); that is why the volume lives in its own pod
# and not in fabric-router's. verify:fabric-api-bootstrap checks it. Workers
# carry role taints, so the driver tolerates everything, like fabric-router
# itself.
#
# The webhook runs on the host network: in this lab the control-plane node
# cannot reach pod addresses on the workers over Cilium's tunnel, so the
# kube-apiserver could never call a pod-network webhook, but it reaches a
# worker's own address directly over the Kind network.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

CERT_MANAGER_VERSION=v1.21.2
CSI_DRIVER_VERSION=v0.16.0

for site in dfw iad sjc; do
  kc=$(site_kubeconfig "${site}")
  echo "Installing cert-manager ${CERT_MANAGER_VERSION} on ${site}..."
  helm upgrade --install cert-manager oci://quay.io/jetstack/charts/cert-manager \
    --version "${CERT_MANAGER_VERSION}" --kubeconfig "${kc}" \
    --namespace cert-manager --create-namespace \
    --set crds.enabled=true \
    --set webhook.hostNetwork=true --set webhook.securePort=10260 \
    --wait --timeout 10m
  echo "Installing cert-manager csi-driver ${CSI_DRIVER_VERSION} on ${site}..."
  helm upgrade --install cert-manager-csi-driver oci://quay.io/jetstack/charts/cert-manager-csi-driver \
    --version "${CSI_DRIVER_VERSION}" --kubeconfig "${kc}" \
    --namespace cert-manager \
    --set 'tolerations[0].operator=Exists' \
    --wait --timeout 10m
done
echo "Done."
