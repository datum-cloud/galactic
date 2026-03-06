#!/bin/bash
set -xe

SRV6_PREFIX="2001:db8:ff00::/40"

CILIUM_VERSION="v0.18.8"
CERTMANAGER_VERSION="v1.19.1"
MULTUS_VERSION="v4.2.3"
CNI_PLUGIN_VERSION="v1.8.0"
GALACTIC_OPERATOR_VERSION="v0.0.5"
GALACTIC_ROUTER_VERSION="v0.0.5"
GALACTIC_AGENT_VERSION="v0.0.5"
GALACTIC_CNI_VERSION="v0.0.5"

ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then ARCH=arm64; fi

if hostname |grep -q control-plane; then # control-plane
  until kubectl get nodes; do # wait for control-plane to be ready
    sleep 1
  done

  # Cilium
  curl -L https://github.com/cilium/cilium-cli/releases/download/${CILIUM_VERSION}/cilium-linux-${ARCH}.tar.gz |tar xvfz - -C /usr/local/bin && chmod +x /usr/local/bin/cilium
  cilium install --set cni.exclusive=false && cilium status --wait

  # Cert Manager
  kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/${CERTMANAGER_VERSION}/cert-manager.yaml
  kubectl -n cert-manager rollout status deployment cert-manager

  # Multus
  kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/refs/tags/${MULTUS_VERSION}/deployments/multus-daemonset-thick.yml
  kubectl -n kube-system rollout status daemonset kube-multus-ds

  # MQTT
  kubectl apply -f /galactic/mqtt.k8s.yml
  kubectl -n galactic-mqtt rollout status deployment galactic-mqtt

  # Galactic Operator
  curl -L "https://raw.githubusercontent.com/datum-cloud/galactic-operator/refs/heads/main/dist/install.yaml" |sed -e "s/galactic-operator:latest/galactic-operator:${GALACTIC_OPERATOR_VERSION}/g" |kubectl apply -f -
  kubectl -n galactic-operator-system rollout status deployment galactic-operator-controller-manager

  # Galactic Router
  cat /galactic/router.k8s.yml |sed -e "s/galactic-router:latest/galactic-router:${GALACTIC_ROUTER_VERSION}/g" |kubectl apply -f -
  kubectl -n galactic-router rollout status deployment galactic-router

  # Galactic Agent
  cat /galactic/agent.k8s.yml |sed -e "s/galactic-agent:latest/galactic-agent:${GALACTIC_AGENT_VERSION}/g" |kubectl apply -f -
  kubectl -n galactic-agent rollout status daemonset galactic-agent
else # worker
  until journalctl -q -u kubelet -g "Successfully registered node"; do
    sleep 1
  done
  until ip6tables -L KUBE-FORWARD; do
    sleep 1
  done

  # SRv6 prefix forwarding
  ip6tables -I FORWARD 1 -s ${SRV6_PREFIX} -j ACCEPT
  ip6tables -I FORWARD 1 -d ${SRV6_PREFIX} -j ACCEPT

  modprobe --quiet --dry-run vrf && modprobe vrf
  sysctl -w net.vrf.strict_mode=1

  for iface in eth1 all default lo-galactic; do
    sysctl -w net.ipv4.conf.$iface.forwarding=1
    sysctl -w net.ipv4.conf.$iface.rp_filter=0
    sysctl -w net.ipv6.conf.$iface.forwarding=1
    sysctl -w net.ipv6.conf.$iface.accept_ra=0
    sysctl -w net.ipv6.conf.$iface.autoconf=0
    sysctl -w net.ipv6.conf.$iface.seg6_enabled=1
  done

  # CNI Plugins
  curl -L "https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGIN_VERSION}/cni-plugins-linux-${ARCH}-${CNI_PLUGIN_VERSION}.tgz" |tar xvfz - -C /opt/cni/bin

  # Galactic CNI
  curl -Lo /opt/cni/bin/galactic "https://github.com/datum-cloud/galactic-cni/releases/download/${GALACTIC_CNI_VERSION}/galactic_${ARCH}" && chmod +x /opt/cni/bin/galactic
fi
