#!/bin/bash
set -xe

SRV6_PREFIX="2001:db8:ff00::/40"

CILIUM_VERSION="v0.18.8"
MULTUS_VERSION="v4.2.3"
CNI_PLUGIN_VERSION="v1.8.0"

ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then ARCH=arm64; fi

if hostname |grep -q control-plane; then # control-plane
  until kubectl get nodes; do # wait for control-plane to be ready
    sleep 1
  done

  # Cilium
  curl -L https://github.com/cilium/cilium-cli/releases/download/${CILIUM_VERSION}/cilium-linux-${ARCH}.tar.gz |tar xvfz - -C /usr/local/bin && chmod +x /usr/local/bin/cilium
  cilium install --set cni.exclusive=false --set kubeProxyReplacement=true && cilium status --wait

  # Multus
  kubectl apply -f https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/refs/tags/${MULTUS_VERSION}/deployments/multus-daemonset-thick.yml
  kubectl -n kube-system rollout status daemonset kube-multus-ds

  # Cosmos BGP CRDs (operator not deployed; resources applied by install-tenant.sh)
  kubectl apply -k https://github.com/milo-os/cosmos/config/crd

else # worker
  until journalctl -q -u kubelet -g "Successfully registered node"; do
    sleep 1
  done
  until ip6tables -L KUBE-FORWARD; do
    sleep 1
  done

  # Allow BGP for FRR node routing daemon
  ip6tables -I INPUT 1 -p tcp --dport 179 -j ACCEPT
  ip6tables -I INPUT 1 -p tcp --sport 179 -j ACCEPT

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

  # Galactic CNI plugin and agent
  # Install the binary under a .bin suffix and front it with a wrapper that
  # exports NODE_NAME and GALACTIC_CNI_NODE_NAME from the container hostname.
  # CNI binaries are exec'd directly by the kubelet and do not inherit
  # NODE_NAME from the pod downward API; in Kind the container hostname
  # equals the Kubernetes node name.
  install -m 0755 /galactic/bin/galactic-cni /opt/cni/bin/galactic-cni.bin
  install -m 0755 /galactic/bin/galactic-cni /usr/local/bin/galactic-cni
  cat > /opt/cni/bin/galactic-cni <<'EOF'
#!/bin/sh
export NODE_NAME=$(hostname)
export GALACTIC_CNI_NODE_NAME=$(hostname)
exec /opt/cni/bin/galactic-cni.bin "$@"
EOF
  chmod 0755 /opt/cni/bin/galactic-cni

  # Bring up the transit-facing data-plane interface
  ip link set dev eth1 up
  sysctl -w net.ipv6.conf.eth1.disable_ipv6=0
  ip link set dev eth1 mtu 1500
fi
