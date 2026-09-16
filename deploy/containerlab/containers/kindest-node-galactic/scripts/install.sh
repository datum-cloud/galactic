#!/bin/bash
# install.sh — worker node bootstrap: kernel/sysctl state only. No CNI
# plugin binaries are installed here: host-local, loopback, portmap, and
# ptp ship pre-installed in the kindest/node base image, and galactic-cni /
# host-device are installed by the galactic-cni DaemonSet (see
# scripts/deploy-cni.sh, task deploy:cni). Cilium and Multus are also
# installed by deploy-cni.sh; BGP and VPC CRDs by scripts/deploy-system.sh
# (task deploy:system). None of it is baked into this image.
set -xe

SRV6_PREFIX="2001:db8:ff00::/40"

# The underlay's loopback ranges: every node's router-id/loopback address in
# both families (fc00:0:1::1 .. fc00:0:c::1 and 10.255.255.1 .. .103, see the
# tables in deploy/containerlab/README.md). Not the transit link prefixes --
# link-local forwarding between two directly connected nodes is symmetric by
# construction and never reaches the rules below.
UNDERLAY_PREFIX6="fc00::/32"
UNDERLAY_PREFIX4="10.255.255.0/24"

until journalctl -q -u kubelet -g "Successfully registered node"; do
  sleep 1
done
until ip6tables -L KUBE-FORWARD; do
  sleep 1
done

# Allow BGP for FRR node routing daemon. Both families: the transit underlay
# is dual-stack, so each worker runs one eBGP session per address family to
# its transit router (see resources/fabric-router/*/frr.conf.*).
ip6tables -I INPUT 1 -p tcp --dport 179 -j ACCEPT
ip6tables -I INPUT 1 -p tcp --sport 179 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 179 -j ACCEPT
iptables -I INPUT 1 -p tcp --sport 179 -j ACCEPT

# Exempt fabric transit traffic from kube-proxy's KUBE-FORWARD
# `ctstate INVALID -j DROP` rule, which is the first rule of that chain on a
# stock kubeadm node and which this lab has now hit twice for two unrelated
# reasons. Both times the symptom was the same: one half of a flow crosses a
# node without conntrack ever seeing the other half, so the half that does
# reach netfilter matches no tracked flow, is marked INVALID, and is dropped
# on a node that is only forwarding it.
#
# The SRv6 prefix covers #554: an ingress VIP's forward half reaches the
# backend through XDP and inside an encapsulation, both of which bypass
# conntrack, so direct server return means the plain reply is the only half
# netfilter ever sees.
ip6tables -I FORWARD 1 -s ${SRV6_PREFIX} -j ACCEPT
ip6tables -I FORWARD 1 -d ${SRV6_PREFIX} -j ACCEPT

# The underlay prefixes cover the ECMP case. dfw's compute node is dual-homed
# to both of its site's edge nodes, so a loopback-to-loopback flow crossing
# dfw has an ECMP group in each direction -- tr1's, across its two links to
# dfw-worker2 and dfw-worker3, and dfw-worker's own, across eth1 and eth2.
# Each node hashes independently, so the two directions routinely pick
# different edge nodes: confirmed live with `task verify`, where the echo
# request reached dfw-worker over dfw-worker3 and the reply left over
# dfw-worker2, whose conntrack had never seen the request. Nothing here is
# broken -- asymmetric ECMP is normal, and the same reason this script
# already sets rp_filter=0 below. Only the INVALID drop turns it into a
# blackhole, and only for the node in the middle.
#
# Both families, because only the hash keeps IPv4 working: the same pair of
# ECMP groups exists for 10.255.255.0/24 and happens to resolve symmetrically
# today, which is luck, not a property worth depending on.
ip6tables -I FORWARD 1 -s ${UNDERLAY_PREFIX6} -j ACCEPT
ip6tables -I FORWARD 1 -d ${UNDERLAY_PREFIX6} -j ACCEPT
iptables -I FORWARD 1 -s ${UNDERLAY_PREFIX4} -j ACCEPT
iptables -I FORWARD 1 -d ${UNDERLAY_PREFIX4} -j ACCEPT

modprobe --quiet --dry-run vrf && modprobe vrf
sysctl -w net.vrf.strict_mode=1

# Every fabric-facing interface this node actually has, not just eth1: dfw's
# compute node is dual-homed to both of its site's edge nodes and so has eth2
# as well (see deploy/containerlab/gvpc.clab.yaml). Enumerated rather than
# hardcoded so a node with one uplink and a node with two both work here.
FABRIC_IFACES=$(ls -1 /sys/class/net | grep -E '^eth[1-9]$' || true)

for iface in ${FABRIC_IFACES} all default; do
  sysctl -w net.ipv4.conf.$iface.forwarding=1
  sysctl -w net.ipv4.conf.$iface.rp_filter=0
  sysctl -w net.ipv6.conf.$iface.forwarding=1
  sysctl -w net.ipv6.conf.$iface.accept_ra=0
  sysctl -w net.ipv6.conf.$iface.autoconf=0
  sysctl -w net.ipv6.conf.$iface.seg6_enabled=1
done

# Bring up the fabric-facing data-plane interfaces
for iface in ${FABRIC_IFACES}; do
  ip link set dev "${iface}" up
  sysctl -w net.ipv6.conf."${iface}".disable_ipv6=0
  ip link set dev "${iface}" mtu 1500
done
