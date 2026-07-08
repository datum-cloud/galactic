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

# Bring up the transit-facing data-plane interface
ip link set dev eth1 up
sysctl -w net.ipv6.conf.eth1.disable_ipv6=0
ip link set dev eth1 mtu 1500
