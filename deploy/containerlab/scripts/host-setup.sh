#!/bin/bash
# host-setup.sh — Prepare the host for Containerlab labs. Raises inotify
# limits for Kind clusters, enables IPv4/IPv6 forwarding, and loads the
# bonding module, all for this session only; nothing is persisted across
# reboots.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: must run as root (use sudo)" >&2
  exit 1
fi

echo "==> Containerlab host setup"
echo ""

echo "--> Setting inotify limits for Kind clusters"
sysctl -w fs.inotify.max_user_instances=1024
sysctl -w fs.inotify.max_user_watches=524288

echo "--> Enabling IPv6 forwarding"
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv6.conf.default.forwarding=1

echo "--> Enabling IPv4 forwarding (required for Docker NAT)"
sysctl -w net.ipv4.ip_forward=1

echo "--> Loading the bonding module"
# Every datapath-carrying link in the lab is an LACP bond (gvpc.clab.yaml).
# Bonds are created inside each node's own network namespace, but the driver
# is the host kernel's, and a container has no module tree to load it from.
modprobe bonding

echo ""
echo "==> Verification"
echo "    net.ipv6.conf.all.forwarding       = $(sysctl -n net.ipv6.conf.all.forwarding)"
echo "    net.ipv6.conf.default.forwarding   = $(sysctl -n net.ipv6.conf.default.forwarding)"
echo "    net.ipv4.ip_forward                = $(sysctl -n net.ipv4.ip_forward)"
echo "    fs.inotify.max_user_instances      = $(sysctl -n fs.inotify.max_user_instances)"
echo "    fs.inotify.max_user_watches        = $(sysctl -n fs.inotify.max_user_watches)"
echo "    bonding module                     = $(lsmod | awk '$1 == "bonding" {print "loaded"; f=1} END {if (!f) print "MISSING"}')"
echo ""
echo "==> Done. Host is ready for Containerlab."
