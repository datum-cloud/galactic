#!/bin/bash
# host-setup.sh — Prepare the host for Containerlab labs. Raises inotify
# limits for Kind clusters and enables IPv4/IPv6 forwarding for this session
# only; sysctls are not persisted across reboots.

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

echo ""
echo "==> Verification"
echo "    net.ipv6.conf.all.forwarding       = $(sysctl -n net.ipv6.conf.all.forwarding)"
echo "    net.ipv6.conf.default.forwarding   = $(sysctl -n net.ipv6.conf.default.forwarding)"
echo "    net.ipv4.ip_forward                = $(sysctl -n net.ipv4.ip_forward)"
echo "    fs.inotify.max_user_instances      = $(sysctl -n fs.inotify.max_user_instances)"
echo "    fs.inotify.max_user_watches        = $(sysctl -n fs.inotify.max_user_watches)"
echo ""
echo "==> Done. Host is ready for Containerlab."
