#!/bin/sh
set -eu
. /opt/lab/startup-lib.sh

wait_for_interface eth1
ip link set eth1 up

sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1

install -d -o frr -g frr -m 775 /run/frr
install -d -o frr -g frr -m 775 /var/log/frr
/usr/lib/frr/frrinit.sh start

wait_for_addr fc00:0:8::1 || log "rr2 loopback not yet programmed"

exec tail -f /dev/null
