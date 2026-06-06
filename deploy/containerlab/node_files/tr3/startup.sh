#!/bin/sh
set -eu
. /opt/lab/startup-lib.sh

wait_for_interface eth1
wait_for_interface eth2
wait_for_interface eth3
wait_for_interface eth5
ip link set eth1 up
ip link set eth2 up
ip link set eth3 up
ip link set eth5 up

sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1

install -d -o frr -g frr -m 775 /run/frr
install -d -o frr -g frr -m 775 /var/log/frr
/usr/lib/frr/frrinit.sh start

exec tail -f /dev/null
