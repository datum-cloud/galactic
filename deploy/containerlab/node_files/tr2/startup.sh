#!/bin/sh
set -eu
. /opt/lab/startup-lib.sh

wait_for_interface eth2
wait_for_interface eth3
wait_for_interface eth4
ip link set eth2 up
ip link set eth3 up
ip link set eth4 up

# Edge-facing links are LACP bonds, the far end built by the same script on
# the edge node (see gvpc.clab.yaml's links comment and mkbond.sh). mkbond.sh
# waits for its members itself.
/opt/lab/mkbond.sh bond1 eth1 eth5   # sjc-worker2

sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1

install -d -o frr -g frr -m 775 /run/frr
install -d -o frr -g frr -m 775 /var/log/frr
/usr/lib/frr/frrinit.sh start

exec tail -f /dev/null
