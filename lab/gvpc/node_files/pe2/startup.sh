#!/bin/sh
set -eu
. /opt/lab/startup-lib.sh

wait_for_interface eth1
ip link set eth1 up

sysctl -w net.vrf.strict_mode=1
sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.seg6_enabled=1
sysctl -w net.ipv6.conf.eth1.seg6_enabled=1

# Program the local VRF and SRv6 data plane before starting control-plane daemons.
ip link add blue type vrf table 100
ip link set blue up
ip link add dummy0 type dummy
ip link set dummy0 master blue
ip link set dummy0 up
ip addr add "$LOCAL_VPN_IP" dev dummy0
ip -6 route add "$LOCAL_SID" encap seg6local action End.DT4 vrftable 100 dev eth1
ip route add "$REMOTE_VPN_PREFIX" vrf blue encap seg6 mode encap.red segs "$REMOTE_SID" dev eth1

install -d -o frr -g frr -m 775 /run/frr
install -d -o frr -g frr -m 775 /var/log/frr
/usr/lib/frr/frrinit.sh start

wait_for_addr "$LOCAL_LOOPBACK"
wait_for_route "$RR_LOOPBACK" || log "rr1 loopback not yet reachable; gobgpd will retry"

gobgpd -f /etc/gobgp/gobgp.conf --api-hosts :50051 --log-level=debug >/var/log/gobgpd.log 2>&1 &
GOBGP_PID=$!

if wait_for_gobgpd; then
  gobgp vrf add blue rd 65000:100 rt both 65000:100 || true
  gobgp vrf blue rib add "$LOCAL_VPN_IP" nexthop "$LOCAL_SID" || true
else
  log "skipping VRF route injection: gobgpd not ready"
fi

wait "$GOBGP_PID"
