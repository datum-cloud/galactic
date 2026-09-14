#!/bin/sh
# remote-host — the lab's one off-fabric host, hanging off tr4 (the transit
# router with no site attached). Configures its own dual-stack transit link
# statically and serves nginx on it; it speaks no routing protocol, so tr4
# originates these prefixes on its behalf (node_files/tr4/frr.conf).
set -eu
. /opt/lab/startup-lib.sh

wait_for_interface eth1

# Ignore router advertisements on the transit link. tr4 runs FRR, whose zebra
# emits RAs on a configured interface, and a host that accepts them ends up
# with a SLAAC address it never asked for plus a second default route (via
# tr4's link-local, proto ra) at the same metric as the static one below --
# observed live before this was added. The worker nodes' own bootstrap
# disables both knobs for the same reason (containers/kindest-node-galactic/
# scripts/install.sh). Set before the link comes up, so no RA is ever
# processed.
sysctl -w net.ipv6.conf.eth1.accept_ra=0
sysctl -w net.ipv6.conf.eth1.autoconf=0

ip link set eth1 up

# Match tr4's eth4 (2001:db8:1:40::1/64, 10.1.40.1/24). The host takes ::2/.2
# on the link, the same TR-.1/node-.2 convention every worker uplink uses.
ip -6 addr add 2001:db8:1:40::2/64 dev eth1 || true
ip -4 addr add 10.1.40.2/24 dev eth1 || true

# Everything this host talks to is somewhere behind tr4: the whole fabric,
# every site's nodes, and every tenant's egress source address. A default
# route per family is all it needs -- no per-prefix state, exactly like a
# host sitting on someone else's network.
ip -6 route replace default via 2001:db8:1:40::1 dev eth1
ip -4 route replace default via 10.1.40.1 dev eth1

# The link-local address takes a moment to leave tentative state; nginx
# binding [::]:80 doesn't depend on it, but a curl issued from this host
# immediately after startup does.
wait_for_addr 2001:db8:1:40::2 || log "link address did not settle"

mkdir -p /run/nginx
log "serving on [2001:db8:1:40::2]:80 and 10.1.40.2:80"
exec nginx -g 'daemon off;'
