// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostgw

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// neighSolicitDialTimeout bounds the solicit dial. A guest not answering
	// yet is the common case, the VM may not have booted, and the next
	// reconcile retries, so this stays short.
	neighSolicitDialTimeout = 500 * time.Millisecond
	// neighResolveTimeout bounds the poll for a solicited entry to appear. A
	// live guest answers in well under a millisecond; this is headroom.
	neighResolveTimeout = 1 * time.Second
	neighPollInterval   = 50 * time.Millisecond
	// discardPort is soliciting traffic's destination. Nothing needs to
	// listen -- see solicitVRFNeighbor.
	discardPort = "9"
)

// EnsureTapGuestNeighbors resolves the neighbor entry for every guest behind a
// tap attachment on this node, so usid_ingress can deliver decapsulated traffic
// to it. It returns how many were resolved and how many are still pending.
//
// bpf_fib_lookup does not trigger NDP the way ordinary forwarding does, so an
// unresolved neighbor makes it return NO_NEIGH and the packet is dropped. For a
// veth the CNI primes a permanent entry at ADD from the guest end's known MAC.
// A tap has no guest-side link in this namespace to read a MAC from, the guest
// picking its own address, so no entry was ever installed and every packet
// dropped.
//
// So resolve it the only way available, by asking the guest. This deliberately
// does not install a permanent entry the way the veth path does: the host never
// learns a tap guest's MAC authoritatively, and a permanent entry holding a
// stale one after a guest reboots is worse than none, since nothing would
// correct it. A dynamically resolved entry is what the lookup needs, any valid
// state satisfying it, the kernel refreshes it from the guest's own
// advertisements, and this re-solicits whenever it falls out of the cache.
//
// Everything needed comes from kernel state, so nothing is persisted at ADD
// time and a guest that boots long after its ADD is picked up on a later pass:
// for each tap enslaved to a VPC VRF, the guest prefixes are the routes in that
// VRF's table pointing at the tap.
//
// Errors are per attachment and never abort the sweep: one guest that is down
// must not stop the others.
func EnsureTapGuestNeighbors() (resolved, pending int) {
	links, err := netlink.LinkList()
	if err != nil {
		slog.Warn("hostgw: could not list links to resolve tap guest neighbors", "err", err)
		return 0, 0
	}

	// Index VRF links so a tap's master resolves to a routing table id.
	vrfByIndex := map[int]*netlink.Vrf{}
	for _, l := range links {
		if v, ok := l.(*netlink.Vrf); ok {
			vrfByIndex[v.Attrs().Index] = v
		}
	}

	for _, l := range links {
		if _, isTap := l.(*netlink.Tuntap); !isTap {
			continue
		}
		attrs := l.Attrs()
		vrf, ok := vrfByIndex[attrs.MasterIndex]
		if !ok {
			continue // not enslaved to a VPC VRF; not ours to resolve
		}
		for _, guest := range guestAddrsForTap(int(vrf.Table), attrs.Index) {
			ok, err := ensureNeighbor(vrf.Attrs().Name, attrs, guest)
			switch {
			case err != nil:
				slog.Warn("hostgw: resolving tap guest neighbor failed",
					"tap", attrs.Name, "guest", guest, "err", err)
				pending++
			case ok:
				resolved++
			default:
				// The ordinary not-yet case: the guest has not booted, or is
				// not answering. Debug, not warn -- the next pass retries.
				slog.Debug("hostgw: tap guest has not answered neighbor solicitation yet",
					"tap", attrs.Name, "guest", guest)
				pending++
			}
		}
	}
	return resolved, pending
}

// guestAddrsForTap returns the guest addresses reachable out this tap, read
// back from the pod-subnet routes in the VPC VRF's own table. Both families,
// since the same drop applies to each.
//
// The filtering is the whole job. A VRF's table carries several routes per tap
// and only one names a guest, so an unfiltered sweep spends its time soliciting
// addresses that can never answer, which on a node with a few guests means
// dozens of candidates and tens of seconds a pass. What the table holds:
//
//	local fd20:0:2::1 dev <tap> proto kernel metric 0     <- host's own gateway addr
//	fd20:0:2::1 dev <tap> proto kernel metric 256         <- its connected route
//	fd20:0:2::3:0:0/96 dev <tap> metric 1024              <- the guest, what we want
//	anycast fe80:: dev <tap> proto kernel metric 0
//	fe80::/64 dev <tap> proto kernel metric 256
//
// So: only unicast routes this component installed itself. Excluding
// kernel-derived routes drops the gateway address and the link-local pair,
// requiring unicast drops the local and anycast entries, and link-local or
// multicast destinations are skipped outright, a guest never being addressed by
// one here.
func guestAddrsForTap(tableID, tapIndex int) []net.IP {
	var out []net.IP
	for _, family := range []int{netlink.FAMILY_V6, netlink.FAMILY_V4} {
		routes, err := netlink.RouteListFiltered(family,
			&netlink.Route{Table: tableID}, netlink.RT_FILTER_TABLE)
		if err != nil {
			continue
		}
		for _, r := range routes {
			if r.LinkIndex != tapIndex || r.Dst == nil {
				continue
			}
			if r.Protocol == unix.RTPROT_KERNEL || r.Type != unix.RTN_UNICAST {
				continue
			}
			ip := r.Dst.IP
			if ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
				continue
			}
			out = append(out, ip)
		}
	}
	return out
}

// ensureNeighbor reports whether guest has a usable neighbor entry on the tap,
// soliciting once and polling if it does not. ok is false with a nil error when
// the guest simply has not answered.
func ensureNeighbor(vrfName string, tap *netlink.LinkAttrs, guest net.IP) (ok bool, err error) {
	if mac, lerr := lookupNeighborMAC(tap.Index, guest); lerr != nil {
		return false, lerr
	} else if mac != nil {
		return true, nil
	}

	solicitVRFNeighbor(vrfName, guest)

	deadline := time.Now().Add(neighResolveTimeout)
	for {
		mac, lerr := lookupNeighborMAC(tap.Index, guest)
		if lerr != nil {
			return false, lerr
		}
		if mac != nil {
			return true, nil
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		time.Sleep(neighPollInterval)
	}
}

// lookupNeighborMAC reads the neighbor cache for guest on linkIndex without
// soliciting, accepting any entry that already carries a hardware address:
// bpf_fib_lookup is satisfied by any valid state, so a stale entry counts.
func lookupNeighborMAC(linkIndex int, guest net.IP) (net.HardwareAddr, error) {
	family := netlink.FAMILY_V6
	if guest.To4() != nil {
		family = netlink.FAMILY_V4
	}
	neighs, err := netlink.NeighList(linkIndex, family)
	if err != nil {
		return nil, fmt.Errorf("list neighbors on link %d: %w", linkIndex, err)
	}
	for _, n := range neighs {
		if n.IP.Equal(guest) && len(n.HardwareAddr) == 6 {
			return n.HardwareAddr, nil
		}
	}
	return nil, nil
}

// solicitVRFNeighbor drives the kernel to resolve guest by sending it a real
// packet, bound to the VPC's VRF device.
//
// The send mirrors the egress route map's own solicit, whose doc comment
// records why an administrative neighbor update does not work here while
// writing a real datagram resolves in well under a millisecond. Nothing need
// listen on the far side; writing the packet is what drives resolution, and its
// fate past this host's output path is irrelevant.
//
// The addition for taps is binding the socket to the VRF device. A guest
// address is routable only in its VPC's table, so an unbound socket would
// resolve against the main table, reaching the default route or nothing, and
// solicit on the wrong interface or not at all.
//
// Errors are ignored deliberately: the caller's poll is the only judge of
// whether this worked.
func solicitVRFNeighbor(vrfName string, guest net.IP) {
	network := "udp6"
	if guest.To4() != nil {
		network = "udp4"
	}
	dialer := &net.Dialer{
		Timeout: neighSolicitDialTimeout,
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, vrfName)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	conn, err := dialer.DialContext(context.Background(), network, net.JoinHostPort(guest.String(), discardPort))
	if err != nil {
		return
	}
	defer conn.Close() //nolint:errcheck // best-effort solicit; nothing to react to either way
	_, _ = conn.Write([]byte{0})
}
