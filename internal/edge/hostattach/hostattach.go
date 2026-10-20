// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hostattach provisions host-owned VPC attachments for pods that
// consume a VPC through a socket or a packet device rather than as an ordinary
// CNI workload.
//
// An attachment is a veth pair between the pod and the node. Its host end is
// enslaved to the canonical host VRF of the VPC, the same VRF every ordinary
// workload of that VPC on the node uses, and its pod end to a VRF inside the
// pod. Only the host end's ifindex and the canonical host table are meaningful
// to the node's shared datapath; the pod VRF's table ID and the pod link's
// ifindex are local to the pod and may equal those of any other pod.
//
// Forwarding is explicit in both directions. The host table routes the
// attachment address, and every prefix the attachment serves, to that address
// on the host link, with a permanent neighbor entry, so traffic for a whole
// site prefix never triggers neighbor discovery per destination. The pod VRF's
// default route points at the host link's link-local address, again with a
// permanent neighbor, and an unreachable default behind it keeps a pod packet
// that misses from falling through to the pod's own interfaces. A packet
// consumer additionally gets a TUN device in the pod VRF that the served
// prefixes route to.
package hostattach

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// UnreachableDefaultMetric is the metric of the unreachable default routes a
// pod VRF gets. It matches the canonical host VRFs', so any real default
// route wins over it.
const UnreachableDefaultMetric = 4278198272

// The link-local addresses on the two ends of every attachment. They are
// scoped to their link, so every attachment can use the same pair.
var (
	hostLinkLocal = netip.MustParseAddr("fe80::1")
	podLinkLocal  = netip.MustParseAddr("fe80::2")
)

// ErrNotOwned is returned when a link Release or Provision would act on
// carries a different attachment ID: another attachment, possibly a
// replacement reusing the same name, owns it.
var ErrNotOwned = errors.New("hostattach: link belongs to another attachment")

// Attachment is the desired state of one pod's attachment to one VPC.
type Attachment struct {
	// ID identifies the attachment instance. It is stamped on the host link
	// as its alias, and Release and Provision refuse to act on a link that
	// carries another ID, so a reused interface name never authorizes
	// changes to someone else's attachment.
	ID string
	// HostVRF is the canonical host VRF of the VPC. It must already exist in
	// the host namespace.
	HostVRF string
	// HostLink is the name of the host end of the veth pair.
	HostLink string
	// PodVRF is the name of the VRF inside the pod. Provision creates it if
	// it is missing.
	PodVRF string
	// PodTable is the routing table of PodVRF, local to the pod.
	PodTable uint32
	// PodLink is the name of the pod end of the veth pair.
	PodLink string
	// PodIndex, when non-zero, is the ifindex the pod end is created with.
	PodIndex int
	// Address is the attachment's own address in the VPC: the source of the
	// pod's sockets and the next hop the host table routes Prefixes through.
	Address netip.Addr
	// Prefixes are the destinations, such as a site's or a client's ranges,
	// the host table routes to this attachment.
	Prefixes []netip.Prefix
	// TUN, when set, gives the attachment a packet device in the pod VRF,
	// which Prefixes route to inside the pod.
	TUN *TUN
}

// TUN is the packet device of a packet-access attachment.
type TUN struct {
	// Name of the device inside the pod.
	Name string
	// Owner and Group are the user and group allowed to open the device
	// without CAP_NET_ADMIN.
	Owner uint32
	Group uint32
}

// Result describes a provisioned attachment.
type Result struct {
	// HostIndex is the host link's ifindex, the only interface identifier the
	// node's shared datapath may use for this attachment.
	HostIndex int
	// HostTable is the canonical host VRF's routing table.
	HostTable uint32
	// PodIndex is the pod link's ifindex, meaningful only inside the pod.
	PodIndex int
}

func (a Attachment) validate() error {
	switch {
	case a.ID == "":
		return errors.New("hostattach: attachment ID is required")
	case a.HostVRF == "" || a.HostLink == "" || a.PodVRF == "" || a.PodLink == "":
		return errors.New("hostattach: VRF and link names are required")
	case a.PodTable == 0:
		return errors.New("hostattach: pod VRF table is required")
	case !a.Address.Is6() || a.Address.Is4In6() || !a.Address.IsGlobalUnicast():
		return fmt.Errorf("hostattach: attachment address %s is not a global IPv6 unicast address", a.Address)
	case a.TUN != nil && a.TUN.Name == "":
		return errors.New("hostattach: TUN name is required")
	}
	for _, p := range a.Prefixes {
		if !p.IsValid() || !p.Addr().Is6() || p.Bits() == 0 || p != p.Masked() {
			return fmt.Errorf("hostattach: prefix %s must be a masked, non-default IPv6 prefix", p)
		}
	}
	return nil
}

// Provision creates the attachment, or completes one a previous call left
// partly done, and reads it back.
//
// Both namespaces are verified before anything changes and again after, so a
// sandbox replaced during provisioning is reported rather than silently
// half-configured; the handles pin the original namespaces, so no change can
// land in the replacement. A host link that already exists must carry a.ID.
func Provision(host, pod *Namespace, a Attachment) (Result, error) {
	if err := a.validate(); err != nil {
		return Result{}, err
	}
	if err := verifyBoth(host, pod); err != nil {
		return Result{}, err
	}
	hostH, err := host.netlink()
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = hostH.Close() }()
	podH, err := pod.netlink()
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = podH.Close() }()

	hostTable, err := vrfTable(hostH, a.HostVRF)
	if err != nil {
		return Result{}, fmt.Errorf("hostattach: canonical host VRF: %w", err)
	}
	if err := ensurePodVRF(podH, a.PodVRF, a.PodTable); err != nil {
		return Result{}, err
	}
	hostLink, podLink, err := ensureVeth(hostH, podH, host, a)
	if err != nil {
		return Result{}, err
	}
	if err := configureHostLink(hostH, hostLink, a, hostTable, podLink.Attrs().HardwareAddr); err != nil {
		return Result{}, err
	}
	if err := configurePodLink(podH, podLink, a, hostLink.Attrs().HardwareAddr); err != nil {
		return Result{}, err
	}
	if a.TUN != nil {
		if err := ensureTUN(podH, pod, a); err != nil {
			return Result{}, err
		}
	}
	if err := verifyBoth(host, pod); err != nil {
		return Result{}, err
	}
	res := Result{HostIndex: hostLink.Attrs().Index, HostTable: hostTable, PodIndex: podLink.Attrs().Index}
	return res, settle(host, pod, a)
}

// settleTimeout bounds how long Provision waits for the kernel to finish
// state it derives asynchronously.
const settleTimeout = 2 * time.Second

// settle reads the attachment back until it matches or settleTimeout passes.
// The kernel installs the local route for an address from its address
// configuration work queue once the link is up, so it can lag the netlink
// calls that caused it; anything still missing after the timeout is drift.
func settle(host, pod *Namespace, a Attachment) error {
	deadline := time.Now().Add(settleTimeout)
	for {
		err := Readback(host, pod, a)
		if err == nil || !errors.Is(err, ErrDrift) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func verifyBoth(host, pod *Namespace) error {
	if err := host.Verify(); err != nil {
		return err
	}
	return pod.Verify()
}

func vrfTable(h *netlink.Handle, name string) (uint32, error) {
	link, err := h.LinkByName(name)
	if err != nil {
		return 0, fmt.Errorf("look up VRF %q: %w", name, err)
	}
	v, ok := link.(*netlink.Vrf)
	if !ok {
		return 0, fmt.Errorf("%q is a %s, not a VRF", name, link.Type())
	}
	return v.Table, nil
}

// ensurePodVRF creates the pod VRF with its unreachable defaults, or checks an
// existing one uses the expected table.
func ensurePodVRF(h *netlink.Handle, name string, table uint32) error {
	if link, err := h.LinkByName(name); err == nil {
		v, ok := link.(*netlink.Vrf)
		if !ok || v.Table != table {
			return fmt.Errorf("hostattach: pod link %q exists but is not a VRF with table %d", name, table)
		}
	} else {
		if err := h.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: name}, Table: table}); err != nil {
			return fmt.Errorf("hostattach: create pod VRF %q: %w", name, err)
		}
	}
	// Installed before the VRF is up, so nothing is ever routed in it without
	// the catch-all.
	for _, dst := range []*net.IPNet{
		{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
	} {
		r := &netlink.Route{Dst: dst, Table: int(table), Type: unix.RTN_UNREACHABLE, Priority: UnreachableDefaultMetric}
		if err := h.RouteReplace(r); err != nil {
			return fmt.Errorf("hostattach: unreachable default %s in pod table %d: %w", dst, table, err)
		}
	}
	link, err := h.LinkByName(name)
	if err != nil {
		return fmt.Errorf("hostattach: look up pod VRF %q: %w", name, err)
	}
	return h.LinkSetUp(link)
}

// ensureVeth creates the veth pair from inside the pod, so the pod end can be
// given a fixed ifindex, with the peer placed straight into the host
// namespace. An existing pair is accepted only if both ends are veths, the
// host end's peer is the expected pod link, and the host end carries a.ID or
// no owner at all: an unstamped pair is what a call that failed between
// creating the pair and stamping it leaves behind, and the pod end sits in
// the verified pod namespace under the expected name.
func ensureVeth(hostH, podH *netlink.Handle, host *Namespace, a Attachment) (netlink.Link, netlink.Link, error) {
	hostLink, hostErr := hostH.LinkByName(a.HostLink)
	podLink, podErr := podH.LinkByName(a.PodLink)
	switch {
	case hostErr == nil && podErr == nil:
		if owner := hostLink.Attrs().Alias; owner != a.ID && owner != "" {
			return nil, nil, fmt.Errorf("%w: host link %q has owner %q", ErrNotOwned, a.HostLink, owner)
		}
		if hostLink.Type() != "veth" || podLink.Type() != "veth" ||
			hostLink.Attrs().ParentIndex != podLink.Attrs().Index {
			return nil, nil, fmt.Errorf("hostattach: host link %q is not a veth paired with pod link %q", a.HostLink, a.PodLink)
		}
		if hostLink.Attrs().Alias == "" {
			if err := hostH.LinkSetAlias(hostLink, a.ID); err != nil {
				return nil, nil, fmt.Errorf("hostattach: stamp owner on host link %q: %w", a.HostLink, err)
			}
		}
		return hostLink, podLink, nil
	case hostErr == nil:
		return nil, nil, fmt.Errorf("%w: host link %q exists without pod link %q", ErrNotOwned, a.HostLink, a.PodLink)
	case podErr == nil:
		return nil, nil, fmt.Errorf("hostattach: pod link %q exists without host link %q", a.PodLink, a.HostLink)
	}
	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: a.PodLink, Index: a.PodIndex},
		PeerName:      a.HostLink,
		PeerNamespace: netlink.NsFd(int(host.fd)),
	}
	if err := podH.LinkAdd(veth); err != nil {
		return nil, nil, fmt.Errorf("hostattach: create veth %s/%s: %w", a.PodLink, a.HostLink, err)
	}
	hostLink, err := hostH.LinkByName(a.HostLink)
	if err != nil {
		return nil, nil, fmt.Errorf("hostattach: look up new host link %q: %w", a.HostLink, err)
	}
	if err := hostH.LinkSetAlias(hostLink, a.ID); err != nil {
		_ = hostH.LinkDel(hostLink)
		return nil, nil, fmt.Errorf("hostattach: stamp owner on host link %q: %w", a.HostLink, err)
	}
	podLink, err = podH.LinkByName(a.PodLink)
	if err != nil {
		return nil, nil, fmt.Errorf("hostattach: look up new pod link %q: %w", a.PodLink, err)
	}
	return hostLink, podLink, nil
}

func linkLocal(addr netip.Addr) *netlink.Addr {
	return &netlink.Addr{
		IPNet: &net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(64, 128)},
		Flags: unix.IFA_F_NODAD,
	}
}

func hostRoute(addr netip.Addr) *netlink.Addr {
	return &netlink.Addr{
		IPNet: &net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(128, 128)},
		Flags: unix.IFA_F_NODAD,
	}
}

// ensureAddr adds addr to link unless it is already there. It never replaces
// an existing address: replacing one on a VRF slave drops the kernel's local
// route for it from the VRF table, after which the address no longer accepts
// traffic.
func ensureAddr(h *netlink.Handle, link netlink.Link, addr *netlink.Addr) error {
	addrs, err := h.AddrList(link, unix.AF_INET6)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if a.IPNet.String() == addr.IPNet.String() {
			return nil
		}
	}
	return h.AddrAdd(link, addr)
}

func prefixNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// configureHostLink enslaves the host end to the canonical VRF and routes the
// attachment address and its prefixes to it through one permanent neighbor.
func configureHostLink(
	h *netlink.Handle, link netlink.Link, a Attachment, table uint32, podMAC net.HardwareAddr,
) error {
	vrfLink, err := h.LinkByName(a.HostVRF)
	if err != nil {
		return fmt.Errorf("hostattach: look up host VRF %q: %w", a.HostVRF, err)
	}
	if err := h.LinkSetMasterByIndex(link, vrfLink.Attrs().Index); err != nil {
		return fmt.Errorf("hostattach: enslave %q to %q: %w", a.HostLink, a.HostVRF, err)
	}
	if err := ensureAddr(h, link, linkLocal(hostLinkLocal)); err != nil {
		return fmt.Errorf("hostattach: address host link %q: %w", a.HostLink, err)
	}
	if err := h.LinkSetUp(link); err != nil {
		return fmt.Errorf("hostattach: set host link %q up: %w", a.HostLink, err)
	}
	idx := link.Attrs().Index
	if err := h.NeighSet(&netlink.Neigh{
		LinkIndex: idx, Family: unix.AF_INET6, State: netlink.NUD_PERMANENT,
		IP: a.Address.AsSlice(), HardwareAddr: podMAC,
	}); err != nil {
		return fmt.Errorf("hostattach: neighbor %s on %q: %w", a.Address, a.HostLink, err)
	}
	routes := []*netlink.Route{{
		LinkIndex: idx, Table: int(table), Scope: netlink.SCOPE_LINK,
		Dst: prefixNet(netip.PrefixFrom(a.Address, 128)),
	}}
	for _, p := range a.Prefixes {
		routes = append(routes, &netlink.Route{
			LinkIndex: idx, Table: int(table), Dst: prefixNet(p), Gw: a.Address.AsSlice(),
		})
	}
	for _, r := range routes {
		if err := checkRouteOwner(h, r); err != nil {
			return err
		}
		if err := h.RouteReplace(r); err != nil {
			return fmt.Errorf("hostattach: host route %s in table %d: %w", r.Dst, table, err)
		}
	}
	return nil
}

// checkRouteOwner refuses to replace a unicast route for r's destination in
// r's table that leaves through another link: that route belongs to another
// attachment or to a workload, and choosing between them is not the
// provisioner's decision.
func checkRouteOwner(h *netlink.Handle, r *netlink.Route) error {
	existing, err := h.RouteListFiltered(unix.AF_INET6, &netlink.Route{Table: r.Table, Dst: r.Dst},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
	if err != nil {
		return fmt.Errorf("hostattach: list routes for %s in table %d: %w", r.Dst, r.Table, err)
	}
	for _, e := range existing {
		if e.Type == unix.RTN_UNICAST && e.LinkIndex != r.LinkIndex {
			return fmt.Errorf("%w: route %s in table %d leaves through ifindex %d", ErrNotOwned, r.Dst, r.Table, e.LinkIndex)
		}
	}
	return nil
}

// configurePodLink enslaves the pod end to the pod VRF, gives it the
// attachment address and routes the pod VRF's default to the host end.
func configurePodLink(h *netlink.Handle, link netlink.Link, a Attachment, hostMAC net.HardwareAddr) error {
	vrfLink, err := h.LinkByName(a.PodVRF)
	if err != nil {
		return fmt.Errorf("hostattach: look up pod VRF %q: %w", a.PodVRF, err)
	}
	if err := h.LinkSetMasterByIndex(link, vrfLink.Attrs().Index); err != nil {
		return fmt.Errorf("hostattach: enslave %q to %q: %w", a.PodLink, a.PodVRF, err)
	}
	for _, addr := range []*netlink.Addr{linkLocal(podLinkLocal), hostRoute(a.Address)} {
		if err := ensureAddr(h, link, addr); err != nil {
			return fmt.Errorf("hostattach: address pod link %q: %w", a.PodLink, err)
		}
	}
	if err := h.LinkSetUp(link); err != nil {
		return fmt.Errorf("hostattach: set pod link %q up: %w", a.PodLink, err)
	}
	idx := link.Attrs().Index
	if err := h.NeighSet(&netlink.Neigh{
		LinkIndex: idx, Family: unix.AF_INET6, State: netlink.NUD_PERMANENT,
		IP: hostLinkLocal.AsSlice(), HardwareAddr: hostMAC,
	}); err != nil {
		return fmt.Errorf("hostattach: neighbor %s on %q: %w", hostLinkLocal, a.PodLink, err)
	}
	def := &netlink.Route{
		LinkIndex: idx, Table: int(a.PodTable),
		Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}, Gw: hostLinkLocal.AsSlice(),
	}
	if err := h.RouteReplace(def); err != nil {
		return fmt.Errorf("hostattach: pod default route in table %d: %w", a.PodTable, err)
	}
	return nil
}

// ensureTUN creates the packet device in the pod VRF and routes the
// attachment's prefixes to it. A TUN device is created in the calling
// thread's namespace, and forwarding between the device and the pod link is a
// per-namespace sysctl, so both happen on a thread inside the pod.
func ensureTUN(h *netlink.Handle, pod *Namespace, a Attachment) error {
	if existing, err := h.LinkByName(a.TUN.Name); err == nil {
		if _, ok := existing.(*netlink.Tuntap); !ok {
			return fmt.Errorf("%w: pod link %q is a %s, not a TUN", ErrNotOwned, a.TUN.Name, existing.Type())
		}
		if owner := existing.Attrs().Alias; owner != a.ID && owner != "" {
			return fmt.Errorf("%w: TUN %q has owner %q", ErrNotOwned, a.TUN.Name, owner)
		}
	} else {
		err := pod.do(func() error {
			if err := netlink.LinkAdd(&netlink.Tuntap{
				LinkAttrs: netlink.LinkAttrs{Name: a.TUN.Name},
				Mode:      netlink.TUNTAP_MODE_TUN,
				Flags:     netlink.TUNTAP_NO_PI | netlink.TUNTAP_ONE_QUEUE,
				Owner:     a.TUN.Owner,
				Group:     a.TUN.Group,
			}); err != nil {
				return fmt.Errorf("hostattach: create TUN %q: %w", a.TUN.Name, err)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if err := pod.do(func() error { return enableSysctl(podForwarding) }); err != nil {
		return err
	}
	tun, err := h.LinkByName(a.TUN.Name)
	if err != nil {
		return fmt.Errorf("hostattach: look up TUN %q: %w", a.TUN.Name, err)
	}
	if err := h.LinkSetAlias(tun, a.ID); err != nil {
		return fmt.Errorf("hostattach: stamp owner on TUN %q: %w", a.TUN.Name, err)
	}
	vrfLink, err := h.LinkByName(a.PodVRF)
	if err != nil {
		return fmt.Errorf("hostattach: look up pod VRF %q: %w", a.PodVRF, err)
	}
	if err := h.LinkSetMasterByIndex(tun, vrfLink.Attrs().Index); err != nil {
		return fmt.Errorf("hostattach: enslave TUN %q to %q: %w", a.TUN.Name, a.PodVRF, err)
	}
	if err := h.LinkSetUp(tun); err != nil {
		return fmt.Errorf("hostattach: set TUN %q up: %w", a.TUN.Name, err)
	}
	for _, p := range a.Prefixes {
		r := &netlink.Route{LinkIndex: tun.Attrs().Index, Table: int(a.PodTable), Dst: prefixNet(p)}
		if err := h.RouteReplace(r); err != nil {
			return fmt.Errorf("hostattach: pod route %s via TUN: %w", p, err)
		}
	}
	return nil
}

// podForwarding is the sysctl that lets a pod forward between its attachment
// link and its TUN device.
const podForwarding = "net/ipv6/conf/all/forwarding"

func enableSysctl(key string) error {
	path := filepath.Join("/proc/sys", key)
	if err := os.WriteFile(path, []byte("1"), 0o644); err != nil { //nolint:gosec // procfs sysctl, fixed key
		return fmt.Errorf("hostattach: write %s: %w", path, err)
	}
	return nil
}

// Release removes the attachment's links and, with them, every route and
// neighbor entry that used them. A host link carrying another attachment's ID
// is left untouched and reported as ErrNotOwned. An already absent attachment
// is not an error.
//
// The pod VRF is left in place: it belongs to the pod, which may route other
// traffic through it, and goes away with the pod's namespace.
func Release(host, pod *Namespace, a Attachment) error {
	hostH, err := host.netlink()
	if err != nil {
		return err
	}
	defer func() { _ = hostH.Close() }()
	if link, err := hostH.LinkByName(a.HostLink); err == nil {
		if link.Attrs().Alias != a.ID {
			return fmt.Errorf("%w: host link %q has owner %q", ErrNotOwned, a.HostLink, link.Attrs().Alias)
		}
		if err := hostH.LinkDel(link); err != nil {
			return fmt.Errorf("hostattach: delete host link %q: %w", a.HostLink, err)
		}
	}
	if a.TUN == nil || pod.Verify() != nil {
		// A replaced sandbox's devices went with its namespace.
		return nil
	}
	podH, err := pod.netlink()
	if err != nil {
		return err
	}
	defer func() { _ = podH.Close() }()
	tun, err := podH.LinkByName(a.TUN.Name)
	if err != nil {
		return nil //nolint:nilerr // absent device is the released state
	}
	if tun.Attrs().Alias != a.ID {
		return fmt.Errorf("%w: TUN %q has owner %q", ErrNotOwned, a.TUN.Name, tun.Attrs().Alias)
	}
	if err := podH.LinkDel(tun); err != nil {
		return fmt.Errorf("hostattach: delete TUN %q: %w", a.TUN.Name, err)
	}
	return nil
}
