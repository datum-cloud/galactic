// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hostattach provisions host-owned VPC attachments for pods that
// consume a VPC through a socket or a packet device rather than as an ordinary
// CNI workload. Only IPv6 attachment addresses and prefixes are supported.
//
// Callers must derive the attachment ID, host VRF, namespace, address and prefix
// grants from authenticated, authorized gVPC state, and serialize mutations with
// other host writers. This package is privileged plumbing, not admission or
// source-address policy. Install host traffic policy and the consumer's
// delegated-source enforcement through ProvisionRegistered's register, so they
// are in place before the host link first comes up. A pod must not have
// authority over host links.
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

	"go.datum.net/galactic/internal/plumbing/nldump"
)

// MinMTU is the smallest MTU an attachment link or packet device may have:
// the IPv6 minimum link MTU (RFC 8200 section 5).
const MinMTU = 1280

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

// ErrStalePeer is returned, with ErrNotOwned, when the host link carries this
// attachment's ID but its peer is not in the given pod namespace: the pod's
// sandbox was replaced while the old one still exists. The link is the
// attachment's own, so its owner may Release it and provision again.
var ErrStalePeer = errors.New("hostattach: host link is paired with another namespace")

// Attachment is authenticated desired state for one pod's attachment to a gVPC.
// Identity, namespace, address, VRFs, link names and TUN configuration are
// immutable for an ID; release and create a new ID to change them. Prefixes
// may change and are reconciled exactly on the dedicated host and TUN links.
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
	// MTU is the MTU of both ends of the veth pair. It must be at least the
	// largest inner packet any interface of the VPC can send, the fabric's
	// tenant MTU, so a packet the node's datapath decapsulates always fits
	// the host link: the decapsulation path drops a packet that does not
	// fit without reporting Packet Too Big. A smaller limit further in, such
	// as a TUN device's, is reported by the pod's own forwarding. It must
	// not exceed what the fabric underlay carries once a packet is
	// encapsulated, which the provisioner cannot see.
	MTU int
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
	// MTU of the device. Zero leaves it at the attachment's MTU; a smaller
	// value makes the pod answer larger packets routed to the device with
	// Packet Too Big.
	MTU int
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
	case a.ID == "" || len(ownerAlias(a.ID)) > 255:
		return errors.New("hostattach: attachment ID must be nonempty and fit the link alias")
	case a.HostVRF == "" || a.HostLink == "" || a.PodVRF == "" || a.PodLink == "":
		return errors.New("hostattach: VRF and link names are required")
	case a.PodTable == 0:
		return errors.New("hostattach: pod VRF table is required")
	case !a.Address.Is6() || a.Address.Is4In6() || !a.Address.IsGlobalUnicast():
		return fmt.Errorf("hostattach: attachment address %s is not a global IPv6 unicast address", a.Address)
	case a.MTU < MinMTU:
		return fmt.Errorf("hostattach: MTU %d is below the IPv6 minimum of %d", a.MTU, MinMTU)
	case a.TUN != nil && a.TUN.Name == "":
		return errors.New("hostattach: TUN name is required")
	case a.TUN != nil && a.TUN.MTU != 0 && (a.TUN.MTU < MinMTU || a.TUN.MTU > a.MTU):
		return fmt.Errorf("hostattach: TUN MTU %d must be between %d and the attachment MTU %d", a.TUN.MTU, MinMTU, a.MTU)
	}
	for _, p := range a.Prefixes {
		if !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() || p.Bits() == 0 || p != p.Masked() {
			return fmt.Errorf("hostattach: prefix %s must be a masked, non-default IPv6 prefix", p)
		}
		if p.Contains(a.Address) {
			return fmt.Errorf("hostattach: prefix %s contains attachment address %s", p, a.Address)
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
// land in the replacement. An unstamped host link requires proof of its actual
// peer namespace before adoption. On later failure the owned host link is disabled
// and remains discoverable for retry or release. Callers must persist authorized
// intent before Provision; a crash before stamping requires that intent and the
// actual peer namespace to recover, never inference from an unstamped link name.
func Provision(host, pod *Namespace, a Attachment) (Result, error) {
	return ProvisionRegistered(host, pod, a, nil)
}

// ProvisionRegistered is Provision with register called once the host link is
// enslaved and addressed but before it is brought up, with the link's host
// ifindex and canonical table. A link that is down carries nothing, so what
// register installs on it, such as the node's datapath and its traffic policy
// enforcement, is in place before the first packet. A link that is already up
// stays up while register runs. If register fails, Provision fails and the
// host link is left down.
func ProvisionRegistered(host, pod *Namespace, a Attachment, register func(Result) error,
) (result Result, provisionErr error) {
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
	hostLink, podLink, err := ensureVeth(hostH, podH, host, pod, a)
	if err != nil {
		return Result{}, err
	}
	// A partial attempt is discoverable by alias but must not remain active.
	defer func() {
		if provisionErr == nil {
			return
		}
		current, err := hostH.LinkByName(a.HostLink)
		if err != nil {
			provisionErr = errors.Join(provisionErr, err)
			return
		}
		if current.Attrs().Alias != ownerAlias(a.ID) || current.Attrs().Index != hostLink.Attrs().Index {
			provisionErr = errors.Join(provisionErr, ErrNotOwned)
			return
		}
		provisionErr = errors.Join(provisionErr, hostH.LinkSetDown(current))
	}()
	res := Result{HostIndex: hostLink.Attrs().Index, HostTable: hostTable, PodIndex: podLink.Attrs().Index}
	beforeUp := func() error {
		if register == nil {
			return nil
		}
		return register(res)
	}
	if err := configureHostLink(hostH, hostLink, a, hostTable, podLink.Attrs().HardwareAddr, beforeUp); err != nil {
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

// VRFTable returns the routing table of host's VRF name, and false when
// there is no link of that name.
func VRFTable(host *Namespace, name string) (uint32, bool, error) {
	if err := host.Verify(); err != nil {
		return 0, false, err
	}
	h, err := host.netlink()
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = h.Close() }()
	link, err := h.LinkByName(name)
	var notFound netlink.LinkNotFoundError
	switch {
	case errors.As(err, &notFound):
		return 0, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("hostattach: look up VRF %q: %w", name, err)
	}
	v, ok := link.(*netlink.Vrf)
	if !ok {
		return 0, false, fmt.Errorf("hostattach: %q is a %s, not a VRF", name, link.Type())
	}
	return v.Table, true, nil
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

// ensureVeth accepts an existing pair only when ownership and its actual peer
// namespace match. Unstamped crash remnants require the same namespace proof
// before stamping; matching namespace-local indexes alone is never authority.
func ensureVeth(hostH, podH *netlink.Handle, host, pod *Namespace, a Attachment) (netlink.Link, netlink.Link, error) {
	hostLink, hostErr := hostH.LinkByName(a.HostLink)
	podLink, podErr := podH.LinkByName(a.PodLink)
	if hostErr != nil && !linkMissing(hostErr) {
		return nil, nil, hostErr
	}
	if podErr != nil && !linkMissing(podErr) {
		return nil, nil, podErr
	}
	if hostErr != nil && podErr != nil {
		veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: a.PodLink, Index: a.PodIndex, MTU: a.MTU},
			PeerMTU:  uint32(a.MTU), //nolint:gosec // validated range
			PeerName: a.HostLink, PeerNamespace: netlink.NsFd(int(host.fd))}
		if err := podH.LinkAdd(veth); err != nil {
			return nil, nil, fmt.Errorf("hostattach: create veth: %w", err)
		}
		hostLink, hostErr = hostH.LinkByName(a.HostLink)
		podLink, podErr = podH.LinkByName(a.PodLink)
	}
	own := hostErr == nil && hostLink.Attrs().Alias == ownerAlias(a.ID)
	if hostErr != nil || podErr != nil {
		if own {
			return nil, nil, fmt.Errorf("%w: %w: no peer in the pod", ErrNotOwned, ErrStalePeer)
		}
		return nil, nil, fmt.Errorf("%w: incomplete veth pair", ErrNotOwned)
	}
	if err := verifyPair(hostH, pod, hostLink, podLink, a); err != nil {
		if own && errors.Is(err, ErrNotOwned) {
			return nil, nil, fmt.Errorf("%w: %w", err, ErrStalePeer)
		}
		return nil, nil, err
	}
	if hostLink.Attrs().Alias == "" {
		if err := hostH.LinkSetAlias(hostLink, ownerAlias(a.ID)); err != nil {
			return nil, nil, err
		}
	}
	return hostLink, podLink, nil
}

func verifyPair(hostH *netlink.Handle, pod *Namespace, hostLink, podLink netlink.Link, a Attachment) error {
	owner := hostLink.Attrs().Alias
	if owner != "" && owner != ownerAlias(a.ID) {
		return fmt.Errorf("%w: host link %q", ErrNotOwned, a.HostLink)
	}
	if err := pod.Verify(); err != nil {
		return err
	}
	nsID, err := hostH.GetNetNsIdByFd(int(pod.fd))
	if err != nil {
		return fmt.Errorf("hostattach: resolve peer namespace: %w", err)
	}
	if hostLink.Type() != vethType || podLink.Type() != vethType || nsID < 0 || hostLink.Attrs().NetNsID != nsID ||
		hostLink.Attrs().ParentIndex != podLink.Attrs().Index || podLink.Attrs().ParentIndex != hostLink.Attrs().Index {
		return fmt.Errorf("%w: host link %q is not paired with the verified pod", ErrNotOwned, a.HostLink)
	}
	return nil
}

func linkMissing(err error) bool {
	var missing netlink.LinkNotFoundError
	return errors.As(err, &missing)
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

func (t *TUN) effectiveMTU(attachment int) int {
	if t.MTU != 0 {
		return t.MTU
	}
	return attachment
}

func ensureMTU(h *netlink.Handle, link netlink.Link, mtu int) error {
	if link.Attrs().MTU == mtu {
		return nil
	}
	if err := h.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("hostattach: set MTU %d on %q: %w", mtu, link.Attrs().Name, err)
	}
	return nil
}

// ensureAddr adds addr to link unless it is already there. It never replaces
// an existing address: replacing one on a VRF slave drops the kernel's local
// route for it from the VRF table, after which the address no longer accepts
// traffic.
func ensureAddr(h *netlink.Handle, link netlink.Link, addr *netlink.Addr) error {
	addrs, err := nldump.On(h).AddrList(link, unix.AF_INET6)
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

// configureHostLink enslaves the host end to the canonical VRF, calls beforeUp,
// brings the link up and routes the attachment address and its prefixes to it
// through one permanent neighbor.
func configureHostLink(
	h *netlink.Handle, link netlink.Link, a Attachment, table uint32, podMAC net.HardwareAddr, beforeUp func() error,
) error {
	vrfLink, err := h.LinkByName(a.HostVRF)
	if err != nil {
		return fmt.Errorf("hostattach: look up host VRF %q: %w", a.HostVRF, err)
	}
	if err := h.LinkSetMasterByIndex(link, vrfLink.Attrs().Index); err != nil {
		return fmt.Errorf("hostattach: enslave %q to %q: %w", a.HostLink, a.HostVRF, err)
	}
	if err := ensureMTU(h, link, a.MTU); err != nil {
		return err
	}
	if err := ensureAddr(h, link, linkLocal(hostLinkLocal)); err != nil {
		return fmt.Errorf("hostattach: address host link %q: %w", a.HostLink, err)
	}
	if err := beforeUp(); err != nil {
		return err
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
	if err := pruneRoutes(h, link.Attrs().Index, table, hostRoutes(a)); err != nil {
		return fmt.Errorf("hostattach: host link %q: %w", a.HostLink, err)
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
	existing, err := nldump.On(h).RouteListFiltered(unix.AF_INET6, &netlink.Route{Table: r.Table, Dst: r.Dst},
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
	if err := ensureMTU(h, link, a.MTU); err != nil {
		return err
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
	// The pod link carries only the default route toward the host; any other
	// route through it would send pod VRF traffic past the uSID datapath's
	// view of the attachment.
	if err := pruneRoutes(h, idx, a.PodTable, podRoutes); err != nil {
		return fmt.Errorf("hostattach: pod link %q: %w", a.PodLink, err)
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
		if owner := existing.Attrs().Alias; owner != ownerAlias(a.ID) {
			return fmt.Errorf("%w: TUN %q has owner %q", ErrNotOwned, a.TUN.Name, owner)
		}
	} else {
		err := pod.do(func() error { return createTUN(a) })
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
	if err := h.LinkSetAlias(tun, ownerAlias(a.ID)); err != nil {
		return fmt.Errorf("hostattach: stamp owner on TUN %q: %w", a.TUN.Name, err)
	}
	vrfLink, err := h.LinkByName(a.PodVRF)
	if err != nil {
		return fmt.Errorf("hostattach: look up pod VRF %q: %w", a.PodVRF, err)
	}
	if err := h.LinkSetMasterByIndex(tun, vrfLink.Attrs().Index); err != nil {
		return fmt.Errorf("hostattach: enslave TUN %q to %q: %w", a.TUN.Name, a.PodVRF, err)
	}
	if err := ensureMTU(h, tun, a.TUN.effectiveMTU(a.MTU)); err != nil {
		return err
	}
	if err := h.LinkSetUp(tun); err != nil {
		return fmt.Errorf("hostattach: set TUN %q up: %w", a.TUN.Name, err)
	}
	if err := pruneRoutes(h, tun.Attrs().Index, a.PodTable, tunRoutes(a)); err != nil {
		return fmt.Errorf("hostattach: TUN %q: %w", a.TUN.Name, err)
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

// SysctlRoot is the procfs sysctl directory per-namespace sysctls are
// written through. A container whose own /proc/sys is read-only points it at
// a writable mount of the host's: net sysctls resolve to the writing
// thread's network namespace whichever procfs mount is used.
var SysctlRoot = "/proc/sys"

func enableSysctl(key string) error {
	path := filepath.Join(SysctlRoot, key)
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
//
// A nil pod releases only a stamped host link: it is for an attachment whose
// pod namespace is gone or can no longer be found. A TUN device left in a
// live pod is then not removed; with its host link gone it carries nothing.
func Release(host, pod *Namespace, a Attachment) error {
	if a.ID == "" {
		return ErrNotOwned
	}
	if err := host.Verify(); err != nil {
		return err
	}
	hostH, err := host.netlink()
	if err != nil {
		return err
	}
	defer func() { _ = hostH.Close() }()
	if link, err := hostH.LinkByName(a.HostLink); err == nil {
		if link.Attrs().Alias == "" {
			if pod == nil {
				return fmt.Errorf("%w: unstamped host link %q and no pod namespace", ErrNotOwned, a.HostLink)
			}
			podH, err := pod.netlink()
			if err != nil {
				return err
			}
			defer func() { _ = podH.Close() }()
			peer, err := podH.LinkByName(a.PodLink)
			if err != nil {
				return fmt.Errorf("%w: missing verified peer", ErrNotOwned)
			}
			if err := verifyPair(hostH, pod, link, peer, a); err != nil {
				return err
			}
		} else if link.Attrs().Alias != ownerAlias(a.ID) {
			return fmt.Errorf("%w: host link %q has owner %q", ErrNotOwned, a.HostLink, link.Attrs().Alias)
		}
		if err := hostH.LinkDel(link); err != nil {
			return fmt.Errorf("hostattach: delete host link %q: %w", a.HostLink, err)
		}
	} else if !linkMissing(err) {
		return err
	}
	if a.TUN == nil || pod == nil || pod.Verify() != nil {
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
		if linkMissing(err) {
			return nil
		}
		return err
	}
	if tun.Attrs().Alias != ownerAlias(a.ID) {
		return fmt.Errorf("%w: TUN %q has owner %q", ErrNotOwned, a.TUN.Name, tun.Attrs().Alias)
	}
	if err := podH.LinkDel(tun); err != nil {
		return fmt.Errorf("hostattach: delete TUN %q: %w", a.TUN.Name, err)
	}
	return nil
}

// createTUN stamps a nonpersistent, exclusively created device before making it
// persistent. A crash before stamping closes its descriptor and removes it.
func createTUN(a Attachment) error {
	tun := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: a.TUN.Name}, Mode: netlink.TUNTAP_MODE_TUN,
		Flags: netlink.TUNTAP_NO_PI | netlink.TUNTAP_ONE_QUEUE | netlink.TUNTAP_TUN_EXCL,
		Owner: a.TUN.Owner, Group: a.TUN.Group, NonPersist: true, Queues: 1,
	}
	if err := netlink.LinkAdd(tun); err != nil {
		return fmt.Errorf("hostattach: create TUN: %w", err)
	}
	defer func() {
		for _, fd := range tun.Fds {
			_ = fd.Close()
		}
	}()
	if err := netlink.LinkSetAlias(tun, ownerAlias(a.ID)); err != nil {
		return fmt.Errorf("hostattach: stamp TUN: %w", err)
	}
	raw, err := tun.Fds[0].SyscallConn()
	if err != nil {
		return err
	}
	var persistErr error
	if err := raw.Control(func(fd uintptr) { persistErr = unix.IoctlSetInt(int(fd), unix.TUNSETPERSIST, 1) }); err != nil {
		return err
	}
	return persistErr
}
