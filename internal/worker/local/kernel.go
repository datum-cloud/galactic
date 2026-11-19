// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/localprog"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// Filter names, one per Local program.
const (
	filterRx        = attach.LocalFilterPrefix + "rx"
	filterLinkRx    = attach.LocalFilterPrefix + "link_rx"
	filterPairRx    = attach.LocalFilterPrefix + "pair_rx"
	filterLinkGuard = attach.LocalFilterPrefix + "link_guard"
	// xdpPairNAPI names local_pair_napi, which is attached as XDP rather
	// than as a filter.
	xdpPairNAPI = "xdp_pair_napi"
)

// DefaultLinkMTU is the MTU of the links Local creates. A veth with a larger
// MTU than about 3500 bytes takes no native XDP program, which the NAT end of
// a pair needs (docs/worker/qualification.md).
const DefaultLinkMTU = 1500

// The ethtool features of a pair's tenant end. Checksum offload off makes the
// kernel finish a partial checksum, and segment a GSO packet, before the
// packet crosses to the NAT end, whose XDP program rewrites addresses as if
// the checksum were complete. GRO on lets the tenant end receive what the NAT
// end's native XDP_REDIRECT sends it.
var tenantFeatures = map[string]bool{featureTxChecksum: false, featureGRO: true}

// ethtool feature names.
const (
	featureTxChecksum = "tx-checksum-ip-generic"
	featureGRO        = "rx-gro"
)

// Link types, as netlink reports them.
const (
	linkVeth   = "veth"
	linkBond   = "bond"
	linkVLAN   = "vlan"
	linkTunTap = "tuntap"
	linkVRF    = "vrf"
)

// errDirty stops a dry run at the first change it would make.
var errDirty = errors.New("local: the host differs from desired")

// Kernel is the Local module's host access, in the calling thread's network
// namespace, which must be the host's.
type Kernel struct {
	// PinDir is the bpffs directory of the pinned uSID maps.
	PinDir string
	// LocalPinDir is the bpffs directory of the Local maps.
	LocalPinDir string
	// DispatchDir is the XDP dispatcher's pin directory.
	DispatchDir string
	// Pods opens a routed link owner's pod network namespace.
	Pods PodNetns
	// LinkMTU is the MTU of the links Local creates; DefaultLinkMTU when 0.
	LinkMTU int
	// edge is the edge-link host access; the pinned maps under PinDir when
	// nil.
	edge edgeHost

	mu      sync.Mutex
	objs    *localprog.Objects
	loadErr error
	routes  *egressroutemap.EgressRouteTable
	rclose  interface{ Close() error }
	progIDs map[string]ebpf.ProgramID
	// receivers are the devices local_rx was last attached to.
	receivers map[string]struct{}
	// swept is set once a stale local_rx left by an earlier Worker on a
	// device that is no longer a receiver has been looked for.
	swept bool
}

// Close releases the Kernel's descriptors. Pinned maps and filters stay.
func (k *Kernel) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	var errs []error
	if k.objs != nil {
		errs = append(errs, k.objs.Close())
		k.objs = nil
	}
	if k.rclose != nil {
		errs = append(errs, k.rclose.Close())
		k.rclose, k.routes = nil, nil
	}
	return errors.Join(errs...)
}

// edgeHost returns the edge-link host access.
func (k *Kernel) edgeHost() edgeHost {
	if k.edge != nil {
		return k.edge
	}
	return pinnedEdgeHost{pinDir: k.PinDir}
}

func (k *Kernel) mtu() int {
	if k.LinkMTU > 0 {
		return k.LinkMTU
	}
	return DefaultLinkMTU
}

// open loads the Local programs and opens egress_route_table on first use,
// and again after a failure.
func (k *Kernel) open() (*localprog.Objects, *egressroutemap.EgressRouteTable, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.objs == nil {
		objs, err := localprog.Load(k.PinDir, k.LocalPinDir)
		if err != nil {
			k.loadErr = err
			return nil, nil, err
		}
		ids := map[string]ebpf.ProgramID{}
		for name, p := range map[string]*ebpf.Program{filterRx: objs.Programs.Rx, filterLinkRx: objs.Programs.LinkRx,
			filterPairRx: objs.Programs.PairRx, filterLinkGuard: objs.Programs.LinkGuard,
			xdpPairNAPI: objs.Programs.PairNAPI} {
			info, err := p.Info()
			if err != nil {
				_ = objs.Close()
				return nil, nil, fmt.Errorf("local: read program %s: %w", name, err)
			}
			id, _ := info.ID()
			ids[name] = id
		}
		k.objs, k.progIDs, k.loadErr = objs, ids, nil
	}
	if k.routes == nil {
		t, c, err := egressroutemap.OpenPinnedEgressRouteTable(k.PinDir)
		if err != nil {
			return nil, nil, err
		}
		k.routes, k.rclose = t, c
	}
	return k.objs, k.routes, nil
}

// Loaded returns nil when the Local programs are loaded.
func (k *Kernel) Loaded() error {
	_, _, err := k.open()
	return err
}

func (k *Kernel) program(name string) *ebpf.Program {
	switch name {
	case filterRx:
		return k.objs.Programs.Rx
	case filterLinkRx:
		return k.objs.Programs.LinkRx
	case filterPairRx:
		return k.objs.Programs.PairRx
	default:
		return k.objs.Programs.LinkGuard
	}
}

// filterCurrent reports whether ifindex carries the Local filter name with
// the program this Kernel loaded.
func (k *Kernel) filterCurrent(ifindex int, name string) (bool, error) {
	got, id, ok, err := attach.LocalFilter(ifindex)
	if err != nil || !ok {
		return false, err
	}
	k.mu.Lock()
	want := k.progIDs[name]
	k.mu.Unlock()
	return got == name && id == want, nil
}

// ensureFilter attaches the Local filter name to link unless it is current.
func (k *Kernel) ensureFilter(link netlink.Link, name string, dry bool) error {
	ok, err := k.filterCurrent(link.Attrs().Index, name)
	if err != nil || ok {
		return err
	}
	if dry {
		return errDirty
	}
	if err := attach.AttachLocal(k.program(name), link.Attrs().Name, name); err != nil {
		return fmt.Errorf("local: attach %s to %s: %w", name, link.Attrs().Name, err)
	}
	return nil
}

// TableID returns vpc's host VRF table and ifindex, and false when the VRF
// does not exist.
func TableID(vpc string) (uint32, int, bool, error) {
	l, err := netlink.LinkByName(intf.GenerateInterfaceNameVRF(vpc))
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return 0, 0, false, nil
		}
		return 0, 0, false, fmt.Errorf("local: look up VRF of %s: %w", vpc, err)
	}
	v, ok := l.(*netlink.Vrf)
	if !ok {
		return 0, 0, false, fmt.Errorf("local: %s is not a VRF", l.Attrs().Name)
	}
	return v.Table, v.Attrs().Index, true, nil
}

// host is what one pass read of the links on the host.
type host struct {
	all    []netlink.Link
	byName map[string]netlink.Link
	byIdx  map[int]netlink.Link
}

func readHost() (*host, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("local: list links: %w", err)
	}
	h := &host{all: links, byName: map[string]netlink.Link{}, byIdx: map[int]netlink.Link{}}
	for _, l := range links {
		h.byName[l.Attrs().Name] = l
		h.byIdx[l.Attrs().Index] = l
	}
	return h, nil
}

// localLinks returns the Local links of vpc, by name: those marked for one
// of its claims, and unmarked ones named for it, which an interrupted
// creation left.
func (h *host) localLinks(vpc string) map[string]netlink.Link {
	out := map[string]netlink.Link{}
	prefix := intf.GenerateInterfaceNameLocal(vpc, "000", intf.LocalRolePairNAT)[:10]
	for _, l := range h.all {
		a, name := l.Attrs().Alias, l.Attrs().Name
		if !intf.IsLocalLinkName(name) {
			continue
		}
		if v, _, ok := parseAlias(a); (ok && v == vpc) || (a == "" && strings.HasPrefix(name, prefix)) {
			out[name] = l
		}
	}
	return out
}

// enslaved returns the links whose master is vrfIdx.
func (h *host) enslaved(vrfIdx int) []netlink.Link {
	var out []netlink.Link
	for _, l := range h.all {
		if vrfIdx != 0 && l.Attrs().MasterIndex == vrfIdx {
			out = append(out, l)
		}
	}
	return out
}

// pair is a pair as the host holds it.
type pair struct {
	tenant, nat netlink.Link
}

// readPair returns p's links when both exist, belong to p's claim and are
// each other's peer.
func (h *host) readPair(p pairWant) (pair, bool) {
	t, nat := h.byName[p.tenant], h.byName[p.nat]
	if t == nil || nat == nil || t.Type() != linkVeth || nat.Type() != linkVeth ||
		t.Attrs().Alias != alias(p.key) || nat.Attrs().Alias != alias(p.key) {
		return pair{}, false
	}
	peer, err := netlink.VethPeerIndex(t.(*netlink.Veth))
	if err != nil || peer != nat.Attrs().Index {
		return pair{}, false
	}
	return pair{tenant: t, nat: nat}, true
}

// collision returns an error when a link named name belongs to another claim
// than the one alias a names. A Local link with no alias is what an
// interrupted creation left, and is Local's to replace.
func (h *host) collision(name, a string) error {
	if l := h.byName[name]; l != nil && l.Attrs().Alias != a &&
		(l.Attrs().Alias != "" || !intf.IsLocalLinkName(name)) {
		return fmt.Errorf("local: link %s belongs to %q, not %q", name, l.Attrs().Alias, a)
	}
	return nil
}

// ensurePair makes p exist in the VPC's VRF vrfIdx, up, with the tenant end's
// features set.
func (k *Kernel) ensurePair(h *host, p pairWant, vrfIdx int, dry bool) (pair, error) {
	got, ok := h.readPair(p)
	if !ok {
		if dry {
			return pair{}, errDirty
		}
		var err error
		if got, err = k.createPair(h, p); err != nil {
			return pair{}, err
		}
	}
	if err := enslave(got.tenant, vrfIdx, dry); err != nil {
		return got, err
	}
	if err := setUp(got.tenant, dry); err != nil {
		return got, err
	}
	if err := fix(dry, got.nat.Attrs().Flags&net.FlagUp == 0, func() error {
		if err := netlink.LinkSetUp(got.nat); err != nil {
			return fmt.Errorf("local: set %s up: %w", p.nat, err)
		}
		return nil
	}); err != nil {
		return got, err
	}
	if err := ensureFeatures(p.tenant, dry); err != nil {
		return got, err
	}
	return got, k.ensurePairNAPI(got.tenant, dry)
}

// pairNAPICurrent reports whether l, a pair's tenant end, runs
// local_pair_napi in native mode.
func (k *Kernel) pairNAPICurrent(l netlink.Link) bool {
	xdp := l.Attrs().Xdp
	if xdp == nil || !xdp.Attached {
		return false
	}
	k.mu.Lock()
	want := k.progIDs[xdpPairNAPI]
	k.mu.Unlock()
	mode, ok := xdpmode.FromAttachMode(xdp.AttachMode)
	return ok && mode == xdpmode.Native && ebpf.ProgramID(xdp.ProgId) == want
}

// ensurePairNAPI attaches local_pair_napi to l, a pair's tenant end, in
// native mode: a veth receives what a native XDP_REDIRECT sends into its
// peer only while it runs NAPI, which GRO alone does not turn on on every
// kernel.
func (k *Kernel) ensurePairNAPI(l netlink.Link, dry bool) error {
	return fix(dry, !k.pairNAPICurrent(l), func() error {
		if err := netlink.LinkSetXdpFdWithFlags(l, k.objs.Programs.PairNAPI.FD(), nl.XDP_FLAGS_DRV_MODE); err != nil {
			return fmt.Errorf("local: attach XDP to %s: %w", l.Attrs().Name, err)
		}
		return nil
	})
}

// createPair creates p, replacing whatever is left of it.
func (k *Kernel) createPair(h *host, p pairWant) (pair, error) {
	for _, n := range []string{p.tenant, p.nat} {
		if err := h.collision(n, alias(p.key)); err != nil {
			return pair{}, err
		}
		if l := h.byName[n]; l != nil {
			if err := netlink.LinkDel(l); err != nil && !errors.Is(err, unix.ENODEV) {
				return pair{}, fmt.Errorf("local: delete incomplete pair link %s: %w", n, err)
			}
		}
	}
	// The kernel takes no alias when it creates a link, so both ends are
	// marked after; a failure before then removes the pair, and an unmarked
	// pair a crash left in between is Local's to replace (collision).
	v := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: p.tenant, MTU: k.mtu()}, PeerName: p.nat}
	if err := netlink.LinkAdd(v); err != nil {
		return pair{}, fmt.Errorf("local: create pair %s/%s: %w", p.tenant, p.nat, err)
	}
	got, err := markPair(p)
	if err != nil {
		if l, lerr := netlink.LinkByName(p.tenant); lerr == nil {
			_ = netlink.LinkDel(l)
		}
		return pair{}, err
	}
	return got, nil
}

// markPair marks both ends of a new pair and returns them.
func markPair(p pairWant) (pair, error) {
	var got pair
	for _, n := range []string{p.tenant, p.nat} {
		l, err := netlink.LinkByName(n)
		if err != nil {
			return pair{}, fmt.Errorf("local: look up new pair link %s: %w", n, err)
		}
		if err := netlink.LinkSetAlias(l, alias(p.key)); err != nil {
			return pair{}, fmt.Errorf("local: mark pair link %s: %w", n, err)
		}
		if l, err = netlink.LinkByName(n); err != nil {
			return pair{}, err
		}
		if n == p.tenant {
			got.tenant = l
		} else {
			got.nat = l
		}
	}
	return got, nil
}

// ensureFeatures sets tenantFeatures on name.
func ensureFeatures(name string, dry bool) error {
	et, err := ethtool.NewEthtool()
	if err != nil {
		return fmt.Errorf("local: open ethtool: %w", err)
	}
	defer et.Close()
	cur, err := et.Features(name)
	if err != nil {
		return fmt.Errorf("local: read features of %s: %w", name, err)
	}
	change := map[string]bool{}
	for f, want := range tenantFeatures {
		if have, ok := cur[f]; ok && have != want {
			change[f] = want
		}
	}
	if len(change) == 0 {
		return nil
	}
	if dry {
		return errDirty
	}
	if err := et.Change(name, change); err != nil {
		return fmt.Errorf("local: set features %v on %s: %w", change, name, err)
	}
	return nil
}

// routedLink is a routed link as the host holds it.
type routedLink struct {
	host netlink.Link
	// podIndex is the pod end's ifindex in the pod's namespace.
	podIndex int
}

// readRouted returns r's host end when it belongs to r's claim and its peer
// is in podNS.
func (h *host) readRouted(r routedWant, podNS netns.NsHandle) (routedLink, bool) {
	l := h.byName[r.host]
	if l == nil || l.Type() != linkVeth || l.Attrs().Alias != alias(r.key) {
		return routedLink{}, false
	}
	want, err := netlink.GetNetNsIdByFd(int(podNS))
	if err != nil || want < 0 || l.Attrs().NetNsID != want {
		return routedLink{}, false
	}
	peer, err := netlink.VethPeerIndex(l.(*netlink.Veth))
	if err != nil {
		return routedLink{}, false
	}
	return routedLink{host: l, podIndex: peer}, true
}

// setUpInPod marks the pod end name in podNS with a and sets it up. The pod
// configures everything else on it.
func setUpInPod(podNS netns.NsHandle, name, a string) error {
	nh, err := netlink.NewHandleAt(podNS)
	if err != nil {
		return fmt.Errorf("local: open the pod's netlink: %w", err)
	}
	defer nh.Close() //nolint:errcheck // our own descriptor
	l, err := nh.LinkByName(name)
	if err != nil {
		return fmt.Errorf("local: look up pod end %s: %w", name, err)
	}
	if err := nh.LinkSetAlias(l, a); err != nil {
		return fmt.Errorf("local: mark pod end %s: %w", name, err)
	}
	if err := nh.LinkSetUp(l); err != nil {
		return fmt.Errorf("local: set pod end %s up: %w", name, err)
	}
	return nil
}

func ipnet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// pairTenantOf returns the tenant end's name for a pair's NAT end name.
func pairTenantOf(nat string) string {
	if !strings.HasSuffix(nat, intf.LocalRolePairNAT) {
		return ""
	}
	return strings.TrimSuffix(nat, intf.LocalRolePairNAT) + intf.LocalRolePairTenant
}

func deleteRow(mp *ebpf.Map, idx uint32, dry bool) error {
	v, err := mp.LookupBytes(idx)
	if err != nil {
		return fmt.Errorf("local: read %s: %w", mp.String(), err)
	}
	if v == nil {
		return nil
	}
	if dry {
		return errDirty
	}
	return ignoreMissing(mp.Delete(idx))
}

func ignoreMissing(err error) error {
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func u32Keys(mp *ebpf.Map) ([]uint32, error) {
	var (
		key  uint32
		keys []uint32
	)
	val := make([]byte, mp.ValueSize())
	it := mp.Iterate()
	for it.Next(&key, val) {
		keys = append(keys, key)
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("local: read %s: %w", mp.String(), err)
	}
	return keys, nil
}

// purgeFlows deletes the local.tap flows of every interface with no lt_link
// row.
func (k *Kernel) purgeFlows() error {
	objs, _, err := k.open()
	if err != nil {
		return err
	}
	links, err := u32Keys(objs.Maps.Link)
	if err != nil {
		return err
	}
	var (
		key  localprog.LocalLtFlowKey
		val  localprog.LocalLtFlowValue
		dead []localprog.LocalLtFlowKey
	)
	it := objs.Maps.Flow.Iterate()
	for it.Next(&key, &val) {
		if !slices.Contains(links, key.LinkIfindex) {
			dead = append(dead, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("local: read flows: %w", err)
	}
	for _, d := range dead {
		if err := ignoreMissing(objs.Maps.Flow.Delete(d)); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// receiver is one device local_rx runs on.
type receiver struct {
	name string
	idx  int
	mtu  int
	// slotErr is nil when a live public slot covers the device, or the
	// device it receives through.
	slotErr error
}

// receiverDevices returns the devices local_rx belongs on: for each
// interface whose XDP dispatcher has the public role, the device its traffic
// reaches tc on. That is its bond master when it is a bond member, and the
// VLAN devices above that when there are any, since native XDP takes no VLAN
// device and the dispatcher runs on the lower one (contract amendment).
func (k *Kernel) receiverDevices(h *host) ([]receiver, error) {
	in, err := xdpdispatch.Inspect(k.DispatchDir)
	if errors.Is(err, xdpdispatch.ErrNoDispatcher) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer in.Close() //nolint:errcheck // our own descriptors
	public, err := in.Interfaces(xdpdispatch.RolePublicLB)
	if err != nil {
		return nil, err
	}
	byIdx := map[int]*receiver{}
	for _, ifx := range public {
		l := h.byIdx[ifx]
		if l == nil {
			continue
		}
		slotErr := in.Claimed(ifx, xdpdispatch.SlotGatewayLB)
		target := l
		if m := h.byIdx[l.Attrs().MasterIndex]; m != nil && m.Type() == linkBond {
			target = m
		}
		var vlans []netlink.Link
		for _, c := range h.all {
			if c.Type() == linkVLAN && c.Attrs().ParentIndex == target.Attrs().Index {
				vlans = append(vlans, c)
			}
		}
		if len(vlans) == 0 {
			vlans = []netlink.Link{target}
		}
		for _, d := range vlans {
			r := byIdx[d.Attrs().Index]
			if r == nil {
				r = &receiver{name: d.Attrs().Name, idx: d.Attrs().Index, mtu: d.Attrs().MTU, slotErr: slotErr}
				byIdx[d.Attrs().Index] = r
			} else if slotErr == nil {
				r.slotErr = nil
			}
		}
	}
	out := make([]receiver, 0, len(byIdx))
	for _, r := range byIdx {
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b receiver) int { return strings.Compare(a.name, b.name) })
	return out, nil
}

// ensureReceivers attaches local_rx to every receiving device when want, and
// removes it from every device it is on otherwise or that is no longer one.
// A TAP Local still authorizes keeps local_rx attached whatever want says:
// after a restart, a scope with no local.tap claim can be planned before the
// scopes that have one, and must not take local_rx away from them.
func (k *Kernel) ensureReceivers(want, dry bool) error {
	objs, _, err := k.open()
	if err != nil {
		return err
	}
	h, err := readHost()
	if err != nil {
		return err
	}
	if !want {
		taps, err := u32Keys(objs.Maps.Tap)
		if err != nil {
			return err
		}
		for _, idx := range taps {
			if h.byIdx[int(idx)] != nil {
				want = true
				break
			}
		}
	}
	rs, err := k.receiverDevices(h)
	if err != nil {
		return err
	}
	k.mu.Lock()
	prev := k.receivers
	swept := k.swept
	k.mu.Unlock()
	if !swept {
		// An earlier Worker may have left local_rx anywhere outside a VRF.
		prev = map[string]struct{}{}
		for _, l := range h.all {
			if l.Attrs().MasterIndex != 0 || l.Type() == linkTunTap || l.Type() == linkVRF {
				continue
			}
			if name, _, ok, err := attach.LocalFilter(l.Attrs().Index); err == nil && ok && name == filterRx {
				prev[l.Attrs().Name] = struct{}{}
			}
		}
	}
	now := map[string]struct{}{}
	for _, r := range rs {
		if !want {
			continue
		}
		now[r.name] = struct{}{}
		if err := k.ensureFilter(h.byIdx[r.idx], filterRx, dry); err != nil {
			return err
		}
	}
	for name := range prev {
		if _, ok := now[name]; ok {
			continue
		}
		if l := h.byName[name]; l != nil {
			if fname, _, ok, err := attach.LocalFilter(l.Attrs().Index); err != nil {
				return err
			} else if !ok || fname != filterRx {
				continue
			}
		}
		if dry {
			return errDirty
		}
		if err := attach.DetachLocal(name); err != nil {
			return err
		}
	}
	if !dry {
		k.mu.Lock()
		k.receivers, k.swept = now, true
		k.mu.Unlock()
	}
	return nil
}
