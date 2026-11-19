// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command handoff-probe places the #1444 prototype handoff programs on a
// scratch rig on a lab node, and removes them. It runs in the node's own
// network and mount namespaces (docker exec), next to galactic-cni, whose
// pinned maps the prototypes' policy decisions read.
//
// It uses the product loaders as they are: xdpdispatch for the dispatcher
// slot, natattach (xdpattach) for XDP on the NAT side of the internal veth
// pair, attach for tc ingress, and egressroutemap for the Local pass-through
// entries. It writes nothing outside its own pin directory except tc filters
// and XDP links on the interfaces its configuration names, and pass-through
// entries under its own owner, all of which teardown removes.
//
// Usage:
//
//	handoff-probe check    GALACTIC_PIN_DIR
//	handoff-probe setup    CONFIG
//	handoff-probe renew    CONFIG
//	handoff-probe counters CONFIG
//	handoff-probe teardown CONFIG
//	handoff-probe leftovers VRF...
//	handoff-probe mode     IFACE...
//
// check loads the programs against the running datapath and removes what it
// loaded; it and setup exit 3 when that datapath does not match this
// checkout, so a caller can stop at that precondition. leftovers lists
// anything a run left behind: the probe's pin directory, tc filters and its
// pass-through entries in the named VRFs, and exits 1 when there is any.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/natattach"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpdispatch"
	"go.datum.net/galactic/internal/plumbing/ebpf/xdpmode"
	"go.datum.net/galactic/tests/handoffs/probe"
)

// passThroughOwner marks the probe's egress_route_table pass-through entries,
// so teardown removes its own and never another writer's.
const passThroughOwner egressroutemap.PassThroughOwner = 0x48

// tapFilterName names the probe's filter on a tenant TAP's tc ingress, after
// galactic-cni's own two.
const tapFilterName = "galactic_handoff_probe"

// exitMismatch is setup's exit status when the datapath differs.
const exitMismatch = 3

// Config is what the rig script writes for one rig cell.
type Config struct {
	PinDir         string `json:"pinDir"`
	GalacticPinDir string `json:"galacticPinDir"`
	Mode           string `json:"mode"` // native or generic
	// PeerMode is the mode of XDP on the NAT side of the internal veth
	// pairs, when it differs from Mode.
	PeerMode string `json:"peerMode,omitempty"`
	// XDP lists the receiving interfaces the dispatcher is attached to; TC
	// the ones hp_tc_tenant_rx is attached to. They differ only for a VLAN:
	// XDP on its lower device, tc on the VLAN device.
	XDP         []string      `json:"xdp"`
	TC          []string      `json:"tc"`
	VLANID      uint32        `json:"vlanID,omitempty"`
	VIPs        []VIP         `json:"vips"`
	Taps        []Tap         `json:"taps"`
	Pairs       []Pair        `json:"pairs"`
	Guards      []Guard       `json:"guards"`
	PassThrough []PassThrough `json:"passThrough"`
}

// VIP is a public address delivered to a tenant TAP (local.tap).
type VIP struct {
	VIP   string `json:"vip"`
	Tap   string `json:"tap"`
	Guest string `json:"guest"`
	// Decide makes the tc program decide policy on the PublicService path.
	// False leaves it to tp_deliver.
	Decide bool `json:"decide"`
}

// Tap is a tenant TAP whose guest replies and NAT flows the probe sends on.
type Tap struct {
	Tap          string `json:"tap"`
	DUT          string `json:"dut"`
	Pair         string `json:"pair"` // tenant end of the internal veth pair
	Peer         string `json:"peer"` // NAT end
	VIP          string `json:"vip"`
	ClientPrefix string `json:"clientPrefix"` // a /64
}

// Pair is one internal veth pair (local.veth_pair).
type Pair struct {
	Pair  string `json:"pair"`
	Peer  string `json:"peer"`
	Tap   string `json:"tap"`
	Guest string `json:"guest"`
	Shard string `json:"shard"`
	// Redirect makes the peer's XDP forward with XDP_REDIRECT; false passes
	// the translated packet to the kernel.
	Redirect bool `json:"redirect"`
	// VLAN, when set, is an egress VLAN device. A redirect toward it pushes
	// the tag in XDP and goes to its lower device instead.
	VLAN *VLANEgress `json:"vlan,omitempty"`
}

// VLANEgress names a VLAN device, its lower device and its VLAN ID.
type VLANEgress struct {
	Device string `json:"device"`
	Lower  string `json:"lower"`
	VID    uint32 `json:"vid"`
}

// Guard is the host end of a routed link and the /127 it carries.
type Guard struct {
	Iface  string `json:"iface"`
	Prefix string `json:"prefix"`
}

// PassThrough is a Local destination in a tenant VRF that usid_egress must
// leave to the kernel rather than send to a NAT shard.
type PassThrough struct {
	VRF    string `json:"vrf"`
	Prefix string `json:"prefix"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: handoff-probe setup|renew|counters|teardown CONFIG | mode IFACE...")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var err error
	switch os.Args[1] {
	case "mode":
		err = selectMode(os.Args[2:])
	case "check":
		err = check(os.Args[2])
	case "leftovers":
		err = leftovers(os.Args[2:])
	case "setup", "renew", "counters", "teardown":
		var cfg Config
		if cfg, err = readConfig(os.Args[2]); err != nil {
			break
		}
		switch os.Args[1] {
		case "setup":
			err = setup(ctx, cfg)
		case "renew":
			err = renew(ctx, cfg)
		case "counters":
			err = counters(cfg)
		case "teardown":
			err = teardown(ctx, cfg)
		}
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "handoff-probe:", err)
		if errors.Is(err, probe.ErrDatapathMismatch) {
			os.Exit(exitMismatch)
		}
		os.Exit(1)
	}
}

// defaultPinDir is where the lab scripts put the probe's pins.
const defaultPinDir = "/sys/fs/bpf/galactic-handoff-proof"

func check(galacticPinDir string) error {
	dir := defaultPinDir + "-check"
	objs, err := probe.Load(galacticPinDir, dir)
	if objs != nil {
		_ = objs.Close()
	}
	if rmErr := os.RemoveAll(dir); err == nil {
		err = rmErr
	}
	if err == nil {
		fmt.Println("the prototype programs load against the running datapath")
	}
	return err
}

func leftovers(vrfs []string) error {
	var found []string
	if _, err := os.Stat(defaultPinDir); err == nil {
		found = append(found, "pin directory "+defaultPinDir)
	}
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	for _, l := range links {
		name := l.Attrs().Name
		if strings.HasPrefix(name, "hp-") || strings.HasPrefix(name, "hpn") || strings.HasPrefix(name, "hpr") ||
			strings.HasPrefix(name, "hpv") {
			found = append(found, "interface "+name)
		}
		filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			continue
		}
		for _, f := range filters {
			if bf, ok := f.(*netlink.BpfFilter); ok && bf.Name == tapFilterName {
				found = append(found, "tc filter "+tapFilterName+" on "+name)
			}
		}
	}
	if len(vrfs) > 0 {
		table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(attach.PinDir)
		if err != nil {
			return err
		}
		defer closer.Close() //nolint:errcheck // our own descriptor
		for _, name := range vrfs {
			l, err := netlink.LinkByName(name)
			if err != nil {
				continue
			}
			vrf, ok := l.(*netlink.Vrf)
			if !ok {
				continue
			}
			entries, err := table.Entries(vrf.Table)
			if err != nil {
				return err
			}
			for prefix, e := range entries {
				if e.PassThrough && e.Owner == passThroughOwner {
					found = append(found, fmt.Sprintf("pass-through %s in %s", prefix, name))
				}
			}
		}
	}
	for _, f := range found {
		fmt.Println(f)
	}
	if len(found) > 0 {
		return fmt.Errorf("%d leftovers", len(found))
	}
	fmt.Println("no leftovers")
	return nil
}

func readConfig(path string) (Config, error) {
	var cfg Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.PinDir == "" || cfg.GalacticPinDir == "" {
		return cfg, errors.New("config needs pinDir and galacticPinDir")
	}
	return cfg, nil
}

func (c Config) mode() (xdpmode.Mode, error) { return parseMode(c.Mode) }

func (c Config) peerMode() (xdpmode.Mode, error) {
	if c.PeerMode == "" {
		return c.mode()
	}
	return parseMode(c.PeerMode)
}

func parseMode(m string) (xdpmode.Mode, error) {
	switch m {
	case "native":
		return xdpmode.Native, nil
	case "generic":
		return xdpmode.Generic, nil
	}
	return 0, fmt.Errorf("mode %q is neither native nor generic", m)
}

func (c Config) mapDir() string      { return filepath.Join(c.PinDir, "maps") }
func (c Config) dispatchDir() string { return filepath.Join(c.PinDir, "dispatch") }
func (c Config) linkDir() string     { return filepath.Join(c.PinDir, "links") }

// selectMode prints what xdpmode.Select decides for the interfaces, for the
// run's record.
func selectMode(ifaces []string) error {
	d, err := xdpmode.Select(ifaces...)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"mode": d.Mode.String(), "reason": d.Reason, "drivers": d.Drivers, "skipped": d.Skipped,
	})
}

func setup(ctx context.Context, cfg Config) error {
	mode, err := cfg.mode()
	if err != nil {
		return err
	}
	objs, err := probe.Load(cfg.GalacticPinDir, cfg.mapDir())
	if err != nil {
		return err
	}
	defer objs.Close() //nolint:errcheck // pins and filters outlive this process

	if err := writeRows(objs, cfg); err != nil {
		return err
	}
	if err := passThrough(cfg, true); err != nil {
		return err
	}

	// The receiving device: the dispatcher's slot program, then tc.
	if len(cfg.XDP) > 0 {
		if err := fillDispatcher(ctx, cfg, mode, objs.Programs.XDPPublic); err != nil {
			return err
		}
		if err := attach.Attach(objs.Programs.TCTenantRx, cfg.TC); err != nil {
			return fmt.Errorf("attach hp_tc_tenant_rx: %w", err)
		}
	}
	for _, t := range cfg.Taps {
		if err := attachTapFilter(objs.Programs.TCTapRx, t.Tap); err != nil {
			return err
		}
	}
	if len(cfg.Pairs) > 0 {
		var peers, pairs []string
		for _, p := range cfg.Pairs {
			peers = append(peers, p.Peer)
			pairs = append(pairs, p.Pair)
		}
		peerMode, err := cfg.peerMode()
		if err != nil {
			return err
		}
		links, err := natattach.Attach(objs.Programs.XDPPairPeer, peers, peerMode)
		if err != nil {
			return fmt.Errorf("attach hp_xdp_pair_peer: %w", err)
		}
		if err := os.MkdirAll(cfg.linkDir(), 0o755); err != nil {
			return err
		}
		for i, l := range links {
			if err := l.Pin(filepath.Join(cfg.linkDir(), "peer-"+peers[i])); err != nil {
				return fmt.Errorf("pin XDP link of %s: %w", peers[i], err)
			}
			_ = l.Close()
		}
		if err := attach.Attach(objs.Programs.TCPairRx, pairs); err != nil {
			return fmt.Errorf("attach hp_tc_pair_rx: %w", err)
		}
	}
	if len(cfg.Guards) > 0 {
		var names []string
		for _, g := range cfg.Guards {
			names = append(names, g.Iface)
		}
		if err := attach.Attach(objs.Programs.TCLinkGuard, names); err != nil {
			return fmt.Errorf("attach hp_tc_link_guard: %w", err)
		}
	}
	return nil
}

func fillDispatcher(ctx context.Context, cfg Config, mode xdpmode.Mode, prog *ebpf.Program) error {
	d, err := xdpdispatch.Open(ctx, cfg.dispatchDir(), mode)
	if err != nil {
		return fmt.Errorf("open dispatcher: %w", err)
	}
	defer d.Close() //nolint:errcheck // our own descriptors

	for _, name := range cfg.XDP {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		locked, err := d.Lock(ctx)
		if err != nil {
			return err
		}
		bounced, err := locked.EnsureLink(l.Attrs().Index)
		if err == nil {
			err = locked.SetRole(l.Attrs().Index, xdpdispatch.RolePublicLB)
		}
		if err == nil && bounced {
			err = waitBondMember(name, 30*time.Second)
		}
		locked.Unlock()
		if err != nil {
			return fmt.Errorf("dispatcher on %s in %s mode: %w", name, mode, err)
		}
	}
	locked, err := d.Lock(ctx)
	if err != nil {
		return err
	}
	defer locked.Unlock()
	return locked.Fill(xdpdispatch.SlotGatewayLB, prog)
}

// waitBondMember waits until a bond member that an XDP attach reset is back
// in its aggregate. Interfaces that are not bond members return at once.
func waitBondMember(name string, timeout time.Duration) error {
	const distributing = 0x20 // LACP actor state bit
	deadline := time.Now().Add(timeout)
	for {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		slave, ok := l.Attrs().Slave.(*netlink.BondSlave)
		if !ok {
			return nil
		}
		if slave.MiiStatus == netlink.BondLinkUp && slave.AdActorOperPortState&distributing != 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("bond member %s did not rejoin its aggregate within %s", name, timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// attachTapFilter adds hp_tc_tap_rx to a tenant TAP's tc ingress at the
// priority after galactic-cni's last filter there, so it sees only what
// usid_egress passed on.
func attachTapFilter(prog *ebpf.Program, tap string) error {
	l, err := netlink.LinkByName(tap)
	if err != nil {
		return err
	}
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return fmt.Errorf("list tc ingress filters on %s: %w", tap, err)
	}
	var last uint16
	for _, f := range filters {
		if bf, ok := f.(*netlink.BpfFilter); ok && bf.Name != tapFilterName && bf.Priority > last {
			last = bf.Priority
		}
	}
	if last == 0 {
		return fmt.Errorf("%s carries no galactic-cni tc ingress filter, so it is not a managed tenant TAP", tap)
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: l.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  last + 1,
		},
		Fd:           prog.FD(),
		Name:         tapFilterName,
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("attach hp_tc_tap_rx to %s: %w", tap, err)
	}
	return nil
}

func ifindex(name string) (uint32, net.HardwareAddr, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return 0, nil, err
	}
	return uint32(l.Attrs().Index), l.Attrs().HardwareAddr, nil
}

func addr16(s string) ([16]byte, error) {
	var out [16]byte
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		return out, fmt.Errorf("%q is not an IPv6 address", s)
	}
	copy(out[:], ip.To16())
	return out, nil
}

func writeRows(objs *probe.Objects, cfg Config) error {
	m := objs.Maps
	if err := m.Cfg.Put(uint32(0), probe.HandoffHpCfgValue{VlanId: cfg.VLANID}); err != nil {
		return err
	}
	for _, write := range []func(probe.Maps, Config) error{writeVIPs, writeTaps, writePairs, writeGuards} {
		if err := write(m, cfg); err != nil {
			return err
		}
	}
	return nil
}

func writeVIPs(m probe.Maps, cfg Config) error {
	for _, v := range cfg.VIPs {
		vip, err := addr16(v.VIP)
		if err != nil {
			return err
		}
		guest, err := addr16(v.Guest)
		if err != nil {
			return err
		}
		tap, _, err := ifindex(v.Tap)
		if err != nil {
			return err
		}
		val := probe.HandoffHpVipValue{TapIfindex: tap, Guest: guest}
		if v.Decide {
			val.Decide = 1
		}
		if err := m.VIP.Put(probe.HandoffHpIn6{A: vip}, val); err != nil {
			return fmt.Errorf("hp_vip %s: %w", v.VIP, err)
		}
	}
	return nil
}

func writeTaps(m probe.Maps, cfg Config) error {
	for _, t := range cfg.Taps {
		tap, _, err := ifindex(t.Tap)
		if err != nil {
			return err
		}
		dut, _, err := ifindex(t.DUT)
		if err != nil {
			return err
		}
		val := probe.HandoffHpTapValue{DutIfindex: dut}
		if val.Vip, err = addr16(t.VIP); err != nil {
			return err
		}
		_, client, err := net.ParseCIDR(t.ClientPrefix)
		if err != nil {
			return err
		}
		copy(val.ClientPrefix[:], client.IP.To16()[:8])
		if t.Pair != "" {
			pair, pairMAC, err := ifindex(t.Pair)
			if err != nil {
				return err
			}
			_, peerMAC, err := ifindex(t.Peer)
			if err != nil {
				return err
			}
			val.PairIfindex = pair
			copy(val.PairSmac[:], pairMAC)
			copy(val.PairDmac[:], peerMAC)
		}
		if err := m.Tap.Put(tap, val); err != nil {
			return fmt.Errorf("hp_tap %s: %w", t.Tap, err)
		}
	}
	return nil
}

func writePairs(m probe.Maps, cfg Config) error {
	for _, p := range cfg.Pairs {
		pair, pairMAC, err := ifindex(p.Pair)
		if err != nil {
			return err
		}
		peer, peerMAC, err := ifindex(p.Peer)
		if err != nil {
			return err
		}
		tap, _, err := ifindex(p.Tap)
		if err != nil {
			return err
		}
		guest, err := addr16(p.Guest)
		if err != nil {
			return err
		}
		shard, err := addr16(p.Shard)
		if err != nil {
			return err
		}
		snat := probe.HandoffHpSnatValue{Guest: guest, Shard: shard}
		if p.Redirect {
			snat.Redirect = 1
		}
		if p.VLAN != nil {
			if snat.VlanIfindex, _, err = ifindex(p.VLAN.Device); err != nil {
				return err
			}
			if snat.LowerIfindex, _, err = ifindex(p.VLAN.Lower); err != nil {
				return err
			}
			snat.Vid = p.VLAN.VID
		}
		if err := m.SNAT.Put(peer, snat); err != nil {
			return err
		}
		sv := probe.HandoffHpShardValue{PeerIfindex: peer, Guest: guest}
		copy(sv.Smac[:], peerMAC)
		copy(sv.Dmac[:], pairMAC)
		if err := m.Shard.Put(probe.HandoffHpIn6{A: shard}, sv); err != nil {
			return err
		}
		if err := m.PairRx.Put(pair, probe.HandoffHpPairRxValue{TapIfindex: tap, Guest: guest}); err != nil {
			return err
		}
	}
	return nil
}

func writeGuards(m probe.Maps, cfg Config) error {
	for _, g := range cfg.Guards {
		idx, _, err := ifindex(g.Iface)
		if err != nil {
			return err
		}
		_, prefix, err := net.ParseCIDR(g.Prefix)
		if err != nil {
			return err
		}
		if ones, _ := prefix.Mask.Size(); ones != 127 {
			return fmt.Errorf("guard prefix %s is not a /127", g.Prefix)
		}
		var v probe.HandoffHpGuardValue
		copy(v.Prefix[:], prefix.IP.To16())
		if err := m.Guard.Put(idx, v); err != nil {
			return err
		}
	}
	return nil
}

// passThrough adds or removes the probe's Local pass-through entries.
func passThrough(cfg Config, add bool) error {
	if len(cfg.PassThrough) == 0 {
		return nil
	}
	table, closer, err := egressroutemap.OpenPinnedEgressRouteTable(cfg.GalacticPinDir)
	if err != nil {
		return err
	}
	defer closer.Close() //nolint:errcheck // our own descriptor

	var errs []error
	for _, p := range cfg.PassThrough {
		l, err := netlink.LinkByName(p.VRF)
		if err != nil {
			if !add {
				continue
			}
			return err
		}
		vrf, ok := l.(*netlink.Vrf)
		if !ok {
			return fmt.Errorf("%s is not a VRF", p.VRF)
		}
		_, prefix, err := net.ParseCIDR(p.Prefix)
		if err != nil {
			return err
		}
		if add {
			if err := table.RegisterPassThroughAs(vrf.Table, prefix, passThroughOwner); err != nil {
				return err
			}
			continue
		}
		if _, err := table.UnregisterPassThroughAs(vrf.Table, prefix, passThroughOwner); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func renew(ctx context.Context, cfg Config) error {
	d, err := xdpdispatch.OpenForSlots(ctx, cfg.dispatchDir())
	if err != nil {
		return err
	}
	defer d.Close() //nolint:errcheck // our own descriptors
	return d.Renew(xdpdispatch.SlotGatewayLB)
}

func counters(cfg Config) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(cfg.mapDir(), "hp_stats"), nil)
	if err != nil {
		return err
	}
	defer m.Close() //nolint:errcheck // our own descriptor
	stats, err := probe.Stats(m)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(stats)
}

// teardown removes everything setup placed. It is safe to run on a partial
// setup and to run twice.
func teardown(ctx context.Context, cfg Config) error {
	var errs []error
	for _, t := range cfg.Taps {
		errs = append(errs, removeFilter(t.Tap, tapFilterName))
	}
	tc := make([]string, 0, len(cfg.TC)+len(cfg.Pairs)+len(cfg.Guards))
	tc = append(tc, cfg.TC...)
	for _, p := range cfg.Pairs {
		tc = append(tc, p.Pair)
	}
	for _, g := range cfg.Guards {
		tc = append(tc, g.Iface)
	}
	if len(tc) > 0 {
		errs = append(errs, attach.Detach(tc))
	}
	for _, p := range cfg.Pairs {
		path := filepath.Join(cfg.linkDir(), "peer-"+p.Peer)
		if l, err := link.LoadPinnedLink(path, nil); err == nil {
			errs = append(errs, l.Unpin(), l.Close())
		}
	}
	if _, err := os.Stat(cfg.dispatchDir()); err == nil {
		errs = append(errs, releaseDispatcher(ctx, cfg))
	}
	errs = append(errs, passThrough(cfg, false))
	errs = append(errs, os.RemoveAll(cfg.PinDir))
	return errors.Join(errs...)
}

func releaseDispatcher(ctx context.Context, cfg Config) error {
	mode, err := cfg.mode()
	if err != nil {
		return err
	}
	d, err := xdpdispatch.Open(ctx, cfg.dispatchDir(), mode)
	if err != nil {
		return err
	}
	defer d.Close() //nolint:errcheck // our own descriptors
	locked, err := d.Lock(ctx)
	if err != nil {
		return err
	}
	defer locked.Unlock()
	errs := []error{locked.Clear(xdpdispatch.SlotGatewayLB)}
	for _, name := range cfg.XDP {
		l, err := netlink.LinkByName(name)
		if err != nil {
			continue // the rig removed it already, and the kernel the link
		}
		errs = append(errs, locked.Release(l.Attrs().Index))
	}
	return errors.Join(errs...)
}

func removeFilter(iface, name string) error {
	l, err := netlink.LinkByName(iface)
	if err != nil {
		return nil // gone with its filters
	}
	filters, err := netlink.FilterList(l, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return err
	}
	for _, f := range filters {
		if bf, ok := f.(*netlink.BpfFilter); ok && bf.Name == name {
			if err := netlink.FilterDel(f); err != nil {
				return fmt.Errorf("remove %s from %s: %w", name, iface, err)
			}
		}
	}
	return nil
}
