// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/natmap"
	"go.datum.net/galactic/internal/plumbing/sysctl"
)

// localLinkPrefix names the pinned XDP link of a pair's NAT end under the
// links directory: local-<NAT end name>.
const localLinkPrefix = "local-"

// kernelLocal attaches nat_ingress to pairs' NAT ends and writes their rows.
//
// The program runs native on a NAT end whatever mode the host's uplinks use:
// generic XDP skips every packet a tc program redirected, which is how the
// tenant's packet enters the pair (docs/worker/contract.md, Local handoffs).
// It is attached directly, never through the XDP dispatcher, which holds one
// host mode for every link it manages. Each attachment is a bpf link pinned
// under linkDir, so a restarted process finds it still attached and the
// pair's sessions keep translating meanwhile.
type kernelLocal struct {
	program *ebpf.Program
	linkDir string
	tables  natmap.LocalTables
	vlans   natmap.VLANTable

	mu sync.Mutex
}

func newKernelLocal(program *ebpf.Program, pinDir string, tables natmap.LocalTables,
	vlans natmap.VLANTable) (*kernelLocal, error) {
	dir := filepath.Join(pinDir, "links")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create the local link pin directory %s: %w", dir, err)
	}
	return &kernelLocal{program: program, linkDir: dir, tables: tables, vlans: vlans}, nil
}

func (k *kernelLocal) linkPath(natName string) string {
	return filepath.Join(k.linkDir, localLinkPrefix+natName)
}

// Program implements localPlumbing.
func (k *kernelLocal) Program(t localTarget) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	nat, err := netlink.LinkByIndex(t.NATIfindex)
	if err != nil {
		return fmt.Errorf("find NAT end %d: %w", t.NATIfindex, err)
	}
	if nat.Attrs().Name != t.NATName {
		return fmt.Errorf("NAT end %d is %q, not %q", t.NATIfindex, nat.Attrs().Name, t.NATName)
	}
	tenantMAC, err := tenantEndMAC(nat, t.TenantName)
	if err != nil {
		return err
	}
	// The forward legs' FIB lookup runs scoped to the NAT end, which
	// refuses every packet while forwarding is off on it.
	if err := sysctl.ConfigureFIBLookupUplinkSysctls(t.NATName); err != nil {
		return fmt.Errorf("configure IPv6 forwarding on %s: %w", t.NATName, err)
	}
	if err := sysctl.ConfigureFIBLookupUplinkSysctlsIPv4(t.NATName); err != nil {
		return fmt.Errorf("configure IPv4 forwarding on %s: %w", t.NATName, err)
	}
	if err := k.syncVLANs(); err != nil {
		return err
	}
	// Rows first: a packet the attached program sees finds its tenant.
	if err := k.tables.Put(natmap.LocalPair{NATIfindex: uint32(t.NATIfindex), //nolint:gosec // kernel ifindex
		TenantSID: t.TenantSID, NATMAC: nat.Attrs().HardwareAddr, TenantMAC: tenantMAC}); err != nil {
		return err
	}
	return k.attach(t)
}

// attach keeps a native XDP link of the program on t's NAT end, pinned. A
// pinned link already on that ifindex is updated to this process's program;
// one left on an older interface of the same name is replaced.
func (k *kernelLocal) attach(t localTarget) error {
	path := k.linkPath(t.NATName)
	if l, err := link.LoadPinnedLink(path, nil); err == nil {
		info, infoErr := l.Info()
		if infoErr == nil {
			if xdp := info.XDP(); xdp != nil && int(xdp.Ifindex) == t.NATIfindex {
				err := l.Update(k.program)
				_ = l.Close()
				if err != nil {
					return fmt.Errorf("update the XDP program on %s: %w", t.NATName, err)
				}
				return nil
			}
		}
		_ = l.Unpin()
		_ = l.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		slog.Warn("Replacing an unreadable pinned local XDP link", "path", path, "err", err)
		_ = os.Remove(path)
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: k.program, Interface: t.NATIfindex, Flags: link.XDPDriverMode})
	if err != nil {
		return fmt.Errorf("attach nat_ingress native to %s: %w", t.NATName, err)
	}
	if err := l.Pin(path); err != nil {
		_ = l.Close()
		return fmt.Errorf("pin the XDP link of %s: %w", t.NATName, err)
	}
	return l.Close()
}

// tenantEndMAC returns the MAC of the pair's tenant end: by name when Worker
// reported it, otherwise as the NAT end's veth peer.
func tenantEndMAC(nat netlink.Link, tenantName string) (net.HardwareAddr, error) {
	var (
		tenant netlink.Link
		err    error
	)
	if tenantName != "" {
		tenant, err = netlink.LinkByName(tenantName)
	} else {
		var peer int
		peer, err = netlink.VethPeerIndex(&netlink.Veth{LinkAttrs: *nat.Attrs()})
		if err == nil {
			tenant, err = netlink.LinkByIndex(peer)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("find the tenant end of %s: %w", nat.Attrs().Name, err)
	}
	return tenant.Attrs().HardwareAddr, nil
}

// syncVLANs writes a nat_vlan_egress row for every VLAN device on the host and
// removes rows of devices that are gone.
func (k *kernelLocal) syncVLANs() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links: %w", err)
	}
	have, err := k.vlans.All()
	if err != nil {
		return err
	}
	seen := map[uint32]bool{}
	for _, l := range links {
		v, ok := l.(*netlink.Vlan)
		if !ok || v.ParentIndex <= 0 {
			continue
		}
		proto := uint16(0x8100)
		if v.VlanProtocol == netlink.VLAN_PROTOCOL_8021AD {
			proto = 0x88a8
		}
		e := natmap.VLANEgress{Ifindex: uint32(v.Index), LowerIfindex: uint32(v.ParentIndex), //nolint:gosec // ifindexes
			VID: uint16(v.VlanId), Proto: proto} //nolint:gosec // a VLAN ID
		seen[e.Ifindex] = true
		if have[e.Ifindex] == e {
			continue
		}
		if err := k.vlans.Put(e); err != nil {
			return err
		}
	}
	for ifx := range have {
		if !seen[ifx] {
			if err := k.vlans.Delete(ifx); err != nil {
				return err
			}
		}
	}
	return nil
}

// Unprogram implements localPlumbing.
func (k *kernelLocal) Unprogram(t localTarget) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.tables.DeletePair(uint32(t.NATIfindex)); err != nil { //nolint:gosec // kernel ifindex
		return err
	}
	if err := k.tables.DeleteReturn(t.TenantSID); err != nil {
		return err
	}
	return k.detach(t.NATName)
}

func (k *kernelLocal) detach(natName string) error {
	path := k.linkPath(natName)
	l, err := link.LoadPinnedLink(path, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return os.Remove(path)
	}
	defer func() { _ = l.Close() }()
	if err := l.Unpin(); err != nil {
		return fmt.Errorf("unpin the XDP link of %s: %w", natName, err)
	}
	return nil
}

// Prune implements localPlumbing.
func (k *kernelLocal) Prune(keep []localTarget) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	keepIfx := map[uint32]bool{}
	keepSID := map[string]bool{}
	keepName := map[string]bool{}
	for _, t := range keep {
		keepIfx[uint32(t.NATIfindex)] = true //nolint:gosec // kernel ifindex
		keepSID[t.TenantSID.String()] = true
		keepName[t.NATName] = true
	}
	pairs, err := k.tables.All()
	if err != nil {
		return err
	}
	for _, p := range pairs {
		if !keepIfx[p.NATIfindex] {
			if err := k.tables.DeletePair(p.NATIfindex); err != nil {
				return err
			}
		}
	}
	sids, err := k.tables.ReturnSIDs()
	if err != nil {
		return err
	}
	for _, sid := range sids {
		if !keepSID[sid.String()] {
			if err := k.tables.DeleteReturn(sid); err != nil {
				return err
			}
		}
	}
	// nat_vlan_egress serves only Local forwards, and syncVLANs is its only
	// writer, so with no pair to keep none of its rows is needed.
	if len(keep) == 0 {
		vlans, err := k.vlans.All()
		if err != nil {
			return err
		}
		for ifx := range vlans {
			if err := k.vlans.Delete(ifx); err != nil {
				return err
			}
		}
	}
	entries, err := os.ReadDir(k.linkDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", k.linkDir, err)
	}
	for _, e := range entries {
		name, ok := strings.CutPrefix(e.Name(), localLinkPrefix)
		if ok && !keepName[name] {
			if err := k.detach(name); err != nil {
				return err
			}
		}
	}
	return nil
}

// openPinnedLocal opens the Local state a previous process pinned under
// pinDir, for a start that has no datapath loaded to prune it with. A missing
// map or link directory is read as empty, and nothing is created, so a node
// that never ran the integration is left as it is. The result only prunes:
// it holds no program to attach. close releases the opened maps.
func openPinnedLocal(pinDir string) (plumb *kernelLocal, closeMaps func(), err error) {
	var opened []*ebpf.Map
	closeMaps = func() {
		for _, m := range opened {
			_ = m.Close()
		}
	}
	open := func(name string) (natmap.Table, error) {
		m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
		if errors.Is(err, os.ErrNotExist) {
			return emptyTable{}, nil
		}
		if err != nil {
			return nil, fmt.Errorf("open the pinned map %s: %w", name, err)
		}
		opened = append(opened, m)
		return natmap.KernelTable{Map: m}, nil
	}
	tables := make([]natmap.Table, 0, 3)
	for _, name := range []string{"nat_local_pair", "nat_local_return", "nat_vlan_egress"} {
		t, err := open(name)
		if err != nil {
			closeMaps()
			return nil, nil, err
		}
		tables = append(tables, t)
	}
	return &kernelLocal{
		linkDir: filepath.Join(pinDir, "links"),
		tables:  natmap.LocalTables{Pair: tables[0], Return: tables[1]},
		vlans:   natmap.VLANTable{Table: tables[2]},
	}, closeMaps, nil
}

// emptyTable is a map that holds nothing: a pinned map that does not exist.
type emptyTable struct{}

func (emptyTable) Put(any, any) error    { return errors.New("the map is not pinned") }
func (emptyTable) Lookup(any, any) error { return ebpf.ErrKeyNotExist }
func (emptyTable) Delete(any) error      { return ebpf.ErrKeyNotExist }
func (emptyTable) Iterate() natmap.Iterator {
	return emptyIterator{}
}

type emptyIterator struct{}

func (emptyIterator) Next(any, any) bool { return false }
func (emptyIterator) Err() error         { return nil }
