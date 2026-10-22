// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/preflight"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
)

// trafficPolicyState owns tp_state and tp_nat_locator_table for galactic-cni
// run: the node's mode and mark, whether the kernel passed the traffic policy
// preflight, and the NAT shard locators the datapath classifies paths by.
type trafficPolicyState struct {
	mu    sync.Mutex
	maps  *tpmap.Maps
	state tpmap.State
}

// trafficPolicyModes maps config.EnvCNITrafficPolicy's values to tp_state's.
var trafficPolicyModes = map[string]uint32{
	config.TrafficPolicyOff:     tpmap.ModeOff,
	config.TrafficPolicyAudit:   tpmap.ModeAudit,
	config.TrafficPolicyEnforce: tpmap.ModeEnforce,
}

// startTrafficPolicy runs the traffic policy preflight and writes the node's
// mode. The NAT locators start unsynced, so until setNATLocators runs an
// encapsulating route's path is unknown and a rule naming a path denies it.
func startTrafficPolicy(objs *prog.UsidObjects, pinDir string, cfg config.TrafficPolicyConfig) *trafficPolicyState {
	s := &trafficPolicyState{
		maps:  tpmap.FromPinnedObjects(objs, pinDir),
		state: tpmap.State{Mode: trafficPolicyModes[cfg.Mode], Mark: cfg.Mark, Capable: true},
	}
	if err := preflight.CheckTrafficPolicy(cfg.KernelCheck); err != nil {
		s.state.Capable = false
		if cfg.Mode != config.TrafficPolicyOff {
			slog.Error("Traffic policy is on but this kernel cannot enforce it; CNI ADD refuses new interfaces "+
				"until it can", "mode", cfg.Mode, "err", err)
		}
	}
	s.write()
	if cfg.Mode != config.TrafficPolicyOff && cfg.Mark == 0 {
		slog.Warn("GALACTIC_CNI_POLICY_MARK is 0: packets usid_ingress delivers through a host interface are " +
			"decided and counted twice")
	}
	s.reconcileInterfaces()
	slog.Info("Interface traffic policy configured", "mode", cfg.Mode, "mark", cfg.Mark, "capable", s.state.Capable)
	return s
}

// setNATLocators records every SID's locator as a NAT shard's and marks the
// set complete. Locators are only ever added: shard locators are disjoint
// from every router locator, so a retained one classifies nothing wrongly.
func (s *trafficPolicyState) setNATLocators(sids []net.IP) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ip := range sids {
		sid, ok := netip.AddrFromSlice(ip.To16())
		if !ok {
			continue
		}
		if err := s.maps.AddNATLocator(sid); err != nil {
			slog.Warn("Failed to record an egress shard locator; encapsulated paths stay unknown", "sid", sid, "err", err)
			return
		}
	}
	if !s.state.NATLocatorsSynced {
		s.state.NATLocatorsSynced = true
		s.writeLocked()
	}
}

func (s *trafficPolicyState) write() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeLocked()
}

func (s *trafficPolicyState) writeLocked() {
	if err := s.maps.SetState(s.state); err != nil {
		slog.Error("Failed to write traffic policy state", "err", err)
	}
}

// reconcileInterfaces keeps tp_iface_table to the interfaces that exist. An
// interface created before traffic policy shipped has the egress chain but no
// row, so a node switched on would deny it everything; it gets a tenant row
// with a fresh token, and galactic-router publishes its bindings against it.
// Its assigned addresses are unknown here, so until it is recreated its ARP
// and neighbor discovery from a global source are ordinary traffic. A row
// whose interface no longer exists, left by a DEL that could not find its
// link, is removed so a reused ifindex cannot inherit it.
func (s *trafficPolicyState) reconcileInterfaces() {
	links, err := attach.ManagedInterfaces()
	if err != nil {
		slog.Warn("Failed to list managed interfaces for traffic policy", "err", err)
		return
	}
	present := make(map[uint32]bool, len(links))
	for _, link := range links {
		ifindex := uint32(link.Attrs().Index) //nolint:gosec // a kernel ifindex
		present[ifindex] = true
		if ifindex >= ifindexvrfmap.SidecarIfindexBase {
			continue // the ingress sidecar writes its own infra rows
		}
		var row prog.UsidTpIfaceValue
		if err := s.maps.Interfaces.Lookup(ifindex, &row); err == nil {
			continue
		}
		token, err := tpmap.NewPolicyToken()
		if err == nil {
			err = s.maps.PutInterface(ifindex, token, tpmap.KindTenant)
		}
		if err != nil {
			slog.Warn("Failed to backfill a traffic policy row", "interface", link.Attrs().Name, "err", err)
			continue
		}
		slog.Info("Backfilled a traffic policy row for an interface that predates it", "interface", link.Attrs().Name)
	}
	var (
		key   uint32
		row   prog.UsidTpIfaceValue
		stale []uint32
	)
	it := s.maps.Interfaces.Iterate()
	for it.Next(&key, &row) {
		if !present[key] {
			stale = append(stale, key)
		}
	}
	for _, ifindex := range stale {
		if _, err := netlink.LinkByIndex(int(ifindex)); err == nil {
			continue // exists, just without the chain yet
		}
		if err := s.maps.RemoveInterface(ifindex); err != nil {
			slog.Warn("Failed to remove a stale traffic policy row", "ifindex", ifindex, "err", err)
		}
	}
}
