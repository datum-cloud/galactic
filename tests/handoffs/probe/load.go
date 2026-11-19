// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
)

// ErrDatapathMismatch means a uSID map galactic-cni pinned does not match the
// map this build of handoff.c expects, so the running datapath was built from
// a different revision than this checkout.
var ErrDatapathMismatch = errors.New("probe: the pinned uSID datapath does not match this checkout")

// Programs are the prototype programs. Assigning only these loads only the
// uSID maps they use, never the rest of the datapath handoff.c includes.
type Programs struct {
	XDPPublic   *ebpf.Program `ebpf:"hp_xdp_public"`
	TCTenantRx  *ebpf.Program `ebpf:"hp_tc_tenant_rx"`
	TCTapRx     *ebpf.Program `ebpf:"hp_tc_tap_rx"`
	XDPPairPeer *ebpf.Program `ebpf:"hp_xdp_pair_peer"`
	TCPairRx    *ebpf.Program `ebpf:"hp_tc_pair_rx"`
	TCLinkGuard *ebpf.Program `ebpf:"hp_tc_link_guard"`
}

// Close closes every program descriptor.
func (p *Programs) Close() error {
	var errs []error
	for _, prog := range []*ebpf.Program{p.XDPPublic, p.TCTenantRx, p.TCTapRx, p.XDPPairPeer, p.TCPairRx,
		p.TCLinkGuard} {
		if prog != nil {
			errs = append(errs, prog.Close())
		}
	}
	return errors.Join(errs...)
}

// Maps are the probe's own maps.
type Maps struct {
	VIP    *ebpf.Map `ebpf:"hp_vip"`
	Shard  *ebpf.Map `ebpf:"hp_shard"`
	Tap    *ebpf.Map `ebpf:"hp_tap"`
	SNAT   *ebpf.Map `ebpf:"hp_snat"`
	PairRx *ebpf.Map `ebpf:"hp_pair_rx"`
	Guard  *ebpf.Map `ebpf:"hp_guard"`
	Cfg    *ebpf.Map `ebpf:"hp_cfg"`
	Stats  *ebpf.Map `ebpf:"hp_stats"`
}

// Close closes every map descriptor.
func (m *Maps) Close() error {
	var errs []error
	for _, mp := range []*ebpf.Map{m.VIP, m.Shard, m.Tap, m.SNAT, m.PairRx, m.Guard, m.Cfg, m.Stats} {
		if mp != nil {
			errs = append(errs, mp.Close())
		}
	}
	return errors.Join(errs...)
}

// Objects are the loaded prototype programs and their own maps.
type Objects struct {
	Programs Programs
	Maps     Maps
	pinned   []*ebpf.Map
}

// Close releases this process's descriptors. Pinned maps, links and tc
// filters stay.
func (o *Objects) Close() error {
	errs := make([]error, 0, 2+len(o.pinned))
	errs = append(errs, o.Programs.Close(), o.Maps.Close())
	for _, m := range o.pinned {
		errs = append(errs, m.Close())
	}
	return errors.Join(errs...)
}

// Load loads the prototype programs. Every uSID map they use is replaced with
// the map pinned under galacticPinDir, and a map with no pin there fails the
// load, so Load never creates or changes a product pin. The probe's own maps
// (hp_*) are pinned under mapDir, so later invocations read the same ones.
func Load(galacticPinDir, mapDir string) (*Objects, error) {
	spec, err := LoadHandoff()
	if err != nil {
		return nil, fmt.Errorf("probe: load compiled spec: %w", err)
	}
	if err := os.MkdirAll(mapDir, 0o755); err != nil {
		return nil, fmt.Errorf("probe: create map pin directory: %w", err)
	}

	objs := &Objects{}
	replacements := map[string]*ebpf.Map{}
	for name, m := range spec.Maps {
		switch {
		case strings.HasPrefix(name, "hp_"):
			m.Pinning = ebpf.PinByName
		case strings.HasPrefix(name, "."):
			// Global data of the included source, private to this load.
		default:
			pinned, err := ebpf.LoadPinnedMap(filepath.Join(galacticPinDir, name), nil)
			if err != nil {
				// Not pinned: drop it from the spec. A program that uses it
				// then fails to load instead of getting a fresh map.
				delete(spec.Maps, name)
				continue
			}
			replacements[name] = pinned
			objs.pinned = append(objs.pinned, pinned)
		}
	}

	opts := &ebpf.CollectionOptions{
		Maps:            ebpf.MapOptions{PinPath: mapDir},
		MapReplacements: replacements,
	}
	if err := spec.LoadAndAssign(&objs.Programs, opts); err != nil {
		_ = objs.Close()
		if errors.Is(err, ebpf.ErrMapIncompatible) {
			return nil, fmt.Errorf("%w: %w", ErrDatapathMismatch, err)
		}
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("probe: verifier rejected a prototype program: %w\n%s", err, fmt.Sprintf("%+v", ve))
		}
		return nil, fmt.Errorf("probe: load programs: %w", err)
	}
	if err := spec.LoadAndAssign(&objs.Maps, opts); err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("probe: load probe maps: %w", err)
	}
	return objs, nil
}

// StatNames names hp_stats' slots, in handoff.c's enum hp_stat order.
var StatNames = []string{
	"xdp_vip",
	"xdp_meta_set",
	"xdp_meta_fail",
	"xdp_shard",
	"xdp_shard_vlan_pop",
	"tc_meta_ok",
	"tc_meta_missing",
	"tc_tenant_deny",
	"tc_tenant_redirect",
	"tap_reply",
	"tap_reply_deny",
	"tap_nat",
	"tap_nat_deny",
	"peer_snat",
	"peer_redirect",
	"peer_pass",
	"pair_rx",
	"pair_rx_deny",
	"guard_pass",
	"guard_drop",
	"max_seen_len",
	"peer_vlan_push",
}

// Stats reads hp_stats by name.
func Stats(m *ebpf.Map) (map[string]uint64, error) {
	out := make(map[string]uint64, len(StatNames))
	for i, name := range StatNames {
		var v uint64
		if err := m.Lookup(uint32(i), &v); err != nil {
			return nil, fmt.Errorf("probe: read %s: %w", name, err)
		}
		out[name] = v
	}
	return out, nil
}
