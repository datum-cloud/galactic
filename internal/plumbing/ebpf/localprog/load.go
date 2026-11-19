// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package localprog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// PinDir is the default bpffs directory of the Local maps.
const PinDir = "/sys/fs/bpf/galactic-local"

// ErrDatapathMismatch means a uSID map galactic-cni pinned does not match the
// map this build of local.c expects, or a Local map pinned by an earlier
// Worker has another layout.
var ErrDatapathMismatch = errors.New("localprog: the pinned datapath does not match this build")

// ErrDatapathNotLoaded means galactic-cni has not pinned a uSID map the Local
// programs use.
var ErrDatapathNotLoaded = errors.New("localprog: the uSID datapath is not loaded")

// Programs are the Local tc programs. Assigning only these loads only the
// uSID maps they use, never the rest of the datapath local.c includes.
type Programs struct {
	Rx        *ebpf.Program `ebpf:"local_rx"`
	LinkRx    *ebpf.Program `ebpf:"local_link_rx"`
	PairRx    *ebpf.Program `ebpf:"local_pair_rx"`
	LinkGuard *ebpf.Program `ebpf:"local_link_guard"`
}

// Close closes every program descriptor.
func (p *Programs) Close() error {
	var errs []error
	for _, prog := range []*ebpf.Program{p.Rx, p.LinkRx, p.PairRx, p.LinkGuard} {
		if prog != nil {
			errs = append(errs, prog.Close())
		}
	}
	return errors.Join(errs...)
}

// Maps are the Local maps.
type Maps struct {
	Tap   *ebpf.Map `ebpf:"lt_tap"`
	Link  *ebpf.Map `ebpf:"lt_link"`
	Guest *ebpf.Map `ebpf:"lt_guest"`
	Pair  *ebpf.Map `ebpf:"lt_pair"`
	Guard *ebpf.Map `ebpf:"lt_guard"`
	Flow  *ebpf.Map `ebpf:"lt_flow"`
	Stats *ebpf.Map `ebpf:"lt_stats"`
}

// Close closes every map descriptor.
func (m *Maps) Close() error {
	var errs []error
	for _, mp := range []*ebpf.Map{m.Tap, m.Link, m.Guest, m.Pair, m.Guard, m.Flow, m.Stats} {
		if mp != nil {
			errs = append(errs, mp.Close())
		}
	}
	return errors.Join(errs...)
}

// Objects are the loaded Local programs and maps.
type Objects struct {
	Programs Programs
	Maps     Maps
	pinned   []*ebpf.Map
}

// Close releases this process's descriptors. Pinned maps and attached tc
// filters stay.
func (o *Objects) Close() error {
	errs := make([]error, 0, 2+len(o.pinned))
	errs = append(errs, o.Programs.Close(), o.Maps.Close())
	for _, m := range o.pinned {
		errs = append(errs, m.Close())
	}
	return errors.Join(errs...)
}

// Load loads the Local programs. Every uSID map they use is replaced with the
// map pinned under galacticPinDir, and a map with no pin there fails the load
// with ErrDatapathNotLoaded, so Load never creates or changes a uSID pin. The
// Local maps (lt_*) are pinned under localPinDir, so a restarted Worker keeps
// the rows the running programs read.
func Load(galacticPinDir, localPinDir string) (*Objects, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("localprog: remove memlock rlimit: %w", err)
	}
	spec, err := LoadLocal()
	if err != nil {
		return nil, fmt.Errorf("localprog: load compiled spec: %w", err)
	}
	if err := os.MkdirAll(localPinDir, 0o755); err != nil {
		return nil, fmt.Errorf("localprog: create map pin directory: %w", err)
	}

	objs := &Objects{}
	replacements := map[string]*ebpf.Map{}
	var missing []string
	for name, m := range spec.Maps {
		switch {
		case strings.HasPrefix(name, "lt_"):
			m.Pinning = ebpf.PinByName
		case strings.HasPrefix(name, "."):
			// Global data of the included source, private to this load.
		default:
			pinned, err := ebpf.LoadPinnedMap(filepath.Join(galacticPinDir, name), nil)
			if err != nil {
				// Not pinned: drop it from the spec. A program that uses it
				// then fails to load instead of getting a fresh map.
				delete(spec.Maps, name)
				missing = append(missing, name)
				continue
			}
			replacements[name] = pinned
			objs.pinned = append(objs.pinned, pinned)
		}
	}

	opts := &ebpf.CollectionOptions{
		Maps:            ebpf.MapOptions{PinPath: localPinDir},
		MapReplacements: replacements,
	}
	if err := spec.LoadAndAssign(&objs.Programs, opts); err != nil {
		_ = objs.Close()
		var ve *ebpf.VerifierError
		switch {
		case errors.Is(err, ebpf.ErrMapIncompatible):
			return nil, fmt.Errorf("%w: %w", ErrDatapathMismatch, err)
		case errors.As(err, &ve):
			return nil, fmt.Errorf("localprog: verifier rejected a Local program:\n%w", ve)
		case len(missing) > 0:
			return nil, fmt.Errorf("%w: no pin for %s under %s: %w", ErrDatapathNotLoaded,
				strings.Join(missing, ", "), galacticPinDir, err)
		}
		return nil, fmt.Errorf("localprog: load programs: %w", err)
	}
	if err := spec.LoadAndAssign(&objs.Maps, opts); err != nil {
		_ = objs.Close()
		if errors.Is(err, ebpf.ErrMapIncompatible) {
			return nil, fmt.Errorf("%w: %w", ErrDatapathMismatch, err)
		}
		return nil, fmt.Errorf("localprog: load Local maps: %w", err)
	}
	return objs, nil
}

// StatNames names lt_stats' slots, in local.c's enum lt_stat order.
var StatNames = []string{
	"rx_no_meta",
	"rx_unclaimed",
	"rx_not_ipv6",
	"rx_fragment",
	"rx_too_big",
	"rx_deny",
	"rx_deliver",
	"link_reply",
	"link_reply_deny",
	"link_nat",
	"link_nat_deny",
	"pair_unclaimed",
	"pair_not_ipv6",
	"pair_fragment",
	"pair_too_big",
	"pair_deny",
	"pair_deliver",
	"guard_pass",
	"guard_drop",
}

// Stats reads lt_stats by name, summed over CPUs.
func Stats(m *ebpf.Map) (map[string]uint64, error) {
	out := make(map[string]uint64, len(StatNames))
	for i, name := range StatNames {
		var per []uint64
		if err := m.Lookup(uint32(i), &per); err != nil {
			return nil, fmt.Errorf("localprog: read %s: %w", name, err)
		}
		var n uint64
		for _, v := range per {
			n += v
		}
		out[name] = n
	}
	return out, nil
}
