// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srcfiltermap

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("test requires root (CAP_BPF/CAP_NET_ADMIN) to load real BPF maps; re-run via sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("rlimit.RemoveMemlock: %v", err)
	}
}

func loadTestObjects(t *testing.T, opts *ebpf.CollectionOptions) *prog.UsidObjects {
	t.Helper()
	spec, err := prog.LoadUsid()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	if opts != nil {
		for _, m := range spec.Maps {
			m.Pinning = ebpf.PinByName
		}
	}
	var objs prog.UsidObjects
	if err := spec.LoadAndAssign(&objs, opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load objects: verifier rejected program:\n%+v", ve)
		}
		t.Fatalf("load objects: %v", err)
	}
	t.Cleanup(func() {
		if err := objs.Close(); err != nil {
			t.Errorf("close objects: %v", err)
		}
	})
	return &objs
}

// TestKernelMaps round-trips every Filter operation through real kernel maps,
// proving the Go key and value layouts match the datapath's.
func TestKernelMaps(t *testing.T) {
	requireRoot(t)
	objs := loadTestObjects(t, nil)
	f := NewFromObjects(objs)

	desired := []Entry{
		{Prefix: netip.MustParsePrefix("fd00:aa::/32"), IfaceMask: 1<<0 | 1<<3},
		{Prefix: netip.MustParsePrefix("fd00:aa:1::/48"), AnyIface: true},
	}
	if _, err := f.SyncAllow(desired); err != nil {
		t.Fatalf("SyncAllow: %v", err)
	}
	got, err := f.ListAllow()
	if err != nil {
		t.Fatalf("ListAllow: %v", err)
	}
	if !reflect.DeepEqual(got, desired) {
		t.Errorf("ListAllow = %+v, want %+v", got, desired)
	}

	var v prog.UsidSrcAllowValue
	probe := prog.UsidSrcAllowKey{Prefixlen: 128, Addr: netip.MustParseAddr("fd00:aa:1::7").As16()}
	if err := objs.SrcAllowTable.Lookup(probe, &v); err != nil {
		t.Fatalf("longest-prefix probe: %v", err)
	}
	if v.Flags != prog.SrcFilterFlagAnyIface {
		t.Errorf("probe matched %+v, want the more specific any-iface entry", v)
	}

	if res, err := f.SyncAllow(desired[:1]); err != nil || res.Removed != 1 || res.Unchanged != 1 {
		t.Errorf("SyncAllow shrink = %+v, %v, want one removed and one unchanged", res, err)
	}

	if err := f.SyncUplinkSlots(map[uint32]uint8{4: 0, 5: 3}); err != nil {
		t.Fatalf("SyncUplinkSlots: %v", err)
	}
	slots, err := f.UplinkSlots()
	if err != nil {
		t.Fatalf("UplinkSlots: %v", err)
	}
	if want := map[uint32]uint8{4: 0, 5: 3}; !reflect.DeepEqual(slots, want) {
		t.Errorf("UplinkSlots = %v, want %v", slots, want)
	}

	cfg, err := f.Config()
	if err != nil || cfg != (Config{}) {
		t.Errorf("fresh Config = %+v, %v, want zero", cfg, err)
	}
	want := Config{Mode: ModeEnforce, Populated: true, Generation: 2}
	if err := f.SetConfig(want); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	if cfg, err = f.Config(); err != nil || cfg != want {
		t.Errorf("Config = %+v, %v, want %+v", cfg, err, want)
	}

	stats, err := f.Stats()
	if err != nil || stats != (Stats{}) {
		t.Errorf("fresh Stats = %+v, %v, want zero", stats, err)
	}

	var key prog.UsidSrcDeniedKey
	a := netip.MustParseAddr("2001:db8:5:6::1").As16()
	copy(key.Prefix[:], a[:8])
	if err := objs.SrcFilterDenied.Put(key, prog.UsidSrcDeniedValue{Count: 3, LastNs: 9, LastIfindex: 4,
		LastReason: prog.SrcFilterStatDenyPrefix}); err != nil {
		t.Fatalf("seed src_filter_denied: %v", err)
	}
	denied, err := f.DeniedSources()
	if err != nil {
		t.Fatalf("DeniedSources: %v", err)
	}
	wantDenied := []DeniedSource{{Prefix: netip.MustParsePrefix("2001:db8:5:6::/64"), Count: 3, LastIfindex: 4,
		LastSeenNs: 9, LastReason: DenyReasonPrefix}}
	if !reflect.DeepEqual(denied, wantDenied) {
		t.Errorf("DeniedSources = %+v, want %+v", denied, wantDenied)
	}
}

func TestOpenPinned(t *testing.T) {
	requireRoot(t)
	if _, err := os.Stat("/sys/fs/bpf"); err != nil {
		t.Skipf("test requires a bpffs at /sys/fs/bpf: %v", err)
	}
	pinDir, err := os.MkdirTemp("/sys/fs/bpf", "srcfiltermap-test-")
	if err != nil {
		t.Skipf("cannot create a pin directory on bpffs: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pinDir) })

	if _, _, err := OpenPinned(filepath.Join(pinDir, "missing")); err == nil {
		t.Error("OpenPinned on an empty directory succeeded, want error")
	}

	objs := loadTestObjects(t, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}})
	f, closer, err := OpenPinned(pinDir)
	if err != nil {
		t.Fatalf("OpenPinned: %v", err)
	}
	t.Cleanup(func() { _ = closer.Close() })

	if err := f.SetConfig(Config{Mode: ModeAudit}); err != nil {
		t.Fatalf("SetConfig through pin: %v", err)
	}
	var cfg prog.UsidSrcFilterConfig
	if err := objs.SrcFilterConfigTable.Lookup(uint32(0), &cfg); err != nil {
		t.Fatalf("read back config: %v", err)
	}
	if cfg.Mode != prog.SrcFilterModeAudit {
		t.Errorf("pinned config mode = %d, want audit", cfg.Mode)
	}
}
