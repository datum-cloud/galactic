// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package mssclamp

import (
	"errors"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

// TestFromMTU_FabricAt1500 pins the values for the fabric MTU production and
// the lab both run.
func TestFromMTU_FabricAt1500(t *testing.T) {
	got, err := FromMTU(1500)
	if err != nil {
		t.Fatalf("FromMTU(1500): %v", err)
	}
	if want := (Values{IPv4: 1420, IPv6: 1400}); got != want {
		t.Errorf("FromMTU(1500) = %+v, want %+v", got, want)
	}
}

// TestFromMTU_EveryPathFits checks the arithmetic, not just one answer: at
// every MTU, a full-size segment at each limit makes a packet of exactly the
// MTU once encapsulated, on every path the clamp covers.
func TestFromMTU_EveryPathFits(t *testing.T) {
	for _, mtu := range []int{MinMTU, 1400, 1496, 1500, 9000, MaxMTU} {
		v, err := FromMTU(mtu)
		if err != nil {
			t.Fatalf("FromMTU(%d): %v", mtu, err)
		}
		paths := []struct {
			name string
			size int
		}{
			{"IPv6 tenant", int(v.IPv6) + tcpHeaderLen + ipv6HeaderLen + OuterHeaderLen},
			{"IPv4 tenant", int(v.IPv4) + tcpHeaderLen + ipv4HeaderLen + OuterHeaderLen},
			// An IPv6 tenant's segment arrives from the IPv4 internet with an
			// IPv4 header, which the shard translates to IPv6 before
			// re-encapsulating it.
			{"NAT64 reply", int(v.IPv6) + tcpHeaderLen + ipv4HeaderLen + (ipv6HeaderLen - ipv4HeaderLen) + OuterHeaderLen},
		}
		for _, p := range paths {
			if p.size != mtu {
				t.Errorf("MTU %d, %s: full-size packet is %d bytes encapsulated, want exactly %d", mtu, p.name, p.size, mtu)
			}
		}
	}
}

func TestFromMTU_RejectsOutOfRange(t *testing.T) {
	for _, mtu := range []int{0, -1, MinMTU - 1, MaxMTU + 1} {
		if v, err := FromMTU(mtu); err == nil {
			t.Errorf("FromMTU(%d) = %+v, nil; want an error", mtu, v)
		}
	}
}

const testUplink = "bond0"

func TestResolve(t *testing.T) {
	at1500 := Values{IPv4: 1420, IPv6: 1400}
	for _, tc := range []struct {
		name     string
		override string
		mtus     []int
		want     Values
		wantErr  bool
	}{
		{"unset means auto", "", []int{1500}, at1500, false},
		{"auto", ModeAuto, []int{1500}, at1500, false},
		{"auto is case- and space-insensitive", " AUTO ", []int{1500}, at1500, false},
		// A packet may leave by any uplink, so the smallest one decides.
		{"auto takes the smallest uplink", ModeAuto, []int{9000, 1500, 9000}, at1500, false},
		{"auto with no uplink MTU is an error", ModeAuto, nil, Off, true},
		{"auto with an uplink below the IPv6 minimum is an error", ModeAuto, []int{1500, 1200}, Off, true},
		{"off", ModeOff, []int{1500}, Off, false},
		{"off needs no uplink", ModeOff, nil, Off, false},
		{"a number is the fabric MTU", "1496", []int{1500}, Values{IPv4: 1416, IPv6: 1396}, false},
		{"a number overrides a larger uplink MTU", "1500", []int{9000}, at1500, false},
		{"a number below the IPv6 minimum is an error", "1000", nil, Off, true},
		{"a number above the maximum is an error", "70000", nil, Off, true},
		// A typo must not silently fall back to auto or to off.
		{"garbage is an error", "1500b", []int{1500}, Off, true},
		{"a misspelt mode is an error", "of", []int{1500}, Off, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(tc.override, tc.mtus)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Resolve(%q, %v) error = %v, want error %v", tc.override, tc.mtus, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("Resolve(%q, %v) = %+v, want %+v", tc.override, tc.mtus, got, tc.want)
			}
		})
	}
}

// fakeTable records every Put.
type fakeTable struct {
	puts []prog.UsidMssClampValue
	keys []any
	err  error
}

func (f *fakeTable) Put(key, value any) error {
	if f.err != nil {
		return f.err
	}
	f.keys = append(f.keys, key)
	f.puts = append(f.puts, value.(prog.UsidMssClampValue))
	return nil
}

func TestWrite_SingleEntryLayout(t *testing.T) {
	var table fakeTable
	if err := Write(&table, Values{IPv4: 1420, IPv6: 1400}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(table.puts) != 1 || table.keys[0] != uint32(0) {
		t.Fatalf("Write made puts %v with keys %v, want one put at key uint32(0)", table.puts, table.keys)
	}
	if want := (prog.UsidMssClampValue{MssIpv4: 1420, MssIpv6: 1400}); table.puts[0] != want {
		t.Errorf("Write stored %+v, want %+v: each family's value in its own field", table.puts[0], want)
	}
}

// withLinkMTUs replaces LinkMTU for one test.
func withLinkMTUs(t *testing.T, mtus map[string]int) {
	t.Helper()
	orig := LinkMTU
	LinkMTU = func(name string) (int, error) {
		mtu, ok := mtus[name]
		if !ok {
			return 0, errors.New("no such link")
		}
		return mtu, nil
	}
	t.Cleanup(func() { LinkMTU = orig })
}

func uplinks(names ...string) func() ([]string, error) {
	return func() ([]string, error) { return names, nil }
}

func TestReconciler_WritesOnlyOnChange(t *testing.T) {
	mtus := map[string]int{testUplink: 1500}
	withLinkMTUs(t, mtus)
	var table fakeTable
	r := NewReconciler(&table, ModeAuto, uplinks(testUplink))

	v, changed, err := r.Reconcile()
	if err != nil || !changed || v != (Values{IPv4: 1420, IPv6: 1400}) {
		t.Fatalf("first Reconcile = %+v, %v, %v; want the 1500 values, changed, no error", v, changed, err)
	}
	if _, changed, _ := r.Reconcile(); changed || len(table.puts) != 1 {
		t.Errorf("second Reconcile with nothing changed: changed=%v, %d puts; want no write", changed, len(table.puts))
	}

	// The uplink's MTU drops, so the clamp has to follow it down.
	mtus[testUplink] = 1496
	v, changed, err = r.Reconcile()
	if err != nil || !changed || v != (Values{IPv4: 1416, IPv6: 1396}) || len(table.puts) != 2 {
		t.Errorf("Reconcile after an MTU change = %+v, %v, %v, %d puts; want the 1496 values written",
			v, changed, err, len(table.puts))
	}
}

// TestReconciler_ErrorLeavesTableAlone is the fail-safe: when the MTU cannot
// be resolved, the map is not touched, so a node that never resolved one
// stays at zero, clamping off, and one that did keeps its last good values.
func TestReconciler_ErrorLeavesTableAlone(t *testing.T) {
	for _, tc := range []struct {
		name    string
		uplinks func() ([]string, error)
	}{
		{"uplinks unresolved", func() ([]string, error) { return nil, errors.New("no default route") }},
		{"no uplinks", uplinks()},
		{"an uplink's MTU unreadable", uplinks(testUplink, "missing0")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withLinkMTUs(t, map[string]int{testUplink: 1500})
			var table fakeTable
			if _, changed, err := NewReconciler(&table, ModeAuto, tc.uplinks).Reconcile(); err == nil || changed {
				t.Errorf("Reconcile = changed %v, err %v; want an error and no change", changed, err)
			}
			if len(table.puts) != 0 {
				t.Errorf("Reconcile wrote %v despite the error, want the table left alone", table.puts)
			}
		})
	}
}

func TestReconciler_KeepsLastGoodValuesOnError(t *testing.T) {
	mtus := map[string]int{testUplink: 1500}
	withLinkMTUs(t, mtus)
	var table fakeTable
	r := NewReconciler(&table, ModeAuto, uplinks(testUplink))
	if _, _, err := r.Reconcile(); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	delete(mtus, testUplink)
	v, changed, err := r.Reconcile()
	if err == nil || changed || v != (Values{IPv4: 1420, IPv6: 1400}) || len(table.puts) != 1 {
		t.Errorf("Reconcile with the uplink gone = %+v, %v, %v, %d puts; want an error and the last good values kept",
			v, changed, err, len(table.puts))
	}
}

// TestReconciler_NonAutoModesIgnoreUplinks checks "off" and a fixed MTU never
// consult the uplinks, so they work on a node whose uplink resolution fails.
func TestReconciler_NonAutoModesIgnoreUplinks(t *testing.T) {
	broken := func() ([]string, error) { return nil, errors.New("must not be called") }
	for override, want := range map[string]Values{ModeOff: Off, "1496": {IPv4: 1416, IPv6: 1396}} {
		var table fakeTable
		v, changed, err := NewReconciler(&table, override, broken).Reconcile()
		if err != nil || !changed || v != want {
			t.Errorf("Reconcile(%q) = %+v, %v, %v; want %+v written", override, v, changed, err, want)
		}
	}
}

func TestReconciler_WriteFailureIsRetried(t *testing.T) {
	withLinkMTUs(t, map[string]int{testUplink: 1500})
	table := fakeTable{err: errors.New("map closed")}
	r := NewReconciler(&table, ModeAuto, uplinks(testUplink))
	if _, _, err := r.Reconcile(); err == nil {
		t.Fatal("Reconcile with a failing write = nil error, want the failure")
	}
	table.err = nil
	if _, changed, err := r.Reconcile(); err != nil || !changed || len(table.puts) != 1 {
		t.Errorf("Reconcile after the write recovers = changed %v, err %v, %d puts; want it written",
			changed, err, len(table.puts))
	}
}
