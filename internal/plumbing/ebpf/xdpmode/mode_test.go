// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xdpmode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink/nl"
)

// Interface names the fixtures reuse.
const (
	testNIC1 = "eno1"
	testNIC2 = "eno2"
)

// fakeSysfs builds a /sys/class/net look-alike under a temp dir and points
// sysClassNet at it. Each physical interface gets a device link whose driver
// link ends in its driver's name, the way sysfs lays out a PCI NIC; each
// virtual one gets a directory and nothing else.
type fakeSysfs struct {
	t    *testing.T
	root string
}

func newFakeSysfs(t *testing.T) *fakeSysfs {
	t.Helper()
	root := t.TempDir()
	net := filepath.Join(root, "class", "net")
	if err := os.MkdirAll(net, 0o755); err != nil {
		t.Fatal(err)
	}
	old := sysClassNet
	sysClassNet = net
	t.Cleanup(func() { sysClassNet = old })
	return &fakeSysfs{t: t, root: root}
}

func (f *fakeSysfs) physical(name, driver string) {
	f.t.Helper()
	dev := filepath.Join(f.root, "devices", name)
	drv := filepath.Join(f.root, "bus", "pci", "drivers", driver)
	for _, dir := range []string{dev, drv, filepath.Join(sysClassNet, name)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			f.t.Fatal(err)
		}
	}
	if err := os.Symlink(drv, filepath.Join(dev, "driver")); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(dev, filepath.Join(sysClassNet, name, "device")); err != nil {
		f.t.Fatal(err)
	}
}

// unbound adds a physical interface whose device has no driver link, which
// Select must report rather than treat as virtual.
func (f *fakeSysfs) unbound(name string) {
	f.t.Helper()
	dev := filepath.Join(f.root, "devices", name)
	if err := os.MkdirAll(dev, 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sysClassNet, name), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(dev, filepath.Join(sysClassNet, name, "device")); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeSysfs) virtual(name string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Join(sysClassNet, name), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

// file adds a regular file, the way the bonding driver adds bonding_masters
// beside the interfaces.
func (f *fakeSysfs) file(name string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(sysClassNet, name), []byte("bond0 bond1\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func TestSelect(t *testing.T) {
	tests := []struct {
		name       string
		build      func(f *fakeSysfs)
		required   []string
		want       Mode
		wantReason string
	}{
		{
			name: "no bnxt_en keeps native",
			build: func(f *fakeSysfs) {
				f.physical(testNIC1, "igb")
				f.physical(testNIC2, "ice")
				f.virtual("lo")
				f.virtual("bond0")
				f.file("bonding_masters")
			},
			required: []string{testNIC1, testNIC2},
			want:     Native,
		},
		{
			name: "all bnxt_en selects generic",
			build: func(f *fakeSysfs) {
				f.physical("ens3", "bnxt_en")
				f.physical("ens7", "bnxt_en")
				f.virtual("bond1")
				f.file("bonding_masters")
			},
			required:   []string{"ens3", "ens7"},
			want:       Generic,
			wantReason: "ens3=bnxt_en, ens7=bnxt_en",
		},
		{
			name: "one bnxt_en NIC among others selects generic for the whole host",
			build: func(f *fakeSysfs) {
				f.physical(testNIC1, "igb")
				f.physical("ens3", "bnxt_en")
			},
			required:   []string{testNIC1},
			want:       Generic,
			wantReason: "ens3=bnxt_en",
		},
		{
			name: "virtual targets follow the host's NICs",
			build: func(f *fakeSysfs) {
				f.physical("ens3", "bnxt_en")
				f.virtual("veth-return")
			},
			required: []string{"veth-return"},
			want:     Generic,
		},
		{
			name: "a host of virtual interfaces only stays native",
			build: func(f *fakeSysfs) {
				f.virtual("lo")
				f.virtual("eth0")
			},
			required: []string{"eth0"},
			want:     Native,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeSysfs(t)
			tt.build(f)
			got, err := Select(tt.required...)
			if err != nil {
				t.Fatalf("Select: %v", err)
			}
			if got.Mode != tt.want {
				t.Errorf("Mode = %s, want %s (reason %q)", got.Mode, tt.want, got.Reason)
			}
			if !strings.Contains(got.Reason, tt.wantReason) {
				t.Errorf("Reason = %q, want it to name %q", got.Reason, tt.wantReason)
			}
		})
	}
}

func TestSelect_ReportsWhatItCannotDecideOn(t *testing.T) {
	tests := []struct {
		name     string
		build    func(f *fakeSysfs)
		required []string
		wantErr  []string
	}{
		{
			name:     "a missing target interface",
			build:    func(f *fakeSysfs) { f.physical(testNIC1, "igb") },
			required: []string{testNIC1, "eno9"},
			wantErr:  []string{"interface eno9 does not exist"},
		},
		{
			name: "a target NIC whose driver cannot be read",
			build: func(f *fakeSysfs) {
				f.physical(testNIC1, "igb")
				f.unbound(testNIC2)
			},
			required: []string{testNIC1, testNIC2},
			wantErr:  []string{"read driver of eno2"},
		},
		{
			name: "both at once",
			build: func(f *fakeSysfs) {
				f.physical("ens3", "bnxt_en")
				f.unbound(testNIC2)
			},
			required: []string{testNIC2, "bond9"},
			wantErr:  []string{"read driver of eno2", "interface bond9 does not exist"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeSysfs(t)
			tt.build(f)
			_, err := Select(tt.required...)
			if err == nil {
				t.Fatal("Select: want an error")
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

func TestSelect_UnreadableSysfs(t *testing.T) {
	old := sysClassNet
	sysClassNet = filepath.Join(t.TempDir(), "missing")
	t.Cleanup(func() { sysClassNet = old })
	if _, err := Select(); err == nil {
		t.Fatal("Select over a missing sysfs: want an error")
	}
}

func TestModeFlagsAndAttachMode(t *testing.T) {
	if got := Native.AttachFlags(); got != link.XDPDriverMode {
		t.Errorf("Native.AttachFlags() = %v, want XDPDriverMode", got)
	}
	if got := Generic.AttachFlags(); got != link.XDPGenericMode {
		t.Errorf("Generic.AttachFlags() = %v, want XDPGenericMode", got)
	}
	for _, tt := range []struct {
		attachMode uint32
		mode       Mode
		ok         bool
	}{
		{nl.XDP_ATTACHED_DRV, Native, true},
		{nl.XDP_ATTACHED_SKB, Generic, true},
		{nl.XDP_ATTACHED_NONE, 0, false},
		{nl.XDP_ATTACHED_HW, 0, false},
	} {
		mode, ok := FromAttachMode(tt.attachMode)
		if ok != tt.ok || (ok && mode != tt.mode) {
			t.Errorf("FromAttachMode(%d) = %s, %v; want %s, %v", tt.attachMode, mode, ok, tt.mode, tt.ok)
		}
		if ok && !tt.mode.Matches(tt.attachMode) {
			t.Errorf("%s.Matches(%d) = false", tt.mode, tt.attachMode)
		}
	}
	if Native.Matches(nl.XDP_ATTACHED_SKB) || Generic.Matches(nl.XDP_ATTACHED_DRV) {
		t.Error("a mode matched the other mode's attach value")
	}
	if Native.String() != "native" || Generic.String() != "generic" {
		t.Errorf("String() = %q, %q", Native, Generic)
	}
}

// TestSelect_SkipsANonTargetNICWithNoDriver covers a NIC caught mid-unbind
// that the datapath does not attach to: it carries no driver traffic, so it
// is listed as skipped rather than failing startup, and the rest decide.
func TestSelect_SkipsANonTargetNICWithNoDriver(t *testing.T) {
	f := newFakeSysfs(t)
	f.physical("ens3", "bnxt_en")
	f.unbound(testNIC2)

	got, err := Select("ens3")
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got.Mode != Generic {
		t.Errorf("Mode = %s, want generic", got.Mode)
	}
	if len(got.Skipped) != 1 || !strings.Contains(got.Skipped[0], "read driver of eno2") {
		t.Errorf("Skipped = %v, want eno2 named", got.Skipped)
	}
}
