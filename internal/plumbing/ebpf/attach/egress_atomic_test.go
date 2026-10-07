// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

func TestAttachEgressFailureAtomicOrdering(t *testing.T) {
	oldPriority := filterPriorityFn
	oldSnapshot := snapshotEgressChainFn
	oldRestore := restoreEgressChainFn
	oldAttach := attachOneAtPriorityFn
	oldLock := withInterfaceLockFn
	oldValidate := validateEgressTargetSlotsFn
	t.Cleanup(func() {
		filterPriorityFn = oldPriority
		snapshotEgressChainFn = oldSnapshot
		restoreEgressChainFn = oldRestore
		attachOneAtPriorityFn = oldAttach
		withInterfaceLockFn = oldLock
		validateEgressTargetSlotsFn = oldValidate
	})
	// Plain AttachEgress is used by an unprivileged sidecar that cannot open
	// the host-shared flock directory. It must remain process-local.
	withInterfaceLockFn = func(string, func() error) error { return errors.New("cross-process lock unavailable") }
	validateEgressTargetSlotsFn = func(string, uint16) error { return nil }
	filterPriorityFn = func() uint16 { return 7 }
	service, legacy := &ebpf.Program{}, &ebpf.Program{}

	t.Run("snapshot failure mutates nothing", func(t *testing.T) {
		wantErr := errors.New("snapshot failed")
		snapshotEgressChainFn = func(string, uint16) (*egressChainSnapshot, error) { return nil, wantErr }
		var calls []string
		attachOneAtPriorityFn = func(_ *ebpf.Program, name, _ string, _ uint32, _ uint16, _ uint32) error {
			calls = append(calls, name)
			return nil
		}
		if err := AttachEgress(service, legacy, "tenant0"); !errors.Is(err, wantErr) {
			t.Fatalf("error = %v, want %v", err, wantErr)
		}
		if len(calls) != 0 {
			t.Fatalf("attach calls = %v, want none", calls)
		}
	})

	t.Run("continuation failure restores snapshot", func(t *testing.T) {
		snapshotEgressChainFn = func(string, uint16) (*egressChainSnapshot, error) { return &egressChainSnapshot{}, nil }
		wantErr := errors.New("continuation failed")
		var calls []string
		attachOneAtPriorityFn = func(_ *ebpf.Program, name, _ string, _ uint32, _ uint16, _ uint32) error {
			calls = append(calls, name)
			return wantErr
		}
		restored := false
		restoreEgressChainFn = func(*egressChainSnapshot, string) error { restored = true; return nil }
		if err := AttachEgress(service, legacy, "tenant0"); !errors.Is(err, wantErr) {
			t.Fatalf("error = %v, want %v", err, wantErr)
		}
		if !reflect.DeepEqual(calls, []string{egressFilterName}) {
			t.Fatalf("attach calls = %v", calls)
		}
		if !restored {
			t.Fatal("prior chain was not restored")
		}
	})

	t.Run("classifier failure restores snapshot", func(t *testing.T) {
		snapshot := &egressChainSnapshot{}
		snapshotEgressChainFn = func(string, uint16) (*egressChainSnapshot, error) { return snapshot, nil }
		wantErr := errors.New("classifier failed")
		var calls []string
		attachOneAtPriorityFn = func(_ *ebpf.Program, name, _ string, _ uint32, priority uint16, _ uint32) error {
			calls = append(calls, name)
			if name == serviceEgressFilterName {
				return wantErr
			}
			if priority != 8 {
				t.Fatalf("continuation priority = %d, want 8", priority)
			}
			return nil
		}
		restored := false
		restoreEgressChainFn = func(got *egressChainSnapshot, iface string) error {
			restored = got == snapshot && iface == "tenant0"
			return nil
		}
		if err := AttachEgress(service, legacy, "tenant0"); !errors.Is(err, wantErr) {
			t.Fatalf("error = %v, want %v", err, wantErr)
		}
		if !reflect.DeepEqual(calls, []string{egressFilterName, serviceEgressFilterName}) {
			t.Fatalf("attach calls = %v, want continuation then classifier", calls)
		}
		if !restored {
			t.Fatal("prior chain was not restored")
		}
	})
}

func TestSnapshotEgressChainRefusesForeignTargetSlot(t *testing.T) {
	oldLinkByName := linkByNameFn
	oldFilterList := filterListFn
	t.Cleanup(func() {
		linkByNameFn = oldLinkByName
		filterListFn = oldFilterList
	})
	linkByNameFn = func(string) (netlink.Link, error) { return &netlink.Dummy{}, nil }
	filters := []netlink.Filter{
		bpfFilter("another-cni", 7, netlink.MakeHandle(0, 1)),
		bpfFilter("unrelated-elsewhere", 20, netlink.MakeHandle(0, 9)),
	}
	filterListFn = func(netlink.Link, uint32) ([]netlink.Filter, error) {
		return filters, nil
	}
	if _, err := snapshotEgressChain("tenant0", 7); err == nil {
		t.Fatal("snapshot accepted a foreign filter in the classifier target slot")
	}

	filters = []netlink.Filter{
		bpfFilter("unrelated-elsewhere", 20, netlink.MakeHandle(0, 9)),
	}
	filterListFn = func(netlink.Link, uint32) ([]netlink.Filter, error) {
		return filters, nil
	}
	if _, err := snapshotEgressChain("tenant0", 7); err != nil {
		t.Fatalf("snapshot rejected unrelated filter outside target slots: %v", err)
	}
}

func TestEgressChainSnapshotRestoreRemovesOnlyNewSlots(t *testing.T) {
	oldAttach := attachOneAtPriorityFn
	oldLinkByName := linkByNameFn
	oldFilterList := filterListFn
	oldFilterDelete := filterDeleteFn
	t.Cleanup(func() {
		attachOneAtPriorityFn = oldAttach
		linkByNameFn = oldLinkByName
		filterListFn = oldFilterList
		filterDeleteFn = oldFilterDelete
	})

	tests := []struct {
		name     string
		snapshot []egressFilterSnapshot
		current  []netlink.Filter
		wantPut  []string
		wantDel  []uint16
	}{
		{
			name: "legacy-only migration",
			snapshot: []egressFilterSnapshot{{
				program: &ebpf.Program{}, name: egressFilterName, priority: 7, handle: netlink.MakeHandle(0, 1),
			}},
			current: []netlink.Filter{
				bpfFilter(egressFilterName, 7, netlink.MakeHandle(0, 1)),
				bpfFilter(egressFilterName, 8, netlink.MakeHandle(0, 2)),
			},
			wantPut: []string{egressFilterName},
			wantDel: []uint16{8},
		},
		{
			name: "existing two-program chain",
			snapshot: []egressFilterSnapshot{
				{program: &ebpf.Program{}, name: serviceEgressFilterName, priority: 7, handle: netlink.MakeHandle(0, 1)},
				{program: &ebpf.Program{}, name: egressFilterName, priority: 8, handle: netlink.MakeHandle(0, 2)},
			},
			current: []netlink.Filter{
				bpfFilter(serviceEgressFilterName, 7, netlink.MakeHandle(0, 1)),
				bpfFilter(egressFilterName, 8, netlink.MakeHandle(0, 2)),
			},
			wantPut: []string{serviceEgressFilterName, egressFilterName},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var put []string
			var deleted []uint16
			attachOneAtPriorityFn = func(_ *ebpf.Program, name, _ string, _ uint32, _ uint16, _ uint32) error {
				put = append(put, name)
				return nil
			}
			linkByNameFn = func(string) (netlink.Link, error) { return &netlink.Dummy{}, nil }
			filterListFn = func(netlink.Link, uint32) ([]netlink.Filter, error) { return tt.current, nil }
			filterDeleteFn = func(filter netlink.Filter) error {
				deleted = append(deleted, filter.(*netlink.BpfFilter).Priority)
				return nil
			}

			snapshot := &egressChainSnapshot{filters: tt.snapshot}
			if err := snapshot.restore("tenant0"); err != nil {
				t.Fatalf("restore: %v", err)
			}
			if !reflect.DeepEqual(put, tt.wantPut) {
				t.Errorf("restored filters = %v, want %v", put, tt.wantPut)
			}
			if !reflect.DeepEqual(deleted, tt.wantDel) {
				t.Errorf("deleted filters = %v, want %v", deleted, tt.wantDel)
			}
		})
	}
}

func bpfFilter(name string, priority uint16, handle uint32) *netlink.BpfFilter {
	return &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{Priority: priority, Handle: handle},
		Name:        name,
	}
}
