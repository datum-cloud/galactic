// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"log/slog"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/gc"
	"go.datum.net/galactic/internal/plumbing/ebpf/vipxlatmap"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// VIPXlatSweepTable is the part of *vipxlatmap.VipXlatTable VIPXlatSweeper
// drives, so tests can run it against a fake.
type VIPXlatSweepTable interface {
	Generation() uint64
	List() ([]vipxlatmap.Entry, error)
	Reconcile(live map[vipxlatmap.Key]struct{}, cutoff uint64) ([]vipxlatmap.Entry, error)
}

// VIPXlatSweeper removes vip_xlat_table rows that no ServiceVIPBinding on this
// node claims. ServiceVIPBindingReconciler removes a binding's rows when the
// binding is deleted, but nothing else ever does, so without this sweep a row
// stays for good once its owner is gone without that teardown: a finalizer
// cleared by hand, a crash between writing a row and recording the binding, a
// manual write, or a row whose key the current code no longer writes, such as
// the slot-0 ingress rows a router built before #799 left behind.
//
// The live set is every row the node's bindings claim, resolved exactly as the
// reconciler resolves them, so a row is kept whatever value it holds and
// whichever of two conflicting bindings owns it. A binding being deleted still
// counts: its finalizer removes its rows, and the sweep does not race it.
//
// A binding whose VRF context does not resolve right now, such as one whose
// VRF has not reached the node yet or has briefly left it, has no known block
// or argument, so its rows cannot be put in the live set by key. Every row
// shaped like one of its two rows (direction, slot, protocol, address and
// port) is kept instead, under any block and argument. Deleting them would
// only have the reconciler write them back once the VRF resolves, and teardown
// already finds them by value. A binding whose spec does not parse never
// registered a row, so it protects nothing.
//
// Any error building the live set skips the whole pass rather than sweep
// against a partial view.
type VIPXlatSweeper struct {
	Client   client.Client
	NodeName string
	Table    VIPXlatSweepTable
}

// Sweep runs one pass and returns what it removed.
//
// It trusts the API's binding list, not this process's own registrations, so
// it is safe on a fresh process once the informer caches have synced.
// galactic-router still runs it only from the GC ticker, never in the initial
// pass at startup, so the reconciler has had a full interval to re-register
// every live binding before the first sweep, as VipXlatTable.Reconcile asks.
func (s *VIPXlatSweeper) Sweep(ctx context.Context) gc.CleanupResult {
	var result gc.CleanupResult

	// Captured before listing bindings, so a row the reconciler registers
	// for a binding created after the list below survives this pass.
	cutoff := s.Table.Generation()

	live, unresolved, err := s.liveRows(ctx)
	if err != nil {
		slog.Error("GC: failed to build live set for eBPF vip_xlat_table sweep, skipping this tick", "err", err)
		result.Errors++
		return result
	}

	if len(unresolved) > 0 {
		entries, err := s.Table.List()
		if err != nil {
			slog.Error("GC: failed to list eBPF vip_xlat_table for sweep, skipping this tick", "err", err)
			result.Errors++
			return result
		}
		for _, e := range entries {
			for _, rows := range unresolved {
				if rows.shapes(e) {
					live[e.Key] = struct{}{}
					break
				}
			}
		}
	}

	removed, err := s.Table.Reconcile(live, cutoff)
	for _, e := range removed {
		slog.Info("GC: removed stale eBPF vip_xlat_table entry",
			"direction", e.Direction, "block", e.Block, "argument", e.Argument, "slot", e.Slot,
			"proto", e.Proto, "addr", e.Addr, "port", e.Port)
	}
	result.EBPFVIPXlatEntriesRemoved = len(removed)
	if err != nil {
		slog.Error("GC: errors while reconciling eBPF vip_xlat_table", "err", err)
		result.Errors++
	}
	if result.EBPFVIPXlatEntriesRemoved > 0 || result.Errors > 0 {
		slog.Info("eBPF vip_xlat_table GC sweep complete",
			"removed", result.EBPFVIPXlatEntriesRemoved, "errors", result.Errors)
	}
	return result
}

// liveRows returns the keys of every row this node's bindings claim, and the
// rows, without a block or argument, of every binding whose VRF context does
// not resolve.
func (s *VIPXlatSweeper) liveRows(
	ctx context.Context,
) (map[vipxlatmap.Key]struct{}, []vipBindingRows, error) {
	list := &bgpv1alpha1.ServiceVIPBindingList{}
	if err := s.Client.List(ctx, list); err != nil {
		return nil, nil, err
	}

	live := make(map[vipxlatmap.Key]struct{})
	var unresolved []vipBindingRows
	indexes := make(map[string]*backendSIDIndex)
	for i := range list.Items {
		b := &list.Items[i]
		if b.Spec.TargetRef.Name != s.NodeName {
			continue
		}
		rows, err := parseVIPBindingRows(b)
		if err != nil {
			continue // never registered a row
		}
		idx, ok := indexes[b.Namespace]
		if !ok {
			if idx, err = buildBackendSIDIndex(ctx, s.Client, b.Namespace); err != nil {
				return nil, nil, err
			}
			indexes[b.Namespace] = idx
		}
		block, argument, err := resolveVIPBindingContextFromIndex(idx, s.NodeName, b.Spec.VPCRef)
		if err != nil {
			slog.Debug("GC: ServiceVIPBinding does not resolve; keeping every vip_xlat_table row shaped like its own",
				"binding", client.ObjectKeyFromObject(b), "reason", err.Error())
			unresolved = append(unresolved, rows)
			continue
		}
		rows = rows.at(block, argument)
		live[rows.ingress.key()] = struct{}{}
		live[rows.egress.key()] = struct{}{}
	}
	return live, unresolved, nil
}

// key returns the vip_xlat_table key r is written under.
func (r vipRow) key() vipxlatmap.Key {
	return vipxlatmap.Key{
		Block: r.block, Argument: r.argument, Slot: r.slot, Proto: r.proto, Addr: r.addr, Port: r.port,
	}
}

// shapes reports whether e has the direction, slot, protocol, address and port
// of one of rows' two rows, under any block and argument.
func (rows vipBindingRows) shapes(e vipxlatmap.Entry) bool {
	var row vipRow
	switch e.Direction {
	case vipxlatmap.DirectionIngress:
		row = rows.ingress
	case vipxlatmap.DirectionEgress:
		row = rows.egress
	default:
		return false
	}
	return e.Slot == row.slot && e.Proto == row.proto && e.Addr == row.addr && e.Port == row.port
}
