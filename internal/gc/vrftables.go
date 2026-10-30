// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gc

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"sync"
	"time"

	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// VRF table ID reservations (see vrf.Reservation) keep a deleted VRF's table
// ID from going to another VPC while node state still references it (#1270).
// This file releases them once nothing does, and removes egress_route_table
// entries keyed by a table no VRF and no reservation holds.

// egressRoutes is the part of the egress_route_table API sweepVRFTableState
// uses; an interface so unprivileged tests can substitute a fake map.
type egressRoutes interface {
	Prefixes() (map[uint32]map[string]struct{}, error)
	Unregister(tableID uint32, prefix *net.IPNet) error
}

// vrfRows lists vrf_table's entries.
type vrfRows interface {
	List() ([]usidmap.VRFEntry, error)
}

// Seams for unprivileged tests, which have no reservation file, lock or pinned
// map.
var (
	vrfReservationsFn  = vrf.ReservationsLocked
	vrfReleaseFn       = vrf.ReleaseLocked
	openEgressRoutesFn = func(pinDir string) (egressRoutes, io.Closer, error) {
		return egressroutemap.OpenPinnedEgressRouteTable(pinDir)
	}
)

// reservationReleaseGrace is how long a reservation stays unreferenced before
// it is released. galactic-router keeps a deleted VPC's route targets mapped
// to its table until its next reconcile, at most 30 seconds later, and
// installs remote routes there meanwhile; releasing sooner could hand those
// to the next VPC given the table.
const reservationReleaseGrace = 2 * time.Minute

// nowFn is the clock the release grace is measured on; a variable for tests.
var nowFn = time.Now

// unreferenced records when each reservation was first seen unreferenced.
// It lives for the process, so a restart only restarts the grace.
var unreferenced = &unreferencedSince{seen: map[vrf.Reservation]time.Time{}}

type unreferencedSince struct {
	mu   sync.Mutex
	seen map[vrf.Reservation]time.Time
}

// elapsed records r as unreferenced at now if it was not already, and reports
// whether it has been for at least grace.
func (u *unreferencedSince) elapsed(r vrf.Reservation, now time.Time, grace time.Duration) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	first, ok := u.seen[r]
	if !ok {
		u.seen[r] = now
		return false
	}
	return now.Sub(first) >= grace
}

// forget drops r, referenced again or released.
func (u *unreferencedSince) forget(r vrf.Reservation) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.seen, r)
}

// referenced reports whether anything on the node still references
// reservation r: its VRF interface, a VRF holding its table, a vrf_table entry
// mapping to its table, or a live BGPVRFInstance naming its VPC. A reservation
// outside the host range counts as referenced, since its owner releases it.
func referenced(r vrf.Reservation, liveNames map[string]struct{}, liveTables, rowTables map[uint32]struct{},
	nodeName string, instNames map[string]struct{}) bool {
	if !hostTable(r.Table) {
		return true
	}
	if _, ok := liveNames[r.Name]; ok {
		return true
	}
	if _, ok := liveTables[r.Table]; ok {
		return true
	}
	if _, ok := rowTables[r.Table]; ok {
		return true
	}
	return vrfNamedByInstance(r.Name, nodeName, instNames)
}

// hostTable reports whether table is in the range host VRFs are allocated
// from. Other ranges belong to the ingress sidecar and the installer's
// sidecar return path, which manage their own tables.
func hostTable(table uint32) bool {
	return table >= vrf.HostTableIDMin && table <= vrf.HostTableIDMax
}

// sweepVRFTableState releases the table ID reservation of every host VRF that
// nothing on the node references any more, and removes the egress_route_table
// entries of every host table no VRF and no reservation holds.
//
// A reservation is released only once its VRF interface is gone, no live
// BGPVRFInstance in instNames names its VPC, and no vrf_table entry maps to
// its table, on sweeps at least reservationReleaseGrace apart. Its
// egress_route_table entries are removed first, so the next VPC given the
// table starts with none of them.
//
// It all runs under the VRF lock, so no CNI ADD creates a VRF or reserves a
// table meanwhile. The CNI and galactic-router write a table's
// egress_route_table entries only once its VRF exists, so a table with no VRF
// and no reservation under the lock has no writer.
func sweepVRFTableState(rows vrfRows, pinDir, nodeName string, instNames map[string]struct{}, result *CleanupResult) {
	err := vrfLockedFn(func() error {
		reservations, err := vrfReservationsFn()
		if err != nil {
			return fmt.Errorf("read VRF table reservations: %w", err)
		}
		links, err := listVRFLinksFn()
		if err != nil {
			return fmt.Errorf("list kernel VRF interfaces: %w", err)
		}
		entries, err := rows.List()
		if err != nil {
			return fmt.Errorf("list eBPF vrf_table: %w", err)
		}
		egress, closer, err := openEgressRoutesFn(pinDir)
		if errors.Is(err, fs.ErrNotExist) {
			return nil // not pinned yet; nothing can be keyed by a table
		}
		if err != nil {
			return fmt.Errorf("open pinned egress_route_table: %w", err)
		}
		defer func() { _ = closer.Close() }()
		byTable, err := egress.Prefixes()
		if err != nil {
			return err
		}

		liveNames := make(map[string]struct{}, len(links))
		liveTables := make(map[uint32]struct{}, len(links))
		for _, l := range links {
			liveNames[l.Name] = struct{}{}
			liveTables[l.Table] = struct{}{}
		}
		rowTables := make(map[uint32]struct{}, len(entries))
		for _, e := range entries {
			rowTables[e.VRFTableID] = struct{}{}
		}

		reserved := make(map[uint32]int, len(reservations))
		for _, r := range reservations {
			reserved[r.Table]++
		}
		now := nowFn()
		for _, r := range reservations {
			if referenced(r, liveNames, liveTables, rowTables, nodeName, instNames) {
				unreferenced.forget(r)
				continue
			}
			if !unreferenced.elapsed(r, now, reservationReleaseGrace) {
				continue
			}
			removed, err := removeEgressTable(egress, r.Table, byTable[r.Table])
			if err != nil {
				slog.Error("GC: failed to remove a released VRF table's egress_route_table entries",
					"vrf", r.Name, "table", r.Table, "err", err)
				result.Errors++
				continue
			}
			delete(byTable, r.Table)
			if removed > 0 {
				result.EgressRouteTablesRemoved++
			}
			if err := vrfReleaseFn(r.Name, r.Table); err != nil {
				slog.Error("GC: failed to release VRF table reservation", "vrf", r.Name, "table", r.Table, "err", err)
				result.Errors++
				continue
			}
			reserved[r.Table]--
			unreferenced.forget(r)
			slog.Info("GC: released VRF table reservation", "vrf", r.Name, "table", r.Table,
				"egressRoutesRemoved", removed)
			result.VRFTableReservationsReleased++
		}

		for table, prefixes := range byTable {
			if !hostTable(table) || reserved[table] > 0 {
				continue
			}
			if _, ok := liveTables[table]; ok {
				continue
			}
			if _, ok := rowTables[table]; ok {
				continue
			}
			removed, err := removeEgressTable(egress, table, prefixes)
			if err != nil {
				slog.Error("GC: failed to remove egress_route_table entries of a table no VRF holds",
					"table", table, "err", err)
				result.Errors++
				continue
			}
			slog.Warn("GC: removed egress_route_table entries of a table no VRF holds",
				"table", table, "removed", removed)
			result.EgressRouteTablesRemoved++
		}
		return nil
	})
	if err != nil {
		slog.Error("GC: failed to sweep VRF table reservations", "err", err)
		result.Errors++
	}
}

// vrfNamedByInstance reports whether a BGPVRFInstance in instNames serves the
// VPC of the VRF interface vrfName on nodeName, in either CRD name form.
func vrfNamedByInstance(vrfName, nodeName string, instNames map[string]struct{}) bool {
	vpc, ok := vpcFromVRFName(vrfName)
	if !ok {
		return false
	}
	for _, key := range vpcKeys(vpc) {
		if _, ok := instNames[key+"-"+nodeName]; ok {
			return true
		}
	}
	return false
}

// removeEgressTable removes table's egress_route_table entries, given by
// prefix, and returns how many it removed.
func removeEgressTable(egress egressRoutes, table uint32, prefixes map[string]struct{}) (int, error) {
	removed := 0
	for p := range prefixes {
		_, prefix, err := net.ParseCIDR(p)
		if err != nil {
			return removed, fmt.Errorf("parse egress_route_table prefix %q: %w", p, err)
		}
		if err := egress.Unregister(table, prefix); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
