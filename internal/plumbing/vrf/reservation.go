// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package vrf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
)

// Table ID reservations keep a VPC's routing table ID stable on a node.
//
// State keyed by table ID outlives the VRF that owned it: vrf_table rows,
// egress_route_table rows, and galactic-router's cached table ID. Allocating
// only from live VRF links hands a freed ID to the next VPC created, which then
// inherits that state and receives the first VPC's traffic and routes (#1270).
// A reservation keeps the ID for its VRF until garbage collection has confirmed
// nothing still references it and released it, so a VRF recreated meanwhile
// gets its own ID back and no other VPC can be given it.
//
// Reservations are keyed by VRF interface name and are only meaningful inside
// the table ID range the caller allocates from. The host and the ingress
// sidecar allocate from disjoint ranges, so one VPC can hold a reservation in
// each without either seeing the other's.

// reservationsFileName names the reservation file, kept beside the lock that
// serializes every change to it.
const reservationsFileName = "tables.json"

// reservationsVersion is the file format version written to the file.
const reservationsVersion = 1

// reservationsDir is the directory holding the reservation file; a variable
// so unprivileged tests can use a temporary directory.
var reservationsDir = lockDir

// listVRFLinksFn lists the VRF links in this network namespace; a variable so
// unprivileged tests can substitute fabricated links.
var listVRFLinksFn = ListVRFLinks

// Reservation records the routing table ID reserved for the VRF interface
// Name on this node.
type Reservation struct {
	Name  string `json:"name"`
	Table uint32 `json:"table"`
}

type reservationFile struct {
	Version int           `json:"version"`
	Tables  []Reservation `json:"tables"`
}

// ReservationsLocked returns the node's table ID reservations. The caller
// holds the lock (see Locked) when it acts on the result, so that no Add can
// change it meanwhile.
//
// A missing or unreadable file is rebuilt from the VRF links that exist, so a
// node upgraded from a version without reservations, or whose file was lost,
// still reserves the table of every VRF it has.
func ReservationsLocked() ([]Reservation, error) {
	return loadReservations()
}

// ReservedTables returns every reserved table ID. It does not take the lock:
// the file is replaced atomically, so it reads either the old or the new set.
// A sweep that removes state for unreserved tables reads it before and after
// its scan, so a table reserved during the scan is never treated as orphaned.
func ReservedTables() (map[uint32]struct{}, error) {
	res, err := loadReservations()
	if err != nil {
		return nil, err
	}
	tables := make(map[uint32]struct{}, len(res))
	for _, r := range res {
		tables[r.Table] = struct{}{}
	}
	return tables, nil
}

// ReleaseLocked removes the reservation of table for the VRF interface name.
// The caller holds the lock (see Locked) and has confirmed that nothing on the
// node still references the table. Releasing a reservation that does not
// exist is not an error.
func ReleaseLocked(name string, table uint32) error {
	res, err := loadReservations()
	if err != nil {
		return err
	}
	kept, changed := releaseTable(res, name, table)
	if !changed {
		return nil
	}
	return saveReservations(kept)
}

// releaseNameLocked removes every reservation of the VRF interface name in
// [minID, maxID]. The caller holds the lock.
func releaseNameLocked(name string, minID, maxID uint32) error {
	res, err := loadReservations()
	if err != nil {
		return err
	}
	kept := make([]Reservation, 0, len(res))
	for _, r := range res {
		if r.Name == name && r.Table >= minID && r.Table <= maxID {
			continue
		}
		kept = append(kept, r)
	}
	if len(kept) == len(res) {
		return nil
	}
	return saveReservations(kept)
}

// loadReservations reads the reservation file, rebuilding it from the VRF
// links that exist when it is missing or unreadable. A rebuilt set is not
// written back here; the next change writes it.
func loadReservations() ([]Reservation, error) {
	path := filepath.Join(reservationsDir, reservationsFileName)
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return seedReservations()
	case err != nil:
		return nil, fmt.Errorf("read VRF table reservations %q: %w", path, err)
	}
	var file reservationFile
	if err := json.Unmarshal(data, &file); err != nil || file.Version != reservationsVersion {
		slog.Warn("vrf: table ID reservations unreadable, rebuilding them from the VRFs on this node",
			"path", path, "version", file.Version, "err", err)
		return seedReservations()
	}
	return file.Tables, nil
}

// seedReservations reserves the table of every VRF link that exists.
func seedReservations() ([]Reservation, error) {
	links, err := listVRFLinksFn()
	if err != nil {
		return nil, fmt.Errorf("list VRF links to rebuild table ID reservations: %w", err)
	}
	res := make([]Reservation, 0, len(links))
	for _, l := range links {
		res = append(res, Reservation{Name: l.Name, Table: l.Table})
	}
	return res, nil
}

// saveReservations writes res, replacing the file atomically so a reader
// without the lock never sees a partial write.
func saveReservations(res []Reservation) error {
	if err := os.MkdirAll(reservationsDir, 0o700); err != nil {
		return fmt.Errorf("create VRF table reservation dir %q: %w", reservationsDir, err)
	}
	sorted := append([]Reservation{}, res...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Table != sorted[j].Table {
			return sorted[i].Table < sorted[j].Table
		}
		return sorted[i].Name < sorted[j].Name
	})
	data, err := json.Marshal(reservationFile{Version: reservationsVersion, Tables: sorted})
	if err != nil {
		return fmt.Errorf("encode VRF table reservations: %w", err)
	}

	tmp, err := os.CreateTemp(reservationsDir, reservationsFileName+".*")
	if err != nil {
		return fmt.Errorf("write VRF table reservations: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write VRF table reservations: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync VRF table reservations: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write VRF table reservations: %w", err)
	}
	path := filepath.Join(reservationsDir, reservationsFileName)
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace VRF table reservations %q: %w", path, err)
	}
	return nil
}

// reserveTable returns the table ID in [minID, maxID] for a new VRF named
// name, and res with that reservation recorded. live maps the table of every
// VRF link that exists to its name.
//
// name's own reservation in the range is reused unless another live VRF holds
// that table, which happens only when reservations were rebuilt after being
// lost. Otherwise the lowest ID that neither a live VRF nor any reservation
// holds is reserved.
func reserveTable(res []Reservation, live map[uint32]string, name string, minID, maxID uint32) (
	uint32, []Reservation, error,
) {
	used := make(map[uint32]struct{}, len(res)+len(live))
	for table := range live {
		used[table] = struct{}{}
	}
	kept := make([]Reservation, 0, len(res)+1)
	for _, r := range res {
		if r.Name == name && r.Table >= minID && r.Table <= maxID {
			if owner, ok := live[r.Table]; !ok || owner == name {
				return r.Table, res, nil
			}
			slog.Warn("vrf: reserved table ID is held by another VRF, allocating a new one",
				"vrf", name, "table", r.Table, "holder", live[r.Table])
			continue
		}
		kept = append(kept, r)
		used[r.Table] = struct{}{}
	}
	table, err := nextFreeTableID(used, minID, maxID)
	if err != nil {
		return 0, res, err
	}
	return table, append(kept, Reservation{Name: name, Table: table}), nil
}

// recordTable returns res with table recorded as name's reservation, for a
// VRF that already exists, and whether that changed res. The live link is the
// truth: name's other reservations in [minID, maxID], and any other name's
// reservation of table, are dropped.
func recordTable(res []Reservation, name string, table, minID, maxID uint32) ([]Reservation, bool) {
	kept := make([]Reservation, 0, len(res)+1)
	found, changed := false, false
	for _, r := range res {
		switch {
		case r.Name == name && r.Table == table:
			found = true
			kept = append(kept, r)
		case r.Name == name && r.Table >= minID && r.Table <= maxID,
			r.Name != name && r.Table == table:
			changed = true
		default:
			kept = append(kept, r)
		}
	}
	if !found {
		kept = append(kept, Reservation{Name: name, Table: table})
		changed = true
	}
	return kept, changed
}

// releaseTable returns res without name's reservation of table, and whether
// it held one.
func releaseTable(res []Reservation, name string, table uint32) ([]Reservation, bool) {
	kept := make([]Reservation, 0, len(res))
	for _, r := range res {
		if r.Name == name && r.Table == table {
			continue
		}
		kept = append(kept, r)
	}
	return kept, len(kept) != len(res)
}
