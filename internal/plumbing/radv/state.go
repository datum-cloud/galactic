// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package radv

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultStateDir is the well-known parent directory for the node-local
// record of which tap host interfaces currently need periodic Router
// Advertisements — mirrors internal/cni/ipam's DefaultLockDir and
// internal/plumbing/vrf's lockDir: node-local state under /var/lib/cni that
// must survive the process that wrote it exiting. A package-level var (not
// a const, unlike its ipam/vrf counterparts): internal/installer's Run
// reads it directly on every tick with no per-call parameter of its own to
// override instead, so tests substitute a t.TempDir() here the same way
// installer.go's own HostBinDir/HostConflist/etc. are overridden.
var DefaultStateDir = "/var/lib/cni/ra"

// Record is one tap attachment's durable RA state: enough for
// SendRouterAdvertisement to resend on it without anything else being
// available (galactic-tap, the process that has the rest of the
// attachment's context, is long gone by the time this is read).
type Record struct {
	// HostInterface is the tap's host-side interface name (see
	// internal/plumbing/intf.GenerateInterfaceNameHost) — both the file's
	// name under DefaultStateDir and the interface SendRouterAdvertisement
	// is told to use, so it doubles as this record's own key.
	HostInterface string `json:"hostInterface"`
	// MTU is the host interface's MTU at ADD time, advertised via the RA's
	// MTU option so the guest learns the same link MTU the host side has.
	MTU int `json:"mtu"`
}

// RecordAttachment persists a tap attachment's RA state under stateDir,
// keyed by hostInterface, so a long-lived reader (internal/installer's
// resend ticker) can find it after the short-lived galactic-tap process
// that created it has exited. Call on CNI ADD, only for attachments that
// need an RA at all (an IPv6 gateway was allocated) — see
// internal/cnitap's cmdAdd for that gating. Overwrites any existing record
// for the same hostInterface, matching CNI's ADD-retry-is-safe contract.
func RecordAttachment(stateDir, hostInterface string, mtu int) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create radv state dir %q: %w", stateDir, err)
	}

	data, err := json.Marshal(Record{HostInterface: hostInterface, MTU: mtu})
	if err != nil {
		return fmt.Errorf("marshal radv record for %q: %w", hostInterface, err)
	}

	path := filepath.Join(stateDir, hostInterface)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write radv record %q: %w", path, err)
	}

	return nil
}

// RemoveAttachment deletes hostInterface's RA state record from stateDir, if
// any. Call on CNI DEL, unconditionally (mirrors tap.Delete's own
// best-effort, idempotent contract in internal/cnitap's cmdDel) — a missing
// record (no IPv6 gateway was ever allocated for this attachment) is not an
// error.
func RemoveAttachment(stateDir, hostInterface string) error {
	err := os.Remove(filepath.Join(stateDir, hostInterface))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove radv record for %q: %w", hostInterface, err)
	}
	return nil
}

// ListAttachments returns every currently-recorded tap attachment under
// stateDir. A missing stateDir (no tap attachment has ever recorded RA state
// on this node) is not an error — it returns an empty slice, the same as an
// empty directory, since the resend ticker's caller has no useful reaction
// to it beyond "nothing to do this tick" either way.
func ListAttachments(stateDir string) ([]Record, error) {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read radv state dir %q: %w", stateDir, err)
	}

	records := make([]Record, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(stateDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read radv record %q: %w", path, err)
		}

		var record Record
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, fmt.Errorf("parse radv record %q: %w", path, err)
		}
		records = append(records, record)
	}

	return records, nil
}
