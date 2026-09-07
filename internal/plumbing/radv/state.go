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

// DefaultStateDir is the node-local parent directory recording which tap host
// interfaces currently need periodic Router Advertisements: state that must
// survive the process that wrote it exiting.
//
// A var rather than a const, unlike its counterparts elsewhere, because the
// daemon reads it directly on every tick with no per-call parameter to override
// instead, so tests substitute a temporary directory here.
var DefaultStateDir = "/var/lib/cni/ra"

// Record is one tap attachment's durable advertisement state: enough to resend
// on it with nothing else available, the process holding the rest of the
// attachment's context being long gone by the time this is read.
type Record struct {
	// HostInterface is the tap's host-side interface name. It is both the
	// record's filename and the interface to send on, so it doubles as this
	// record's key.
	HostInterface string `json:"hostInterface"`
	// MTU is the host interface's MTU at ADD time, advertised via the RA's
	// MTU option so the guest learns the same link MTU the host side has.
	MTU int `json:"mtu"`
}

// RecordAttachment persists a tap attachment's advertisement state under
// stateDir, keyed by hostInterface, so the long-lived resend ticker can find it
// after the short-lived plugin process that created it has exited.
//
// Call it on ADD, only for attachments that need an advertisement at all, that
// is, ones with an IPv6 gateway allocated. It overwrites any existing record for
// the same interface, matching the ADD-retry-is-safe contract.
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

// RemoveAttachment deletes hostInterface's record from stateDir, if any. Call it
// on DEL unconditionally: a missing record, from an attachment that never had an
// IPv6 gateway, is not an error.
func RemoveAttachment(stateDir, hostInterface string) error {
	err := os.Remove(filepath.Join(stateDir, hostInterface))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove radv record for %q: %w", hostInterface, err)
	}
	return nil
}

// ListAttachments returns every recorded tap attachment under stateDir. A
// missing directory, meaning no attachment has ever recorded state on this node,
// returns an empty slice rather than an error, the caller having no useful
// reaction beyond "nothing to do this tick" either way.
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
