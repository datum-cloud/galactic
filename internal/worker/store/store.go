// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package store keeps Worker's desired state durably: one file per claim,
// replaced atomically and synced before a mutating call returns. Programmed
// and observed state are never stored; Worker rebuilds them from the host.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultDir is where Worker keeps desired state on the host.
const DefaultDir = "/var/lib/galactic-worker/claims"

// Withdrawal causes recorded with a releasing claim.
const (
	WithdrawClaim  = "claim"
	WithdrawCaller = "caller"
)

// Record is the durable desired state of one claim.
type Record struct {
	Node          string `json:"node"`
	VPC           string `json:"vpc"`
	AttachmentUID string `json:"attachmentUID"`
	// Owner is the ServiceAccount, "namespace/name", that created the claim.
	Owner string `json:"owner"`
	// Capabilities are the capabilities the owner was allowed when the
	// generation was accepted. Reconciliation programs no destination
	// whose capability is missing from them.
	Capabilities []string `json:"capabilities,omitempty"`
	Generation   uint64   `json:"generation"`
	// SpecHash is the hash of the deterministic encoding of Spec.
	SpecHash string `json:"specHash"`
	// Spec is the claim spec in protobuf JSON.
	Spec json.RawMessage `json:"spec"`
	// Releasing is set once a release, a revocation or a lease expiry is
	// accepted. The record is deleted when read-back confirms that no
	// programmed state of the claim remains.
	Releasing bool `json:"releasing,omitempty"`
	// Withdrawal is the scope of a releasing claim's withdrawal.
	Withdrawal string `json:"withdrawal,omitempty"`
	// WithdrawReason is the reason the claim is being withdrawn.
	WithdrawReason string `json:"withdrawReason,omitempty"`
}

// Store is the durable desired-state store.
type Store interface {
	// Put replaces the record durably.
	Put(r Record) error
	// Delete removes the record durably. A missing record is not an error.
	Delete(node, vpc, attachmentUID string) error
	// List returns every record.
	List() ([]Record, error)
}

// Dir is a Store over a directory.
type Dir struct {
	dir string
}

// Open returns a store over dir, creating it if needed.
func Open(dir string) (*Dir, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create %s: %w", dir, err)
	}
	return &Dir{dir: dir}, nil
}

func (d *Dir) path(node, vpc, att string) string {
	sum := sha256.Sum256([]byte(node + "\x00" + vpc + "\x00" + att))
	return filepath.Join(d.dir, hex.EncodeToString(sum[:])+".json")
}

// Put implements Store.
func (d *Dir) Put(r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("store: encode: %w", err)
	}
	path := d.path(r.Node, r.VPC, r.AttachmentUID)
	tmp, err := os.CreateTemp(d.dir, ".claim-*")
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("store: rename: %w", err)
	}
	return d.syncDir()
}

// Delete implements Store.
func (d *Dir) Delete(node, vpc, att string) error {
	if err := os.Remove(d.path(node, vpc, att)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("store: delete: %w", err)
	}
	return d.syncDir()
}

// List implements Store.
func (d *Dir) List() ([]Record, error) {
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		return nil, fmt.Errorf("store: list: %w", err)
	}
	var out []Record
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(d.dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("store: read %s: %w", e.Name(), err)
		}
		var r Record
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("store: decode %s: %w", e.Name(), err)
		}
		out = append(out, r)
	}
	return out, nil
}

func (d *Dir) syncDir() error {
	f, err := os.Open(d.dir)
	if err != nil {
		return fmt.Errorf("store: open dir: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("store: sync dir: %w", err)
	}
	return nil
}
