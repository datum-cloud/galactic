// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package attachmentidentity manages per-interface incarnation tokens used to
// prevent a recycled kernel ifindex from inheriting private-service policy.
package attachmentidentity

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

var randomReader io.Reader = rand.Reader

// Rotate replaces ifindex's identity before a service classifier can run on
// that interface. Zero is reserved for "no identity".
func Rotate(table interface{ Put(key, value any) error }, ifindex uint32) (uint64, error) {
	var raw [8]byte
	for {
		if _, err := io.ReadFull(randomReader, raw[:]); err != nil {
			return 0, fmt.Errorf("attachmentidentity: generate token: %w", err)
		}
		token := binary.LittleEndian.Uint64(raw[:])
		if token == 0 {
			continue
		}
		if err := table.Put(ifindex, token); err != nil {
			return 0, fmt.Errorf("attachmentidentity: rotate ifindex=%d: %w", ifindex, err)
		}
		return token, nil
	}
}

// RotateMap rotates an identity in an already-open kernel map.
func RotateMap(m *ebpf.Map, ifindex uint32) (uint64, error) {
	if m == nil {
		return 0, fmt.Errorf("attachmentidentity: map is nil")
	}
	return Rotate(m, ifindex)
}

// RotatePinned opens the pinned identity map, rotates ifindex, and closes it.
func RotatePinned(pinDir string, ifindex uint32) (uint64, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, prog.UsidMapAttachmentIdentityTable), nil)
	if err != nil {
		return 0, fmt.Errorf("attachmentidentity: open pinned map: %w", err)
	}
	defer func() { _ = m.Close() }()
	return RotateMap(m, ifindex)
}
