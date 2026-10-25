// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"sync"

	"go.datum.net/galactic/internal/plumbing/ebpf/vipxlatmap"
)

// PinnedVIPTranslationTable is a VIPTranslationTable over this node's pinned
// vip_xlat_table that opens the pin on first use. galactic-cni creates the pin,
// so it can be missing when galactic-router starts. Every call that finds the
// table not yet open tries again, and the first successful open is kept until
// Close.
//
// Safe for concurrent use.
type PinnedVIPTranslationTable struct {
	// Open opens the pinned map. Production passes
	// vipxlatmap.OpenPinnedVipXlatTable over attach.PinDir.
	Open func() (*vipxlatmap.VipXlatTable, io.Closer, error)

	mu     sync.Mutex
	table  *vipxlatmap.VipXlatTable
	closer io.Closer
	closed bool
}

// errVIPTranslationTableClosed is what Table returns after Close.
var errVIPTranslationTableClosed = errors.New("vip_xlat_table handle is closed")

// Table returns the open table, opening the pin first if no earlier call has.
func (p *PinnedVIPTranslationTable) Table() (*vipxlatmap.VipXlatTable, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, errVIPTranslationTableClosed
	}
	if p.table != nil {
		return p.table, nil
	}
	table, closer, err := p.Open()
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("vip_xlat_table is not available on this node (eBPF uSID datapath not loaded): %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("vip_xlat_table is not available on this node: %w", err)
	}
	p.table, p.closer = table, closer
	return table, nil
}

// Close closes this process's handle, if one was opened, and makes every later
// call fail rather than open the pin again. The pinned map itself is
// unaffected. Closing twice is a no-op.
func (p *PinnedVIPTranslationTable) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.closer == nil {
		return nil
	}
	err := p.closer.Close()
	p.table, p.closer = nil, nil
	return err
}

// RegisterIngress implements VIPTranslationTable.
func (p *PinnedVIPTranslationTable) RegisterIngress(block uint64, argument, slot uint16, proto uint8,
	vipAddr net.IP, vipPort uint16, backendAddr net.IP, backendPort uint16,
) error {
	t, err := p.Table()
	if err != nil {
		return err
	}
	return t.RegisterIngress(block, argument, slot, proto, vipAddr, vipPort, backendAddr, backendPort)
}

// RegisterEgress implements VIPTranslationTable.
func (p *PinnedVIPTranslationTable) RegisterEgress(block uint64, argument uint16, proto uint8,
	backendAddr net.IP, backendPort uint16, vipAddr net.IP, vipPort uint16,
) error {
	t, err := p.Table()
	if err != nil {
		return err
	}
	return t.RegisterEgress(block, argument, proto, backendAddr, backendPort, vipAddr, vipPort)
}

// UnregisterIngress implements VIPTranslationTable.
func (p *PinnedVIPTranslationTable) UnregisterIngress(block uint64, argument, slot uint16, proto uint8,
	vipAddr net.IP, vipPort uint16,
) error {
	t, err := p.Table()
	if err != nil {
		return err
	}
	return t.UnregisterIngress(block, argument, slot, proto, vipAddr, vipPort)
}

// UnregisterEgress implements VIPTranslationTable.
func (p *PinnedVIPTranslationTable) UnregisterEgress(block uint64, argument uint16, proto uint8,
	backendAddr net.IP, backendPort uint16,
) error {
	t, err := p.Table()
	if err != nil {
		return err
	}
	return t.UnregisterEgress(block, argument, proto, backendAddr, backendPort)
}

// UnregisterEgressTranslated implements VIPTranslationTable.
func (p *PinnedVIPTranslationTable) UnregisterEgressTranslated(block uint64, argument uint16, proto uint8,
	backendAddr net.IP, backendPort uint16,
) error {
	t, err := p.Table()
	if err != nil {
		return err
	}
	return t.UnregisterEgressTranslated(block, argument, proto, backendAddr, backendPort)
}

// UnregisterBinding implements VIPTranslationTable.
func (p *PinnedVIPTranslationTable) UnregisterBinding(slot uint16, proto uint8, vipAddr net.IP, vipPort uint16,
	backendAddr net.IP, backendPort uint16,
) ([]vipxlatmap.Entry, error) {
	t, err := p.Table()
	if err != nil {
		return nil, err
	}
	return t.UnregisterBinding(slot, proto, vipAddr, vipPort, backendAddr, backendPort)
}

// UnregisterBindingAt implements VIPTranslationTable.
func (p *PinnedVIPTranslationTable) UnregisterBindingAt(block uint64, argument, slot uint16, proto uint8,
	vipAddr net.IP, vipPort uint16, backendAddr net.IP, backendPort uint16,
) ([]vipxlatmap.Entry, error) {
	t, err := p.Table()
	if err != nil {
		return nil, err
	}
	return t.UnregisterBindingAt(block, argument, slot, proto, vipAddr, vipPort, backendAddr, backendPort)
}
