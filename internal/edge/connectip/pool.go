// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

var errPoolExhausted = errors.New("address pool exhausted")

// addressPool hands out single IPv6 addresses from a prefix.
type addressPool struct {
	prefix netip.Prefix

	mu    sync.Mutex
	inUse map[netip.Addr]struct{}
}

// newAddressPool returns a pool over prefix, which must be a masked IPv6
// prefix no longer than /127. The prefix's first address is never handed out.
func newAddressPool(prefix netip.Prefix) (*addressPool, error) {
	if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return nil, fmt.Errorf("pool %s is not an IPv6 prefix", prefix)
	}
	if prefix != prefix.Masked() {
		return nil, fmt.Errorf("pool %s has host bits set", prefix)
	}
	if prefix.Bits() > 127 {
		return nil, fmt.Errorf("pool %s has no assignable addresses", prefix)
	}
	return &addressPool{prefix: prefix, inUse: map[netip.Addr]struct{}{}}, nil
}

// allocate returns the lowest free address after the prefix's first address,
// or errPoolExhausted.
func (p *addressPool) allocate() (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for a := p.prefix.Addr().Next(); a.IsValid() && p.prefix.Contains(a); a = a.Next() {
		if _, taken := p.inUse[a]; !taken {
			p.inUse[a] = struct{}{}
			return a, nil
		}
	}
	return netip.Addr{}, errPoolExhausted
}

// release returns addr to the pool.
func (p *addressPool) release(addr netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.inUse, addr)
}
