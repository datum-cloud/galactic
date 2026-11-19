// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabric

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Watch calls changed with each VPC whose tenant routes an underlay event in
// the calling process's network namespace touches: a main-table route change
// covering one of the VPC's SIDs, or a neighbor change for a next hop its
// entries use. It returns once subscribed and stops when ctx is done. A lost
// subscription is reported through errs; Worker's periodic resync still
// covers every VPC.
func (m *Module) Watch(ctx context.Context, changed func(vpc string), errs func(error)) error {
	routeUpdates := make(chan netlink.RouteUpdate, 256)
	neighUpdates := make(chan netlink.NeighUpdate, 256)
	done := make(chan struct{})
	// Closing the subscriptions once ctx is done fails their reads, which is
	// no error.
	report := errs
	errs = func(err error) {
		if ctx.Err() == nil && report != nil {
			report(err)
		}
	}
	if err := netlink.RouteSubscribeWithOptions(routeUpdates, done, netlink.RouteSubscribeOptions{
		ErrorCallback: errs,
	}); err != nil {
		close(done)
		return fmt.Errorf("subscribe to route events: %w", err)
	}
	if err := netlink.NeighSubscribeWithOptions(neighUpdates, done, netlink.NeighSubscribeOptions{
		ErrorCallback: errs,
	}); err != nil {
		close(done)
		return fmt.Errorf("subscribe to neighbor events: %w", err)
	}
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case u, ok := <-routeUpdates:
				if !ok {
					return
				}
				for _, vpc := range m.routeEvent(u.Route) {
					changed(vpc)
				}
			case u, ok := <-neighUpdates:
				if !ok {
					return
				}
				for _, vpc := range m.neighborEvent(u.Neigh) {
					changed(vpc)
				}
			}
		}
	}()
	return nil
}

// routeEvent returns the VPCs a change to r touches. Only main-table routes
// carry the underlay toward other nodes' locators.
func (m *Module) routeEvent(r netlink.Route) []string {
	if r.Table != 0 && r.Table != unix.RT_TABLE_MAIN {
		return nil
	}
	dst := netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	if r.Dst != nil {
		addr, ok := netip.AddrFromSlice(r.Dst.IP)
		if !ok {
			return nil
		}
		ones, _ := r.Dst.Mask.Size()
		dst = netip.PrefixFrom(addr.Unmap(), ones)
	}
	if !dst.Addr().Is6() {
		return nil
	}
	return m.affectedByRoute(dst)
}

// neighborEvent returns the VPCs whose entries use the neighbor n.
func (m *Module) neighborEvent(n netlink.Neigh) []string {
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return nil
	}
	return m.affectedByNeighbor(n.LinkIndex, addr)
}
