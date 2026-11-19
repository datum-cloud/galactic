// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package local

import (
	"context"
	"fmt"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/gc"
	"go.datum.net/galactic/internal/plumbing/intf"
)

// Watch requeues the VPCs a link or neighbor event touches, beyond the
// events hostscope.Watch already maps to VPCs (a link joining, leaving or
// changing in a VPC's VRF):
//
//   - a Local link outside any VRF, such as a pair's NAT end gaining or
//     losing the client's XDP program, requeues its VPC;
//   - any other link outside a VRF, such as a receiving device or its bond or
//     VLAN, requeues every VPC with a local.tap claim;
//   - a neighbor event on a VPC's tenant interface requeues that VPC while
//     one of its destinations waits on a failed neighbor.
//
// It returns once subscribed and stops when ctx is done. A lost subscription
// is reported through errs; the periodic resync still covers every VPC.
func (m *Module) Watch(ctx context.Context, changed func(vpc string), errs func(error)) error {
	links := make(chan netlink.LinkUpdate, 256)
	neighs := make(chan netlink.NeighUpdate, 256)
	done := make(chan struct{})
	if err := netlink.LinkSubscribeWithOptions(links, done,
		netlink.LinkSubscribeOptions{ErrorCallback: errs}); err != nil {
		return fmt.Errorf("local: subscribe to link events: %w", err)
	}
	if err := netlink.NeighSubscribeWithOptions(neighs, done,
		netlink.NeighSubscribeOptions{ErrorCallback: errs}); err != nil {
		close(done)
		return fmt.Errorf("local: subscribe to neighbor events: %w", err)
	}
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case u, ok := <-links:
				if !ok {
					return
				}
				for _, vpc := range m.linkEvent(u) {
					changed(vpc)
				}
			case u, ok := <-neighs:
				if !ok {
					return
				}
				for _, vpc := range m.neighEvent(u) {
					changed(vpc)
				}
			}
		}
	}()
	return nil
}

// linkEvent returns the VPCs a link event touches.
func (m *Module) linkEvent(u netlink.LinkUpdate) []string {
	a := u.Attrs()
	if v, _, ok := parseAlias(a.Alias); ok && intf.IsLocalLinkName(a.Name) {
		return []string{v}
	}
	if a.MasterIndex != 0 && u.Header.Type != unix.RTM_DELLINK {
		// Enslaved to a VRF (hostscope.Watch) or a bond, whose own event
		// follows.
		if master, err := netlink.LinkByIndex(a.MasterIndex); err == nil && master.Type() == linkVRF {
			return nil
		}
	}
	if u.Type() == linkVRF || u.Type() == linkTunTap {
		return nil
	}
	return m.tapVPCs()
}

// neighEvent returns the VPCs a neighbor event touches.
func (m *Module) neighEvent(u netlink.NeighUpdate) []string {
	waiting := m.neighborVPCs()
	if len(waiting) == 0 {
		return nil
	}
	l, err := netlink.LinkByIndex(u.LinkIndex)
	if err != nil || l.Attrs().MasterIndex == 0 {
		return nil
	}
	master, err := netlink.LinkByIndex(l.Attrs().MasterIndex)
	if err != nil {
		return nil
	}
	vpc, ok := gc.VPCFromVRFName(master.Attrs().Name)
	if !ok {
		return nil
	}
	for _, w := range waiting {
		if w == vpc {
			return []string{vpc}
		}
	}
	return nil
}
