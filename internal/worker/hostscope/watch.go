// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package hostscope

import (
	"context"
	"fmt"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.datum.net/galactic/internal/gc"
)

// Watch calls changed with a VPC whenever a link event in the calling
// process's network namespace touches that VPC's host VRF: the VRF itself
// appears or goes, or a link joins, leaves or changes while enslaved to it.
// That is how Worker observes a CNI attachment. It returns once subscribed and
// stops when ctx is done. A lost subscription is reported through errs, after
// which the caller's periodic resync still covers every VPC.
func Watch(ctx context.Context, changed func(vpc string), errs func(error)) error {
	updates := make(chan netlink.LinkUpdate, 256)
	done := make(chan struct{})
	if err := netlink.LinkSubscribeWithOptions(updates, done, netlink.LinkSubscribeOptions{
		ErrorCallback: errs,
	}); err != nil {
		return fmt.Errorf("subscribe to link events: %w", err)
	}
	w := &watcher{vrfs: map[int]string{}, links: map[int]string{}}
	if err := w.seed(); err != nil {
		close(done)
		return err
	}
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case u, ok := <-updates:
				if !ok {
					return
				}
				for _, vpc := range w.update(u) {
					changed(vpc)
				}
			}
		}
	}()
	return nil
}

// watcher maps link events to VPCs. It remembers which VPC each VRF and each
// enslaved link belonged to, so an event for a link that left or was deleted
// still names the VPC it left.
type watcher struct {
	mu sync.Mutex
	// vrfs maps a host VRF's ifindex to its VPC.
	vrfs map[int]string
	// links maps an enslaved link's ifindex to its VRF's VPC.
	links map[int]string
}

func (w *watcher) seed() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links: %w", err)
	}
	for _, l := range links {
		if vpc, ok := gc.VPCFromVRFName(l.Attrs().Name); ok && l.Type() == "vrf" {
			w.vrfs[l.Attrs().Index] = vpc
		}
	}
	for _, l := range links {
		if vpc, ok := w.vrfs[l.Attrs().MasterIndex]; ok {
			w.links[l.Attrs().Index] = vpc
		}
	}
	return nil
}

// update records u and returns the VPCs it touched.
func (w *watcher) update(u netlink.LinkUpdate) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	a := u.Attrs()
	deleted := u.Header.Type == unix.RTM_DELLINK
	var out []string
	if vpc, ok := gc.VPCFromVRFName(a.Name); ok && u.Type() == "vrf" {
		if deleted {
			delete(w.vrfs, a.Index)
		} else {
			w.vrfs[a.Index] = vpc
		}
		return append(out, vpc)
	}
	if prev, ok := w.links[a.Index]; ok {
		out = append(out, prev)
		delete(w.links, a.Index)
	}
	if vpc, ok := w.vrfs[a.MasterIndex]; ok && !deleted {
		w.links[a.Index] = vpc
		if len(out) == 0 || out[0] != vpc {
			out = append(out, vpc)
		}
	}
	return out
}
