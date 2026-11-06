// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"time"

	"github.com/vishvananda/netlink"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// linkWatch reports the name of every interface added, changed or removed on
// the node to changed until the manager stops, resubscribing after a netlink
// error. The producer health controller uses it to probe a replaced producer
// afresh as soon as its interface is recreated, and the traffic policy
// controller to publish a new interface's policy as soon as it comes up.
func linkWatch(changed func(name string)) manager.Runnable {
	return manager.RunnableFunc(func(ctx context.Context) error {
		log := ctrl.Log.WithName("interface-watch")
		for ctx.Err() == nil {
			updates := make(chan netlink.LinkUpdate, 64)
			done := make(chan struct{})
			// The subscription closes updates when it fails for good; the
			// errors it reports here, it survives.
			err := netlink.LinkSubscribeWithOptions(updates, done, netlink.LinkSubscribeOptions{
				ErrorCallback: func(err error) { log.Error(err, "interface watch") },
			})
			if err != nil {
				log.Error(err, "subscribe to interface changes")
			} else {
				watch(ctx, updates, changed)
			}
			close(done)
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
		return nil
	})
}

func watch(ctx context.Context, updates <-chan netlink.LinkUpdate, changed func(string)) {
	for {
		select {
		case <-ctx.Done():
			return
		case update, ok := <-updates:
			if !ok {
				return
			}
			if update.Link != nil && update.Attrs() != nil {
				changed(update.Attrs().Name)
			}
		}
	}
}
