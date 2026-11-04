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

// producerLinkWatch reports the name of every interface added, changed or
// removed on the node to changed until the manager stops, resubscribing after
// a netlink error. The producer health controller uses it to probe a
// replaced producer afresh as soon as its interface is recreated.
func producerLinkWatch(changed func(name string)) manager.Runnable {
	return manager.RunnableFunc(func(ctx context.Context) error {
		log := ctrl.Log.WithName("service-producer-links")
		for ctx.Err() == nil {
			updates := make(chan netlink.LinkUpdate, 64)
			done := make(chan struct{})
			failed := make(chan struct{}, 1)
			err := netlink.LinkSubscribeWithOptions(updates, done, netlink.LinkSubscribeOptions{
				ErrorCallback: func(err error) {
					log.Error(err, "interface watch failed; resubscribing")
					select {
					case failed <- struct{}{}:
					default:
					}
				},
			})
			if err != nil {
				log.Error(err, "subscribe to interface changes")
			} else {
				watch(ctx, updates, failed, changed)
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

func watch(ctx context.Context, updates <-chan netlink.LinkUpdate, failed <-chan struct{}, changed func(string)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-failed:
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
