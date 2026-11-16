// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"time"

	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/nodevpc"
)

// HostVPCState returns an Agent.VPCState that runs nodevpc.Ensure for a gVPC
// in host, the node's network namespace, each call bounded by timeout.
//
// cfg.K8s should read the API server directly rather than through a cache:
// Argument allocation must see every BGPVRFInstance its node's other writers
// made, and the agent should not watch them all.
//
// The gVPC's attachment is not Released while the agent programs it, so
// galactic-router GC counts it as a user of the state Ensure creates and does
// not remove that state before the attachment's host link joins it.
func HostVPCState(host *hostattach.Namespace, cfg nodevpc.Config, timeout time.Duration) func(vpc string) error {
	return func(vpc string) error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return host.Do(func() error {
			_, err := nodevpc.Ensure(ctx, cfg, vpc)
			return err
		})
	}
}
