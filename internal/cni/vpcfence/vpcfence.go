// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vpcfence runs CNI's writes to a VPC's shared host state under the
// VPC's write fence (internal/ownership), as a writer that never owns the
// scope. The shared state is the canonical host VRF and its table, the SID
// Argument and BGPVRFInstance, vrf_table rows and the BGPAdvertisement of an
// attachment on the node. Whichever process owns the scope, such as
// galactic-worker, sees each write as an Exclusive one and prepares its next
// change from the state it left. No write waits for that owner to run.
package vpcfence

import (
	"context"
	"fmt"
	"time"

	"go.datum.net/galactic/internal/ownership"
)

// Dir is the fence's state directory, shared with every other writer on the
// node. Tests point it elsewhere.
var Dir = ownership.DefaultDir

// Wait bounds how long Write waits while ownership of the scope moves, which
// takes one locked file write.
const Wait = 30 * time.Second

// Write runs mutate under vpc's write fence, waiting up to Wait, or until ctx
// is done, while ownership of the scope moves. It creates the fence's
// directory when the node has none yet. mutate must finish every write before
// it returns and must not call the fence.
func Write(ctx context.Context, vpc string, mutate func() error) error {
	auth, err := ownership.New(Dir)
	if err != nil {
		return fmt.Errorf("open VPC write fence: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, Wait)
	defer cancel()
	if err := auth.ExclusiveWait(ctx, ownership.VPCScope(vpc), func(ownership.Record) error { return nil },
		mutate); err != nil {
		return fmt.Errorf("write VPC %s under its fence: %w", vpc, err)
	}
	return nil
}

// WriteUnlessWorker is Write for maintenance a galactic-worker incarnation
// does itself once it owns the VPC's scope: it returns an error wrapping
// ownership.ErrWorkerOwned, and runs nothing, when one does.
func WriteUnlessWorker(ctx context.Context, vpc string, mutate func() error) error {
	auth, err := ownership.New(Dir)
	if err != nil {
		return fmt.Errorf("open VPC write fence: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, Wait)
	defer cancel()
	if err := auth.ExclusiveWait(ctx, ownership.VPCScope(vpc), ownership.RefuseWorkerOwned, mutate); err != nil {
		return fmt.Errorf("write VPC %s under its fence: %w", vpc, err)
	}
	return nil
}
