// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import "go.datum.net/galactic/internal/nodevpc"

// The node-local Argument allocation lives in nodevpc, shared with
// galactic-edge, which claims a VPC's BGPVRFInstance on a node where the VPC
// has no workload. These names keep this package's call sites and tests.
var (
	lockArguments    = nodevpc.LockArguments
	claimArgument    = nodevpc.ClaimArgument
	allocateArgument = nodevpc.AllocateArgument
	argumentHolder   = nodevpc.ArgumentHolder

	errArgumentCollision = nodevpc.ErrArgumentCollision
)
