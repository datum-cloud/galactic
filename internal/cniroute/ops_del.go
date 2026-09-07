// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cniroute

import (
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
)

// cmdDel is a no-op, as in every other binary in the chain. The termination
// routes this plugin's ADD installed are keyed by attachment and may still be in
// use by another pod sharing it, so deleting them here would race a concurrent
// ADD during a restart. Cleanup is left to garbage collection.
func cmdDel(args *skel.CmdArgs) error {
	slog.Info("DEL: skipping shared resource cleanup (handled by GC)", "containerID", args.ContainerID)

	result := &type100.Result{}
	_ = types.PrintResult(result, "1.0.0")
	return nil
}
