// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"log/slog"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	type100 "github.com/containernetworking/cni/pkg/types/100"
)

// cmdDel is a no-op, same as every other binary in the chain: the
// BGPVRFInstance/BGPAdvertisement CRDs and eBPF vrf_table entry this
// plugin's own ADD created are keyed by (vpc, vpcAttachment) and may still
// be in use by another pod/VM sharing the same attachment. Deleting them
// here would race with a concurrent ADD during restarts. Cleanup is left
// entirely to galactic-router's GC controller — see internal/cni's own
// cmdDel for the full reasoning, identical here.
func cmdDel(args *skel.CmdArgs) error {
	slog.Info("DEL: skipping shared resource cleanup (handled by GC)", "containerID", args.ContainerID)

	result := &type100.Result{}
	_ = types.PrintResult(result, "1.0.0")
	return nil
}
