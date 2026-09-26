// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/egressroutes"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/egressroutemap"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/vrf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// egressClaimGrace is how long a VRF carrying an egress route but no claim is
// left alone before the route is withdrawn.
//
// ADD installs the route from the attachment's own declaration so the network
// works when ADD returns, and only then does the attachment report its node
// and the cell record a claim against it. A sweep that ran in that window
// would see a route with no claim and withdraw what ADD just installed. The
// grace is measured from the VRF entry's last registration, so a VRF that
// gained an attachment recently is left alone, and one that has carried a
// route for longer than any claim takes to appear is withdrawn on the first
// sweep after its claim goes.
var egressClaimGrace = 2 * time.Minute

// vrfTableIDFn resolves a VPC's kernel VRF table id. Tests replace it, since
// the real one reads a VRF interface that only exists on a node.
var vrfTableIDFn = vrf.TableID

// egressVRF is one tenant VRF on this node as the claim sweep sees it.
type egressVRF struct {
	TableID  uint32
	Argument uint16
	Age      time.Duration
	HasRoute bool
}

// egressAction is one route the sweep decided to install or withdraw.
type egressAction struct {
	TableID  uint32
	Argument uint16
	Install  bool
}

// planEgressClaims decides what the sweep does to each VRF: a claimed VRF
// without a route gets one, and an unclaimed VRF with a route older than
// grace loses it. Everything else is already in step and left alone.
func planEgressClaims(vrfs []egressVRF, claimed map[uint32]struct{}, grace time.Duration) []egressAction {
	var actions []egressAction
	for _, v := range vrfs {
		_, wanted := claimed[v.TableID]
		switch {
		case wanted && !v.HasRoute:
			actions = append(actions, egressAction{TableID: v.TableID, Argument: v.Argument, Install: true})
		case !wanted && v.HasRoute && v.Age >= grace:
			actions = append(actions, egressAction{TableID: v.TableID, Argument: v.Argument})
		}
	}
	return actions
}

// claimedTableIDs maps the claims naming this node to the VRF tables on it. A
// claim whose VPC has no VRF here is skipped rather than an error: the cell
// can record a claim a moment before the VRF exists, or a moment after it was
// torn down, and the next sweep sees whichever way that settles.
func claimedTableIDs(claims []bgpv1alpha1.EgressShardClaim, tableID func(string) (uint32, error)) map[uint32]struct{} {
	claimed := make(map[uint32]struct{}, len(claims))
	for _, claim := range claims {
		id, err := tableID(claim.Spec.VPC.Name)
		if err != nil {
			slog.Debug("egress claim sweep: claim names a VPC with no VRF on this node",
				"claim", client.ObjectKeyFromObject(&claim), "vpc", claim.Spec.VPC.Name, "err", err)
			continue
		}
		claimed[id] = struct{}{}
	}
	return claimed
}

// listNodeEgressClaims lists the claims the cell recorded against this node,
// in every namespace, by the node label the cell stamps on each.
func listNodeEgressClaims(
	ctx context.Context, k8s client.Client, nodeName string,
) ([]bgpv1alpha1.EgressShardClaim, error) {
	var list bgpv1alpha1.EgressShardClaimList
	if err := k8s.List(ctx, &list, client.MatchingLabels{bgpv1alpha1.LabelEgressShardClaimNode: nodeName}); err != nil {
		return nil, fmt.Errorf("list EgressShardClaims for node %q: %w", nodeName, err)
	}
	return list.Items, nil
}

// nodeEgressVRFs reads every tenant VRF this node's datapath registers, with
// whether it carries an egress route and how long ago it was last registered.
// Tables the ingress sidecar owns are skipped: their routes are written from
// inside a pod network namespace and are not this sweep's to touch.
//
// Two vrf_table rows can map to one table during a Block migration. The
// younger one wins, so a VRF is never withdrawn from on the strength of an
// old row while a new attachment just registered it.
func nodeEgressVRFs(
	vrfTable *usidmap.VRFTable, routes *egressroutemap.EgressRouteTable, foreign map[uint32]struct{},
) ([]egressVRF, error) {
	entries, err := vrfTable.List()
	if err != nil {
		return nil, fmt.Errorf("list vrf_table: %w", err)
	}
	now := vrfTable.Generation()

	byTable := map[uint32]egressVRF{}
	for _, e := range entries {
		if _, skip := foreign[e.VRFTableID]; skip {
			continue
		}
		var age time.Duration
		if now > e.Generation {
			age = time.Duration(now - e.Generation)
		}
		current, seen := byTable[e.VRFTableID]
		if !seen || age < current.Age {
			byTable[e.VRFTableID] = egressVRF{TableID: e.VRFTableID, Argument: e.Argument, Age: age}
		}
	}

	vrfs := make([]egressVRF, 0, len(byTable))
	for id, v := range byTable {
		_, ok, err := routes.Lookup(id, egressroutemap.DefaultPrefix)
		if err != nil {
			return nil, fmt.Errorf("look up table %d's default egress route: %w", id, err)
		}
		v.HasRoute = ok
		vrfs = append(vrfs, v)
	}
	sort.Slice(vrfs, func(i, j int) bool { return vrfs[i].TableID < vrfs[j].TableID })
	return vrfs, nil
}

// startEgressClaimSweep runs one claim sweep in the background, dropping the
// tick when the previous one is still running.
func startEgressClaimSweep(ctx context.Context, sem chan struct{}, state ebpfDatapathState) {
	select {
	case sem <- struct{}{}:
		go func() {
			defer func() { <-sem }()
			runEgressClaimSweep(ctx, state)
		}()
	default:
	}
}

// runEgressClaimSweep keeps every tenant VRF's egress route in step with the
// claims the cell has recorded against this node. It is what lets a network's
// egress be turned on or off under a running workload: ADD wrote the route
// from the declaration it was handed, and nothing else re-reads that
// declaration once the plugin process exits.
//
// A missing pinned map is not an error worth logging on every tick: it means
// the datapath is not loaded on this node, and the sweep has nothing to do.
func runEgressClaimSweep(ctx context.Context, state ebpfDatapathState) {
	if state.k8sClient == nil || state.nodeName == "" {
		return
	}

	claims, err := listNodeEgressClaims(ctx, state.k8sClient, state.nodeName)
	if err != nil {
		slog.Error("egress claim sweep skipped", "err", err)
		return
	}
	claimed := claimedTableIDs(claims, vrfTableIDFn)

	registry, registryCloser, err := usidmap.OpenPinnedRegistry(attach.PinDir)
	if err != nil {
		return
	}
	defer func() { _ = registryCloser.Close() }()

	routes, routesCloser, err := egressroutemap.OpenPinnedEgressRouteTable(attach.PinDir)
	if err != nil {
		return
	}
	defer func() { _ = routesCloser.Close() }()

	foreign, err := egressroutemap.SidecarOwnedTableIDs(registry.VRF)
	if err != nil {
		slog.Error("egress claim sweep skipped: could not resolve entry ownership", "err", err)
		return
	}
	vrfs, err := nodeEgressVRFs(registry.VRF, routes, foreign)
	if err != nil {
		slog.Error("egress claim sweep skipped", "err", err)
		return
	}

	applyEgressActions(planEgressClaims(vrfs, claimed, egressClaimGrace), state.egressShardSIDs, state.nat64Prefix)
}

// applyEgressActions writes what the plan decided. An install on a node that
// names no shard is logged and left for the next sweep, since the node cannot
// give the VRF egress until an operator names one; a withdraw needs nothing.
func applyEgressActions(actions []egressAction, shardSIDs []net.IP, nat64Prefix *net.IPNet) {
	for _, a := range actions {
		if !a.Install {
			if err := egressroutes.Withdraw(a.TableID, nat64Prefix); err != nil {
				slog.Error("egress claim sweep: withdraw failed", "table", a.TableID, "err", err)
				continue
			}
			slog.Info("egress claim sweep: egress withdrawn from a VRF whose claim is gone", "table", a.TableID)
			continue
		}
		if len(shardSIDs) == 0 {
			slog.Warn("egress claim sweep: a VRF claims egress but this node names no egress shard",
				"table", a.TableID)
			continue
		}
		if err := egressroutes.Install(a.TableID, a.Argument, shardSIDs, nat64Prefix); err != nil {
			slog.Error("egress claim sweep: install failed", "table", a.TableID, "err", err)
			continue
		}
		slog.Info("egress claim sweep: egress installed for a VRF the cell claims", "table", a.TableID)
	}
}
