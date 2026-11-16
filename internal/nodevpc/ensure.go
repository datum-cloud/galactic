// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package nodevpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"k8s.io/apimachinery/pkg/api/equality"
	"sigs.k8s.io/controller-runtime/pkg/client"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// ErrNoSRv6Identity is returned by Ensure when the node's BGPRouter has no
// SRv6 locator or node ID, so no uSID can deliver the VPC's traffic to it.
var ErrNoSRv6Identity = errors.New("node's BGPRouter has no SRv6 locator or node ID")

// Config is what Ensure needs to find and write a node's VPC state.
type Config struct {
	K8s client.Client
	// Namespace holds the node's BGPRouter and BGPVRFInstances.
	Namespace string
	// Node is the node's name, which its BGPRouter targets.
	Node string
	// PinDir is the bpffs directory holding the pinned uSID maps.
	PinDir string
}

// State is a VPC's state on a node, as Ensure left it.
type State struct {
	Router Router
	// Table is the host VRF's routing table.
	Table uint32
	// Block and Argument key the VPC's vrf_table row.
	Block    uint64
	Argument uint16
	// Instance is the name of the node's BGPVRFInstance for the VPC.
	Instance string
}

// Ensure creates whatever is missing of vpc's state on the node, in the
// calling thread's network namespace, and returns it. It is idempotent and
// changes nothing that is already in place:
//
//  1. The canonical host VRF, with its table reservation, as CNI ADD creates
//     it (vrf.Add, under the node's VRF lock).
//  2. The node's BGPVRFInstance for the VPC, with an Argument claimed under
//     the node's Argument lock (ClaimArgument).
//  3. The vrf_table row mapping (Block, Argument) to the VRF's table, with the
//     veth egress kind, when no row exists for that key.
//
// Ensure never removes state, including on failure: galactic-router GC removes
// a VRF and its BGPVRFInstance once no workload, ingress sidecar, enslaved link
// or Galactic Edge attachment on the node uses the VPC. A caller relying on
// that state must already count as such a user, so GC keeps it between Ensure
// and the caller's own link; galactic-edge does through its non-Released
// EdgeAttachment.
//
// Ensure returns ErrNoSRv6Identity, before creating anything, for a node whose
// router has no SRv6 identity.
func Ensure(ctx context.Context, cfg Config, vpc string) (State, error) {
	router, err := LookupRouter(ctx, cfg.K8s, cfg.Node, cfg.Namespace)
	if err != nil {
		return State{}, err
	}
	node := attachreg.Node{Locator: router.SRv6Locator, NodeID: router.NodeID}
	if !node.Configured() {
		return State{}, fmt.Errorf("%w: router %s", ErrNoSRv6Identity, router.Name)
	}
	block, err := node.Block()
	if err != nil {
		return State{}, err
	}
	vpcHex, err := intf.Base62ToHex(vpc)
	if err != nil {
		return State{}, fmt.Errorf("convert VPC %q to hex: %w", vpc, err)
	}
	rtValue, err := RouteTarget(int64(router.ASN), vpcHex)
	if err != nil {
		return State{}, fmt.Errorf("compute route target: %w", err)
	}
	// The number vpc_attribution_table names a VPC by holds 48 bits, which
	// a base62 identifier can exceed. CNI ADD then leaves attribution out
	// and forwards as usual; Ensure does too.
	owner := attributionOwner{}
	if n, err := strconv.ParseUint(vpcHex, 16, 48); err == nil {
		owner = attributionOwner{vpc: n, known: true}
	}
	name := crdnames.BGPVRFInstanceName(vpc, cfg.Node)
	want := func(vrfID int32) bgpv1alpha1.BGPVRFInstanceSpec { return InstanceSpec(router.Name, rtValue, vrfID) }

	// A caller that runs Ensure on every pass finds everything in place
	// almost always, so that is read first, without the node's locks, which
	// every CNI ADD on the node waits for.
	if s, ok := current(ctx, cfg, vpc, name, want, block, owner); ok {
		s.Router = router
		return s, nil
	}

	if err := vrf.Add(vpc); err != nil {
		return State{}, fmt.Errorf("add host VRF for VPC %s: %w", vpc, err)
	}
	table, err := vrf.TableID(vpc)
	if err != nil {
		return State{}, fmt.Errorf("look up host VRF table for VPC %s: %w", vpc, err)
	}

	// createdBefore is false, so a reused instance is never moved and
	// siblings is never asked.
	noSiblings := func() ([]string, error) { return nil, nil }
	release := func(argument int32) error {
		return attachreg.ReleaseArgument(cfg.PinDir, node, vpc, uint16(argument))
	}
	vrfID, _, err := ClaimArgument(ctx, cfg.K8s, cfg.Namespace, router.Name, name, false, noSiblings, want, release)
	if err != nil {
		return State{}, fmt.Errorf("claim BGPVRFInstance %s: %w", name, err)
	}

	state := State{Router: router, Table: table, Block: block, Argument: uint16(vrfID), Instance: name}
	if err := ensureVRFRow(cfg.PinDir, state, owner); err != nil {
		return State{}, err
	}
	return state, nil
}

// ensureVRFRow makes the vrf_table row for s's (Block, Argument) map to s's
// table. A missing row is written with the veth egress kind. A row that maps
// to another table is rewritten with its egress kind kept, as GC's repair
// does: it was left by a VPC that held the Argument before, and would deliver
// this VPC's traffic into that VPC's VRF. A row already on s's table is left
// alone, since CNI ADD writes it with the egress kind of its own interface.
//
// The key's vpc_attribution_table row is removed when it names a VPC other
// than owner's, so the key's traffic is reported unattributed rather than
// charged to that VPC; a CNI ADD of this VPC writes it again. A missing row is
// not written: an edge attachment has no VPCAttachment to name.
func ensureVRFRow(pinDir string, s State, owner attributionOwner) error {
	registry, closer, err := usidmap.OpenPinnedRegistry(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned uSID maps: %w", err)
	}
	defer func() { _ = closer.Close() }()
	if attr, ok, err := registry.VPCAttribution.Get(s.Block, s.Argument); err != nil {
		return fmt.Errorf("read vpc_attribution_table entry: %w", err)
	} else if ok && owner.other(attr.VPC) {
		slog.Warn("nodevpc: removing vpc_attribution_table entry that names another VPC",
			"block", s.Block, "argument", s.Argument, "vpc", attr.VPC, "want", owner.vpc)
		if err := registry.VPCAttribution.Unregister(s.Block, s.Argument); err != nil {
			return fmt.Errorf("remove vpc_attribution_table entry: %w", err)
		}
	}
	row, ok, err := registry.VRF.Get(s.Block, s.Argument)
	switch {
	case err != nil:
		return fmt.Errorf("read vrf_table entry: %w", err)
	case ok && row.VRFTableID == s.Table:
		return nil
	}
	kind := usidmap.EgressKindVeth
	if ok {
		kind = row.EgressKind
		slog.Warn("nodevpc: rewriting vrf_table entry that maps to another VRF's table",
			"block", s.Block, "argument", s.Argument, "from", row.VRFTableID, "to", s.Table)
	}
	if err := registry.VRF.Register(s.Block, s.Argument, s.Table, kind); err != nil {
		return fmt.Errorf("register vrf_table entry: %w", err)
	}
	return nil
}

// attributionOwner is the number vpc_attribution_table names Ensure's VPC
// by, when the VPC's identifier fits in its 48 bits.
type attributionOwner struct {
	vpc   uint64
	known bool
}

// other reports whether an attribution row naming vpc is another VPC's. With
// no number for Ensure's VPC, no row is judged, as CNI ADD writes none then.
func (o attributionOwner) other(vpc uint64) bool {
	return o.known && vpc != o.vpc
}

// current returns vpc's state on the node when all of it is in place: the
// host VRF, the BGPVRFInstance named name with the spec want gives for its
// Argument, a vrf_table row mapping that Argument to the VRF's table, and no
// vpc_attribution_table row naming another VPC. It takes none of the node's
// locks, and reports false on any doubt, so Ensure then does the full work
// under them.
func current(
	ctx context.Context, cfg Config, vpc, name string, want func(int32) bgpv1alpha1.BGPVRFInstanceSpec,
	block uint64, owner attributionOwner,
) (State, bool) {
	table, err := vrf.TableID(vpc)
	if err != nil {
		return State{}, false
	}
	var inst bgpv1alpha1.BGPVRFInstance
	if err := cfg.K8s.Get(ctx, client.ObjectKey{Namespace: cfg.Namespace, Name: name}, &inst); err != nil {
		return State{}, false
	}
	if !equality.Semantic.DeepEqual(inst.Spec, want(inst.Spec.VRFID)) {
		return State{}, false
	}
	argument := uint16(inst.Spec.VRFID)
	registry, closer, err := usidmap.OpenPinnedRegistry(cfg.PinDir)
	if err != nil {
		return State{}, false
	}
	defer func() { _ = closer.Close() }()
	if row, ok, err := registry.VRF.Get(block, argument); err != nil || !ok || row.VRFTableID != table {
		return State{}, false
	}
	if attr, ok, err := registry.VPCAttribution.Get(block, argument); err != nil || (ok && owner.other(attr.VPC)) {
		return State{}, false
	}
	return State{Table: table, Block: block, Argument: argument, Instance: name}, true
}
