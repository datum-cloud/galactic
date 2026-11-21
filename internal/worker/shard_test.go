// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"net/netip"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/sources"
)

const (
	vpcC = "vpcC"

	shardLocalUID  = "uid-shard-local"
	shardRemoteUID = "uid-shard-remote"
	shardLocal     = "shard-local"
	shardRemote    = "shard-remote"
	svcA2          = "svc-a2"
)

var (
	shardLocalSID  = netip.MustParseAddr("2001:db8:5:1::")
	shardRemoteSID = netip.MustParseAddr("2001:db8:5:2::")
)

// withShards adds a ready shard on this node and one on the other node.
func withShards(e *env) {
	e.src.SetEgressShard(sources.EgressShard{UID: shardLocalUID, Name: shardLocal, Node: node,
		SID: shardLocalSID, Ready: true})
	e.src.SetEgressShard(sources.EgressShard{UID: shardRemoteUID, Name: shardRemote, Node: otherNode,
		SID: shardRemoteSID, Ready: true})
}

func shardDest(name string) *workerv1alpha1.Destination {
	return &workerv1alpha1.Destination{Target: &workerv1alpha1.Destination_Shard{
		Shard: &workerv1alpha1.ShardRef{Name: name}}}
}

// shardSpec is NAT's claim: a veth pair toward shards.
func shardSpec(names ...string) *workerv1alpha1.ClaimSpec {
	s := &workerv1alpha1.ClaimSpec{Handoff: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR}
	for _, n := range names {
		s.Destinations = append(s.Destinations, shardDest(n))
	}
	return s
}

// TestShardRefValidation refuses a shard named by the unused group and
// index, and one with no name.
func TestShardRefValidation(t *testing.T) {
	e := newEnv(t)
	withShards(e)
	e.start()
	for name, ref := range map[string]*workerv1alpha1.ShardRef{
		"group": {Group: "g", Name: shardLocal},
		"index": {Index: 1, Name: shardLocal},
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			s := &workerv1alpha1.ClaimSpec{Handoff: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR,
				Destinations: []*workerv1alpha1.Destination{{Target: &workerv1alpha1.Destination_Shard{Shard: ref}}}}
			wantRefusal(t, e.request(natSA, key(vpcA, shardLocalUID), 1, s), codes.InvalidArgument,
				workerv1alpha1.ReasonMalformedSpec)
		})
	}
}

// TestShardAttachmentGuards covers each guard on a claim whose attachment is
// an EgressShard: the caller must be allowed it, the claim must be a veth
// pair toward shards only, the shard must run on this node, and the VPC
// must have an admitted VPCAttachment on this node. Refusals record nothing.
func TestShardAttachmentGuards(t *testing.T) {
	e := newEnv(t)
	withShards(e)
	e.start()

	// Guard 1: a caller the allowlist does not let name an EgressShard,
	// though it may use local.veth_pair.
	wantRefusal(t, e.request(otherSA, key(vpcA, shardLocalUID), 1, shardSpec(shardLocal)),
		codes.PermissionDenied, workerv1alpha1.ReasonCapabilityNotAllowed)
	// Guard 2: a destination other than a shard.
	mixed := shardSpec(shardLocal)
	mixed.Destinations = append(mixed.Destinations, veth("guest-a1").Destinations...)
	wantRefusal(t, e.request(natSA, key(vpcA, shardLocalUID), 1, mixed),
		codes.InvalidArgument, workerv1alpha1.ReasonMalformedSpec)
	// Guard 3: a VPC with no admitted VPCAttachment on this node.
	wantRefusal(t, e.request(natSA, key(vpcC, shardLocalUID), 1, shardSpec(shardLocal)),
		codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized)
	// An attachment being deleted is not admitted, and does not count.
	e.src.SetAttachment(sources.Attachment{UID: "gone-c", Kind: sources.KindVPCAttachment, VPC: vpcC, Node: node})
	wantRefusal(t, e.request(natSA, key(vpcC, shardLocalUID), 1, shardSpec(shardLocal)),
		codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized)
	// An attachment on another node does not count either.
	e.src.SetAttachment(sources.Attachment{UID: "far-c", Kind: sources.KindVPCAttachment, VPC: vpcC,
		Node: otherNode, Admitted: true})
	wantRefusal(t, e.request(natSA, key(vpcC, shardLocalUID), 1, shardSpec(shardLocal)),
		codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized)
	// The shard must run on this node.
	wantRefusal(t, e.request(natSA, key(vpcA, shardRemoteUID), 1, shardSpec(shardRemote)),
		codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized)
	// A UID that names nothing.
	wantRefusal(t, e.request(natSA, key(vpcA, "uid-nothing"), 1, shardSpec(shardLocal)),
		codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized)
	// A destination shard that does not exist.
	wantRefusal(t, e.request(natSA, key(vpcA, shardLocalUID), 1, shardSpec("shard-missing")),
		codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized)
	if recs, _ := e.store.List(); len(recs) != 0 {
		t.Fatalf("refused calls recorded %v", recs)
	}

	// With every guard met the claim is accepted.
	e.mustOK(e.request(natSA, key(vpcA, shardLocalUID), 1, shardSpec(shardLocal)))
}

// TestShardResolution resolves a shard on this node to Local, carrying the
// VPC's attachments on this node, and one on another node to Fabric toward
// the shard SID's own locator. A shard that is not ready does not resolve,
// and none falls back to the other mode.
func TestShardResolution(t *testing.T) {
	e := newEnv(t)
	withShards(e)
	e.start()

	e.mustOK(e.request(natSA, key(vpcA, shardLocalUID), 1, shardSpec(shardLocal, shardRemote)))
	st := e.waitReady(mkey(vpcA, shardLocalUID), 1)
	if !isTrue(st, workerv1alpha1.ConditionResolved) {
		t.Fatalf("status = %v, want Resolved", st)
	}

	local := destinationsOf(e.local.Desired(vpcA), mkey(vpcA, shardLocalUID))
	if len(local) != 1 || local[0].Shard == nil || local[0].Shard.Name != shardLocal {
		t.Fatalf("Local destinations = %+v, want shard-local", local)
	}
	uids := make([]string, 0, len(local[0].Shard.Tenants))
	for _, tn := range local[0].Shard.Tenants {
		uids = append(uids, tn.UID)
	}
	// Every admitted attachment of vpcA on this node, and none of vpcB's or
	// the other node's, though vpcB uses the same addresses.
	if want := []string{uidGuestA1, "guest-a3", svcA, svcA2}; !slices.Equal(uids, want) {
		t.Fatalf("Local shard tenants = %v, want %v", uids, want)
	}
	if got, want := local[0].Locator, netip.MustParsePrefix("2001:db8:5:1::/64"); got != want {
		t.Fatalf("Local shard locator = %v, want the shard SID's %v", got, want)
	}

	remote := destinationsOf(e.fabric.Desired(vpcA), mkey(vpcA, shardLocalUID))
	if len(remote) != 1 || remote[0].Shard == nil || remote[0].Shard.Name != shardRemote {
		t.Fatalf("Fabric destinations = %+v, want shard-remote", remote)
	}
	if got, want := remote[0].Locator, netip.MustParsePrefix("2001:db8:5:2::/64"); got != want ||
		got == locB {
		t.Fatalf("Fabric shard locator = %v, want %v, distinct from the node's router locator", got, want)
	}
	if len(remote[0].Shard.Tenants) != 0 {
		t.Fatalf("a Fabric shard carries tenants %v", remote[0].Shard.Tenants)
	}

	// A shard that is not ready does not resolve; the other stays.
	e.src.SetEgressShard(sources.EgressShard{UID: shardRemoteUID, Name: shardRemote, Node: otherNode,
		SID: shardRemoteSID})
	e.w.Changed("")
	e.eventually("shard-remote unresolved", func() bool {
		st := e.status(mkey(vpcA, shardLocalUID))
		c := condOf(st, workerv1alpha1.ConditionResolved)
		return c.GetStatus() == condFalse && c.GetReason() == workerv1alpha1.ReasonShardNotReady
	})

	// A Local preference never falls back to the remote shard.
	pref := shardSpec(shardRemote)
	pref.Mode = workerv1alpha1.Mode_MODE_LOCAL
	e.src.SetEgressShard(sources.EgressShard{UID: shardRemoteUID, Name: shardRemote, Node: otherNode,
		SID: shardRemoteSID, Ready: true})
	e.mustOK(e.update(natSA, key(vpcA, shardLocalUID), 2, pref))
	e.eventually("ModeUnavailable", func() bool {
		st := e.status(mkey(vpcA, shardLocalUID))
		c := condOf(st, workerv1alpha1.ConditionResolved)
		return st.GetObservedGeneration() == 2 && c.GetReason() == workerv1alpha1.ReasonModeUnavailable
	})
}

// TestShardAttachmentRevoked withdraws a shard-attached claim once its VPC
// has no admitted attachment left on this node.
func TestShardAttachmentRevoked(t *testing.T) {
	e := newEnv(t)
	withShards(e)
	e.start()
	e.mustOK(e.request(natSA, key(vpcB, shardLocalUID), 1, shardSpec(shardLocal)))
	e.waitReady(mkey(vpcB, shardLocalUID), 1)
	e.src.DeleteAttachment("svc-b")
	e.src.DeleteAttachment("guest-b1")
	e.w.Changed(vpcB)
	e.waitGone(mkey(vpcB, shardLocalUID))
}

// destinationsOf returns the destinations of claim k in desired.
func destinationsOf(desired []module.Claim, k module.ClaimKey) []module.Destination {
	for _, c := range desired {
		if c.Key == k {
			return c.Destinations
		}
	}
	return nil
}
