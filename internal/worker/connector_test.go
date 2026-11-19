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

// Connector claims (D37): galactic-edge claims a routed link on an
// EdgeAttachment, naming the host link it created.
const (
	edgeSA   = "galactic-system/galactic-edge"
	edgeAtt  = "edge-a"
	edgeAtt2 = "edge-a2"
	edgeLink = "ge0abc123"
)

var edgeAddr = netip.MustParseAddr("2001:db8:100::10")

// connectorEnv is a Worker env whose sources hold two admitted
// EdgeAttachments of vpcA on this node, and that lets galactic-edge use
// local.routed_link.
func connectorEnv(t *testing.T) *env {
	t.Helper()
	testCaps[edgeSA] = []string{workerv1alpha1.CapabilityLocalRoutedLink}
	t.Cleanup(func() { delete(testCaps, edgeSA) })
	e := newEnv(t)
	for _, uid := range []string{edgeAtt, edgeAtt2} {
		e.src.SetAttachment(sources.Attachment{UID: uid, Kind: sources.KindEdgeAttachment, VPC: vpcA, Node: node,
			Admitted: true, Addresses: []netip.Addr{edgeAddr}})
	}
	return e
}

func edgeSpec(name string, prefixes ...string) *workerv1alpha1.ClaimSpec {
	return &workerv1alpha1.ClaimSpec{Handoff: workerv1alpha1.Handoff_HANDOFF_ROUTED_LINK,
		EdgeLink: &workerv1alpha1.EdgeLink{Name: name, Prefixes: prefixes}}
}

// edgeDesired returns the connector claim of att the Local module was last
// handed.
func (e *env) edgeDesired(att string) (module.Claim, bool) {
	for _, c := range e.local.Desired(vpcA) {
		if c.Key.AttachmentUID == att {
			return c, true
		}
	}
	return module.Claim{}, false
}

// TestConnectorClaimAttaches admits a connector claim and hands the Local
// module the link, the address from the EdgeAttachment and the prefixes,
// with the claim's own attachment as its one Local destination.
func TestConnectorClaimAttaches(t *testing.T) {
	e := connectorEnv(t)
	e.start()
	k := mkey(vpcA, edgeAtt)
	e.mustOK(e.request(edgeSA, key(vpcA, edgeAtt), 1, edgeSpec(edgeLink, "2001:db8:200::/48")))
	st := e.waitReady(k, 1)
	ds := st.GetDestinations()
	if len(ds) != 1 || ds[0].GetDestination().GetAttachment().GetUid() != edgeAtt ||
		ds[0].GetMode() != workerv1alpha1.Mode_MODE_LOCAL {
		t.Fatalf("destinations = %v, want the claim's own attachment, Local", ds)
	}
	c, ok := e.edgeDesired(edgeAtt)
	if !ok || c.EdgeLink == nil {
		t.Fatalf("Local module was not handed the edge link: %+v", c)
	}
	if c.EdgeLink.Name != edgeLink || c.EdgeLink.Address != edgeAddr ||
		!slices.Equal(c.EdgeLink.Prefixes, []netip.Prefix{netip.MustParsePrefix("2001:db8:200::/48")}) {
		t.Fatalf("edge link = %+v", c.EdgeLink)
	}

	// Delivery changes: a gate opens for a second prefix.
	e.mustOK(e.update(edgeSA, key(vpcA, edgeAtt), 2, edgeSpec(edgeLink, "2001:db8:200::/48", "2001:db8:300::/48")))
	e.waitReady(k, 2)
	if c, _ := e.edgeDesired(edgeAtt); len(c.EdgeLink.Prefixes) != 2 {
		t.Fatalf("prefixes after update = %v", c.EdgeLink.Prefixes)
	}

	// Withdrawal: the release removes every row of the claim.
	e.mustOK(e.release(edgeSA, key(vpcA, edgeAtt), 2))
	e.waitGone(k)
	if rows := e.host.Rows(vpcA); len(rows) != 0 {
		t.Fatalf("rows after release = %v", rowIDs(rows))
	}
}

// TestConnectorClaimReplacement replaces an attachment with a new one: the
// old attachment's claim is released and the new one's is attached on a new
// link, each with its own rows.
func TestConnectorClaimReplacement(t *testing.T) {
	e := connectorEnv(t)
	e.start()
	e.mustOK(e.request(edgeSA, key(vpcA, edgeAtt), 1, edgeSpec(edgeLink)))
	e.waitReady(mkey(vpcA, edgeAtt), 1)
	e.mustOK(e.release(edgeSA, key(vpcA, edgeAtt), 1))
	e.src.DeleteAttachment(edgeAtt)
	e.mustOK(e.request(edgeSA, key(vpcA, edgeAtt2), 1, edgeSpec("ge0def456")))
	e.waitGone(mkey(vpcA, edgeAtt))
	e.waitReady(mkey(vpcA, edgeAtt2), 1)
	for _, r := range e.host.Rows(vpcA) {
		if r.Key.AttachmentUID != edgeAtt2 {
			t.Fatalf("row of the replaced attachment left: %v", rowIDs(e.host.Rows(vpcA)))
		}
	}
}

// TestConnectorClaimRefusals refuses malformed and unauthorized connector
// claims, writing nothing.
func TestConnectorClaimRefusals(t *testing.T) {
	e := connectorEnv(t)
	e.src.SetAttachment(sources.Attachment{UID: "edge-denied", Kind: sources.KindEdgeAttachment, VPC: vpcA,
		Node: node, Admitted: false, Addresses: []netip.Addr{edgeAddr}})
	e.src.SetAttachment(sources.Attachment{UID: "edge-other-node", Kind: sources.KindEdgeAttachment, VPC: vpcA,
		Node: otherNode, Admitted: true, Addresses: []netip.Addr{edgeAddr}})
	e.start()
	withDest := edgeSpec(edgeLink)
	withDest.Destinations = veth("guest-a1").Destinations
	veth := edgeSpec(edgeLink)
	veth.Handoff = workerv1alpha1.Handoff_HANDOFF_VETH_PAIR
	fabric := edgeSpec(edgeLink)
	fabric.Mode = workerv1alpha1.Mode_MODE_FABRIC
	for _, tc := range []struct {
		name   string
		caller string
		att    string
		spec   *workerv1alpha1.ClaimSpec
		code   codes.Code
		reason string
	}{
		{"destinations", edgeSA, edgeAtt, withDest, codes.InvalidArgument, workerv1alpha1.ReasonMalformedSpec},
		{"veth handoff", edgeSA, edgeAtt, veth, codes.InvalidArgument, workerv1alpha1.ReasonMalformedSpec},
		{"fabric mode", edgeSA, edgeAtt, fabric, codes.InvalidArgument, workerv1alpha1.ReasonMalformedSpec},
		{"bad name", edgeSA, edgeAtt, edgeSpec("not a link"), codes.InvalidArgument,
			workerv1alpha1.ReasonMalformedSpec},
		{"bad prefix", edgeSA, edgeAtt, edgeSpec(edgeLink, "2001:db8::1"), codes.InvalidArgument,
			workerv1alpha1.ReasonMalformedSpec},
		{"denied attachment", edgeSA, "edge-denied", edgeSpec(edgeLink), codes.PermissionDenied,
			workerv1alpha1.ReasonVPCNotAuthorized},
		{"other node", edgeSA, "edge-other-node", edgeSpec(edgeLink), codes.PermissionDenied,
			workerv1alpha1.ReasonVPCNotAuthorized},
		{"not an EdgeAttachment", edgeSA, svcA, edgeSpec(edgeLink), codes.PermissionDenied,
			workerv1alpha1.ReasonVPCNotAuthorized},
		{"routed link without edge link", edgeSA, edgeAtt, spec(workerv1alpha1.Handoff_HANDOFF_ROUTED_LINK,
			"guest-a1"), codes.PermissionDenied, workerv1alpha1.ReasonVPCNotAuthorized},
		{"caller without routed_link", natSA, edgeAtt, edgeSpec(edgeLink), codes.PermissionDenied,
			workerv1alpha1.ReasonCapabilityNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantRefusal(t, e.request(tc.caller, key(vpcA, tc.att), 1, tc.spec), tc.code, tc.reason)
		})
	}
	e.idle()
	if rows := e.host.Rows(vpcA); len(rows) != 0 {
		t.Fatalf("rows after refusals = %v", rowIDs(rows))
	}
}

// TestConnectorClaimWithoutAddress programs nothing for an EdgeAttachment
// core has not allocated an address to.
func TestConnectorClaimWithoutAddress(t *testing.T) {
	e := connectorEnv(t)
	e.src.SetAttachment(sources.Attachment{UID: edgeAtt, Kind: sources.KindEdgeAttachment, VPC: vpcA, Node: node,
		Admitted: true})
	e.start()
	k := mkey(vpcA, edgeAtt)
	e.mustOK(e.request(edgeSA, key(vpcA, edgeAtt), 1, edgeSpec(edgeLink)))
	st := e.waitObserved(k)
	if c := condOf(st, workerv1alpha1.ConditionProgrammed); c.GetStatus() != condFalse ||
		c.GetReason() != workerv1alpha1.ReasonDestinationAddressUnknown {
		t.Fatalf("Programmed = %v, want False/DestinationAddressUnknown", c)
	}
	if rows := e.host.Rows(vpcA); len(rows) != 0 {
		t.Fatalf("rows = %v", rowIDs(rows))
	}
}

// TestConnectorClaimRevoked withdraws a connector claim whose EdgeAttachment
// loses Admitted, as core's revocation does, and refuses its renewal.
func TestConnectorClaimRevoked(t *testing.T) {
	e := connectorEnv(t)
	e.start()
	k := mkey(vpcA, edgeAtt)
	e.mustOK(e.request(edgeSA, key(vpcA, edgeAtt), 1, edgeSpec(edgeLink, "2001:db8:200::/48")))
	e.waitReady(k, 1)

	a, _, _ := e.src.Attachment(t.Context(), edgeAtt)
	a.Admitted = false
	e.src.SetAttachment(a)
	e.w.Changed(vpcA)
	e.waitGone(k)
	if rows := e.host.Rows(vpcA); len(rows) != 0 {
		t.Fatalf("rows after revocation = %v", rowIDs(rows))
	}
	// galactic-edge, unaware yet, asks for the link again.
	wantRefusal(t, e.request(edgeSA, key(vpcA, edgeAtt), 2, edgeSpec(edgeLink)), codes.PermissionDenied,
		workerv1alpha1.ReasonVPCNotAuthorized)
}

// TestConnectorReplayRejected refuses each replay of a previous owner's
// claim without changing any row.
func TestConnectorReplayRejected(t *testing.T) {
	e := connectorEnv(t)
	e.start()
	k := mkey(vpcA, edgeAtt)
	e.mustOK(e.request(edgeSA, key(vpcA, edgeAtt), 1, edgeSpec(edgeLink)))
	e.mustOK(e.update(edgeSA, key(vpcA, edgeAtt), 2, edgeSpec(edgeLink, "2001:db8:200::/48")))
	e.waitReady(k, 2)
	before := rowIDs(e.host.Rows(vpcA))

	// A fenced galactic-edge process replays what it last sent.
	wantRefusal(t, e.update(edgeSA, key(vpcA, edgeAtt), 1, edgeSpec(edgeLink)), codes.Aborted,
		workerv1alpha1.ReasonStaleGeneration)
	wantRefusal(t, e.release(edgeSA, key(vpcA, edgeAtt), 1), codes.Aborted, workerv1alpha1.ReasonStaleGeneration)
	wantRefusal(t, e.request(edgeSA, key(vpcA, edgeAtt), 1, edgeSpec(edgeLink)), codes.FailedPrecondition,
		workerv1alpha1.ReasonClaimExists)
	// Another caller names the attachment.
	wantRefusal(t, e.request(routedSA, key(vpcA, edgeAtt), 3, edgeSpec(edgeLink)), codes.PermissionDenied,
		workerv1alpha1.ReasonAttachmentClaimedByAnotherCaller)
	// A deleted attachment's claim, replayed after its replacement.
	e.src.DeleteAttachment(edgeAtt2)
	wantRefusal(t, e.request(edgeSA, key(vpcA, edgeAtt2), 1, edgeSpec(edgeLink)), codes.PermissionDenied,
		workerv1alpha1.ReasonVPCNotAuthorized)

	e.idle()
	if got := rowIDs(e.host.Rows(vpcA)); !slices.Equal(got, before) {
		t.Fatalf("rows changed from %v to %v", before, got)
	}
	if st := e.status(k); st.GetGeneration() != 2 {
		t.Fatalf("generation after replays = %d, want 2", st.GetGeneration())
	}
}
