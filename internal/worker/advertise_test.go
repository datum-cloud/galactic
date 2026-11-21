// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"google.golang.org/grpc/metadata"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/worker/hostscope"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/module/fake"
	"go.datum.net/galactic/internal/worker/sources"
)

// proxySA is an Envoy galactic-vrf sidecar's ServiceAccount.
const proxySA = "envoy/galactic-vrf"

func init() {
	testCaps[proxySA] = []string{workerv1alpha1.CapabilityLocalSocket, workerv1alpha1.CapabilityFabricSRv6}
}

// advertisingHost is a fakeHostState that also publishes advertisements,
// keyed by VPC and attachment UID.
type advertisingHost struct {
	*fakeHostState
	amu sync.Mutex
	ads map[string]map[string]hostscope.Advertisement
}

func (h *advertisingHost) Advertise(_ context.Context, vpc string, want []hostscope.Advertisement) error {
	h.amu.Lock()
	defer h.amu.Unlock()
	m := map[string]hostscope.Advertisement{}
	for _, a := range want {
		m[a.AttachmentUID] = a
	}
	if len(m) == 0 {
		delete(h.ads, vpc)
	} else {
		h.ads[vpc] = m
	}
	return nil
}

func (h *advertisingHost) Current(_ context.Context, vpc string, want []hostscope.Advertisement) (bool, error) {
	h.amu.Lock()
	defer h.amu.Unlock()
	have := h.ads[vpc]
	if len(have) != len(want) {
		return false, nil
	}
	for _, a := range want {
		got, ok := have[a.AttachmentUID]
		if !ok || got.PodUID != a.PodUID || !slices.Equal(got.Addresses, a.Addresses) {
			return false, nil
		}
	}
	return true, nil
}

// pod returns the pod the advertisement of att in vpc names, and whether it
// exists.
func (h *advertisingHost) pod(vpc, att string) (string, bool) {
	h.amu.Lock()
	defer h.amu.Unlock()
	a, ok := h.ads[vpc][att]
	return a.PodUID, ok
}

// TestSocketClaimAdvertisesItsAddresses checks the return path Worker gives
// a socket claim: the Local module gets the claim even when every destination
// resolves to Fabric, since its routed link carries every reply; the claim's
// addresses are advertised for the pod it serves; a move to the owner's new
// pod rewrites the advertisement; a gone pod withdraws it; and a release
// withdraws it, leaving another VPC's advertisement alone.
func TestSocketClaimAdvertisesItsAddresses(t *testing.T) {
	e, h := hostEnv(t)
	ah := &advertisingHost{fakeHostState: h, ads: map[string]map[string]hostscope.Advertisement{}}
	e.hostState = ah
	gw := netip.MustParseAddr("2001:db8:ff::1")
	for _, a := range []sources.Attachment{
		{UID: svcA, VPC: vpcA, Node: node, Addresses: []netip.Addr{gw}},
		{UID: svcB, VPC: vpcB, Node: node, Addresses: []netip.Addr{gw}},
	} {
		a.Kind, a.Admitted = sources.KindVPCAttachment, true
		e.src.SetAttachment(a)
	}
	hm := &handoffModule{pods: map[module.ClaimKey]string{}}
	e.modules = func(fh *fake.Host) []module.Module {
		hm.Module = fake.New("local", workerv1alpha1.Mode_MODE_LOCAL, fh)
		return []module.Module{hm, fake.New("fabric", workerv1alpha1.Mode_MODE_FABRIC, fh)}
	}
	var mu sync.Mutex
	alive := map[string]bool{podOne: true}
	setAlive := func(pod string, v bool) {
		mu.Lock()
		defer mu.Unlock()
		alive[pod] = v
	}
	e.podAlive = func(uid string) bool {
		mu.Lock()
		defer mu.Unlock()
		return alive[uid]
	}
	e.start()

	fromPod := func(pod string, k *workerv1alpha1.ClaimKey, gen uint64, dest string) error {
		ctx := metadata.AppendToOutgoingContext(e.ctx(proxySA), podMD, pod)
		_, err := e.api.Request(ctx, &workerv1alpha1.RequestRequest{Key: k, Generation: gen,
			Spec: spec(workerv1alpha1.Handoff_HANDOFF_SOCKET, dest)})
		return err
	}
	// guest-a2 is on the other node, so the claim's only destination is
	// Fabric's.
	e.mustOK(fromPod(podOne, key(vpcA, svcA), 1, "guest-a2"))
	e.mustOK(fromPod(podOne, key(vpcB, svcB), 1, "guest-b1"))
	e.eventually("the Local module planned the Fabric-only socket claim", func() bool {
		return hm.pod(mkey(vpcA, svcA)) == podOne
	})
	e.eventually("both claims advertised for pod-1", func() bool {
		a, okA := ah.pod(vpcA, svcA)
		b, okB := ah.pod(vpcB, svcB)
		return okA && okB && a == podOne && b == podOne
	})

	// The proxy pod is replaced: while pod-1 is gone and the owner has not
	// called back, nothing is advertised for VPC A's claim.
	setAlive(podOne, false)
	setAlive("pod-2", true)
	e.w.Changed(vpcA)
	e.eventually("the advertisement of a claim whose pod is gone is withdrawn", func() bool {
		_, ok := ah.pod(vpcA, svcA)
		return !ok
	})
	e.mustOK(fromPod("pod-2", key(vpcA, svcA), 1, "guest-a2"))
	e.eventually("the advertisement follows the claim to pod-2", func() bool {
		p, ok := ah.pod(vpcA, svcA)
		return ok && p == "pod-2"
	})

	// Releasing VPC A's claim withdraws only its advertisement.
	_, err := e.api.Release(e.ctx(proxySA), &workerv1alpha1.ReleaseRequest{Key: key(vpcA, svcA), Generation: 1})
	e.mustOK(err)
	e.waitGone(mkey(vpcA, svcA))
	e.eventually("the released claim's advertisement is withdrawn", func() bool {
		_, ok := ah.pod(vpcA, svcA)
		return !ok
	})
	if _, ok := ah.pod(vpcB, svcB); !ok {
		t.Fatal("releasing VPC A's claim withdrew VPC B's advertisement")
	}
}

// TestAdvertisementOfAVPCWithoutVRFIsWithdrawn removes an advertisement Worker
// left for a VPC that has neither claims nor a host VRF any more, before
// forgetting the VPC: nothing would requeue it afterwards.
func TestAdvertisementOfAVPCWithoutVRFIsWithdrawn(t *testing.T) {
	e, h := hostEnv(t)
	ah := &advertisingHost{fakeHostState: h, ads: map[string]map[string]hostscope.Advertisement{
		vpcB: {svcB: {AttachmentUID: svcB, PodUID: podOne, Addresses: []netip.Addr{netip.MustParseAddr("2001:db8:ff::1")}}},
	}}
	e.hostState = ah
	e.start()
	e.w.HostChanged(vpcB)
	e.eventually("the advertisement of a VPC with no VRF is withdrawn", func() bool {
		_, ok := ah.pod(vpcB, svcB)
		return !ok
	})
}

// TestConnectorClaimsAreNotAdvertised leaves a connector claim's addresses to
// the edge route's own advertisement (D37).
func TestConnectorClaimsAreNotAdvertised(t *testing.T) {
	w := &Worker{}
	addr := []netip.Addr{netip.MustParseAddr("2001:db8:ff::1")}
	got := w.wantAdvertisements([]module.Claim{
		{Key: mkey(vpcA, svcA), Handoff: workerv1alpha1.Handoff_HANDOFF_SOCKET, OwnerPod: podOne, Addresses: addr},
		{Key: mkey(vpcA, "edge-1"), Handoff: workerv1alpha1.Handoff_HANDOFF_ROUTED_LINK, OwnerPod: podOne,
			Addresses: addr, EdgeLink: &module.EdgeLink{Name: "edge0", Address: addr[0]}},
	})
	if len(got) != 1 || got[0].AttachmentUID != svcA {
		t.Fatalf("advertisements = %+v, want only the socket claim's", got)
	}
}
