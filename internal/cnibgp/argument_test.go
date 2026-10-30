// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package cnibgp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/intf"
)

const argTestRouter = "router-a"

// claim runs claimArgument for the test router and namespace, ignoring
// released Arguments.
func claim(k8s client.Client, name string, createdBefore bool, siblings func() ([]string, error)) (int32, bool, error) {
	return claimReleasing(k8s, name, createdBefore, siblings, func(int32) error { return nil })
}

// claimReleasing runs claimArgument with releaseArgument as its release hook.
func claimReleasing(
	k8s client.Client, name string, createdBefore bool, siblings func() ([]string, error),
	releaseArgument func(int32) error,
) (int32, bool, error) {
	ctx := context.Background()
	return claimArgument(ctx, k8s, testNamespace, argTestRouter, name, createdBefore, siblings, argTestSpec,
		releaseArgument)
}

// recordReleases returns a release hook that records each Argument it is
// given, and the slice it records into.
func recordReleases() (func(int32) error, *[]int32) {
	var released []int32
	return func(argument int32) error {
		released = append(released, argument)
		return nil
	}, &released
}

// noSiblings reports no other attachment's link in the VPC's VRF.
func noSiblings() ([]string, error) { return nil, nil }

func argTestSpec(vrfID int32) bgpv1alpha1.BGPVRFInstanceSpec {
	return buildVRFInstanceSpec(argTestRouter, testRD65000_1, vrfID)
}

// collidingArgument is the Argument the collision tests' instances share.
const collidingArgument = int32(7)

func argTestInstance(name string) *bgpv1alpha1.BGPVRFInstance {
	return &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec:       argTestSpec(collidingArgument),
	}
}

func getInstance(t *testing.T, k8s client.Client, name string) *bgpv1alpha1.BGPVRFInstance {
	t.Helper()
	inst := &bgpv1alpha1.BGPVRFInstance{}
	if err := k8s.Get(context.Background(), client.ObjectKey{Name: name, Namespace: testNamespace}, inst); err != nil {
		t.Fatalf("get BGPVRFInstance %s: %v", name, err)
	}
	return inst
}

// TestClaimArgument_ConcurrentFirstADDs runs the first ADDs of many VPCs on
// one node at once, as separate galactic-bgp processes do. Each takes the
// Argument lock, so every one succeeds with a distinct Argument.
func TestClaimArgument_ConcurrentFirstADDs(t *testing.T) {
	k8s := fakeClient()
	const vpcs = 16
	var wg sync.WaitGroup
	errs := make(chan error, vpcs)
	for i := range vpcs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := crdnames.BGPVRFInstanceName(fmt.Sprintf("v%02d", i), testNodeName)
			_, created, err := claim(k8s, name, false, noSiblings)
			if err == nil && !created {
				err = fmt.Errorf("%s: not reported created", name)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	list := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := k8s.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	seen := map[int32]string{}
	for _, inst := range list.Items {
		if prev, ok := seen[inst.Spec.VRFID]; ok {
			t.Errorf("Argument %d held by both %s and %s", inst.Spec.VRFID, prev, inst.Name)
		}
		seen[inst.Spec.VRFID] = inst.Name
	}
	if len(seen) != vpcs {
		t.Errorf("%d distinct Arguments, want %d", len(seen), vpcs)
	}
}

// racingWriter returns a client that, on this ADD's create of mine, also
// creates other with the same Argument, as a writer outside the Argument
// lock would.
func racingWriter(t *testing.T, mine, other string) client.Client {
	t.Helper()
	base := fake.NewClientBuilder().WithScheme(testScheme).Build()
	create := func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		if err := c.Create(ctx, obj, opts...); err != nil {
			return err
		}
		inst, ok := obj.(*bgpv1alpha1.BGPVRFInstance)
		if !ok || inst.Name != mine {
			return nil
		}
		return c.Create(ctx, &bgpv1alpha1.BGPVRFInstance{
			ObjectMeta: metav1.ObjectMeta{Name: other, Namespace: testNamespace},
			Spec:       argTestSpec(inst.Spec.VRFID),
		})
	}
	return interceptor.NewClient(base, interceptor.Funcs{Create: create})
}

// TestClaimArgument_ReallocatesOwnInstance has another writer take the same
// Argument as this ADD's freshly created instance. The ADD moves its own
// instance to the next free Argument rather than failing, and leaves the
// other writer's alone.
func TestClaimArgument_ReallocatesOwnInstance(t *testing.T) {
	mine := crdnames.BGPVRFInstanceName("va", testNodeName)
	other := crdnames.BGPVRFInstanceName("vb", testNodeName)
	k8s := racingWriter(t, mine, other)

	vrfID, created, err := claim(k8s, mine, false, noSiblings)
	if err != nil {
		t.Fatalf("claimArgument: %v", err)
	}
	if !created {
		t.Error("created = false, want true")
	}
	if want := int32(uformat.ArgumentMin) + 1; vrfID != want {
		t.Errorf("Argument = %d, want %d, the next free one", vrfID, want)
	}
	if got := getInstance(t, k8s, mine).Spec.VRFID; got != vrfID {
		t.Errorf("own instance holds %d, want %d", got, vrfID)
	}
	if got := getInstance(t, k8s, other).Spec.VRFID; got != int32(uformat.ArgumentMin) {
		t.Errorf("other writer's instance holds %d, want %d unchanged", got, uformat.ArgumentMin)
	}
}

// TestClaimArgument_ReusedInstanceCollisionFails reuses an existing
// instance whose Argument another instance also holds. Attachments already
// use the reused value, so the ADD fails, naming both, instead of moving it.
func TestClaimArgument_ReusedInstanceCollisionFails(t *testing.T) {
	mine := crdnames.BGPVRFInstanceName("va", testNodeName)
	other := crdnames.BGPVRFInstanceName("vb", testNodeName)
	k8s := fakeClient(
		argTestInstance(mine),
		argTestInstance(other),
	)

	_, created, err := claim(k8s, mine, false, noSiblings)
	if !errors.Is(err, errArgumentCollision) {
		t.Fatalf("claimArgument = %v, want a collision error", err)
	}
	if created {
		t.Error("created = true for a reused instance")
	}
	if got := getInstance(t, k8s, mine).Spec.VRFID; got != 7 {
		t.Errorf("reused instance moved to %d, want 7 unchanged", got)
	}
}

// TestClaimArgument_EarlierAttemptCreated retries an ADD whose earlier
// attempt created the instance: the retry sees an update, but the instance
// is still this ADD's to move.
func TestClaimArgument_EarlierAttemptCreated(t *testing.T) {
	mine := crdnames.BGPVRFInstanceName("va", testNodeName)
	other := crdnames.BGPVRFInstanceName("vb", testNodeName)
	k8s := fakeClient(
		argTestInstance(mine),
		argTestInstance(other),
	)

	vrfID, created, err := claim(k8s, mine, true, noSiblings)
	if err != nil {
		t.Fatalf("claimArgument: %v", err)
	}
	if created {
		t.Error("created = true, want false: this attempt updated")
	}
	if vrfID == 7 {
		t.Errorf("Argument stayed 7, want it moved off the collision")
	}
}

// TestClaimArgument_EarlierAttemptSiblingReused retries an ADD whose earlier
// attempt created the instance, after a sibling attachment's link joined the
// VPC's VRF. The sibling may already use the Argument, so the collision fails
// the ADD rather than moving the instance under it.
func TestClaimArgument_EarlierAttemptSiblingReused(t *testing.T) {
	mine := crdnames.BGPVRFInstanceName("va", testNodeName)
	other := crdnames.BGPVRFInstanceName("vb", testNodeName)
	k8s := fakeClient(argTestInstance(mine), argTestInstance(other))
	sibling := func() ([]string, error) { return []string{"sibling-link"}, nil }

	_, _, err := claim(k8s, mine, true, sibling)
	if !errors.Is(err, errArgumentCollision) {
		t.Fatalf("claimArgument = %v, want a collision error", err)
	}
	if got := getInstance(t, k8s, mine).Spec.VRFID; got != collidingArgument {
		t.Errorf("instance moved to %d under a sibling, want %d unchanged", got, collidingArgument)
	}
}

// TestClaimArgument_ReleasesLeftArgument retries an ADD whose earlier
// attempt created the instance and may have registered the datapath under
// its Argument before another writer took it. Moving the instance releases
// the Argument it left, so the other writer's traffic is not delivered into
// this VPC.
func TestClaimArgument_ReleasesLeftArgument(t *testing.T) {
	mine := crdnames.BGPVRFInstanceName("va", testNodeName)
	other := crdnames.BGPVRFInstanceName("vb", testNodeName)
	k8s := fakeClient(argTestInstance(mine), argTestInstance(other))
	releaseArgument, released := recordReleases()

	vrfID, _, err := claimReleasing(k8s, mine, true, noSiblings, releaseArgument)
	if err != nil {
		t.Fatalf("claimArgument: %v", err)
	}
	if vrfID == collidingArgument {
		t.Fatalf("Argument stayed %d, want it moved off the collision", collidingArgument)
	}
	if want := []int32{collidingArgument}; !slices.Equal(*released, want) {
		t.Errorf("released %v, want %v", *released, want)
	}
}

// TestClaimArgument_ReleasesNothingInPlace keeps an instance on its
// Argument, uncontested or reused under a collision, and releases nothing.
func TestClaimArgument_ReleasesNothingInPlace(t *testing.T) {
	mine := crdnames.BGPVRFInstanceName("va", testNodeName)
	other := crdnames.BGPVRFInstanceName("vb", testNodeName)
	for name, k8s := range map[string]client.Client{
		"uncontested":       fakeClient(),
		"reused, colliding": fakeClient(argTestInstance(mine), argTestInstance(other)),
	} {
		t.Run(name, func(t *testing.T) {
			releaseArgument, released := recordReleases()
			_, _, _ = claimReleasing(k8s, mine, false, noSiblings, releaseArgument)
			if len(*released) != 0 {
				t.Errorf("released %v, want nothing", *released)
			}
		})
	}
}

// TestClaimArgument_ReleaseFailureFailsClaim fails the release hook. The
// claim fails rather than leave the left Argument routed into this VPC.
func TestClaimArgument_ReleaseFailureFailsClaim(t *testing.T) {
	mine := crdnames.BGPVRFInstanceName("va", testNodeName)
	other := crdnames.BGPVRFInstanceName("vb", testNodeName)
	k8s := fakeClient(argTestInstance(mine), argTestInstance(other))
	errRelease := errors.New("release failed")

	_, _, err := claimReleasing(k8s, mine, true, noSiblings, func(int32) error { return errRelease })
	if !errors.Is(err, errRelease) {
		t.Fatalf("claimArgument = %v, want the release error", err)
	}
}

// TestLockArguments_WaitsForContext holds the Argument lock and has a second
// caller give up when its context ends, then take the lock once released.
func TestLockArguments_WaitsForContext(t *testing.T) {
	release, err := lockArguments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := lockArguments(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lockArguments while held = %v, want the context's deadline", err)
	}
	release()
	release2, err := lockArguments(context.Background())
	if err != nil {
		t.Fatalf("lockArguments after release: %v", err)
	}
	release2()
}

// withLinks substitutes links for the kernel's list of links.
func withLinks(t *testing.T, links ...netlink.Link) {
	t.Helper()
	orig := listLinksFn
	listLinksFn = func() ([]netlink.Link, error) { return links, nil }
	t.Cleanup(func() { listLinksFn = orig })
}

// TestResourceTrackerCleanup_KeepsInstanceASiblingReused rolls back an ADD
// that created the BGPVRFInstance after a sibling attachment's host link has
// joined the VPC's VRF. The sibling has reused the instance, so it is kept.
func TestResourceTrackerCleanup_KeepsInstanceASiblingReused(t *testing.T) {
	vrfLink := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: intf.GenerateInterfaceNameVRF(testVPC), Index: 10}}
	own := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{
		Name: intf.GenerateInterfaceNameHost(testVPC, testAttachment), MasterIndex: 10,
	}}
	sibling := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{
		Name: intf.GenerateInterfaceNameHost(testVPC, "ghi"), MasterIndex: 10,
	}}
	name := crdnames.BGPVRFInstanceName(testVPC, testNodeName)
	newTracker := func(k8s client.Client) *resourceTracker {
		return &resourceTracker{
			vpc: testVPC, vpcAttachment: testAttachment, nodeName: testNodeName,
			namespace: testNamespace, k8s: k8s,
			publishResult: publishResult{vrfInstanceCreated: true},
		}
	}
	instance := func() client.Object {
		return &bgpv1alpha1.BGPVRFInstance{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace}}
	}

	t.Run("a sibling's link keeps it", func(t *testing.T) {
		withLinks(t, vrfLink, own, sibling)
		k8s := fakeClient(instance())
		newTracker(k8s).cleanup(context.Background())
		getInstance(t, k8s, name)
	})

	t.Run("its own link alone does not", func(t *testing.T) {
		withLinks(t, vrfLink, own)
		k8s := fakeClient(instance())
		newTracker(k8s).cleanup(context.Background())
		err := k8s.Get(context.Background(), client.ObjectKey{Name: name, Namespace: testNamespace},
			&bgpv1alpha1.BGPVRFInstance{})
		if !apierrors.IsNotFound(err) {
			t.Fatalf("BGPVRFInstance after cleanup: %v, want it deleted", err)
		}
	})
}
