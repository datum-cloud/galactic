/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	ipamv1alpha1 "go.miloapis.com/ipam/pkg/apis/ipam/v1alpha1"
	"go.miloapis.com/ipam/pkg/ipamerrors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	"go.datum.net/galactic/internal/cloud/fabricidentity"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

const (
	testNetworkName = "prod"
	testNamespace   = "ns-project"
	testNetworkUID  = "11111111-1111-1111-1111-111111111111"
	testClass       = "datum-fabric-identity"
)

// fakeIdentityIPAM stands in for the address service. Allocation is synchronous
// there, so the create response already carries the block.
type fakeIdentityIPAM struct {
	client client.Client
	// next is the index the pool hands out. A correctly provisioned identifier
	// pool holds its own first block back, because a network handed index zero
	// reads as one holding no identity at all.
	next int
	// created records every claim name the factory was asked to bind.
	created []string
	// retained maps an allocation name to the block it still holds after its
	// claim was deleted under Retain. It is what makes a second claim of the
	// same name a conflict rather than a fresh allocation.
	retained map[string]string
}

func allocationNameFor(claimName string) string { return "alloc-" + claimName }

// refuseWhatTheServerWouldRefuse mirrors the address service's own admission of
// a claim. The fake would otherwise bind anything, which is how a claim that no
// real server has ever accepted passed every test here.
//
// Only the part this depends on is modelled: the server bounds a claim's prefix
// length by the family stated on the claim, before it looks at the class, so an
// identity block asked for without a family is read as an IPv4 length.
func refuseWhatTheServerWouldRefuse(ipClaim *ipamv1alpha1.IPClaim) error {
	if ipClaim.Spec.ClassName == "" && ipClaim.Spec.IPFamily == "" {
		return apierrors.NewInvalid(
			ipamv1alpha1.SchemeGroupVersion.WithKind("IPClaim").GroupKind(), ipClaim.Name,
			field.ErrorList{field.Required(field.NewPath("spec"),
				"one of className or ipFamily is required")})
	}
	if p := ipClaim.Spec.PrefixLength; p != nil {
		maxLen := int32(32)
		if ipClaim.Spec.IPFamily == ipamv1alpha1.IPv6 {
			maxLen = 128
		}
		if *p <= 0 || *p > maxLen {
			return apierrors.NewInvalid(
				ipamv1alpha1.SchemeGroupVersion.WithKind("IPClaim").GroupKind(), ipClaim.Name,
				field.ErrorList{field.Invalid(field.NewPath("spec", "prefixLength"), *p,
					fmt.Sprintf("must be between 1 and %d", maxLen))})
		}
	}
	return nil
}

func newFakeIdentityIPAM(t *testing.T) *fakeIdentityIPAM {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := ipamv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("build the IPAM scheme: %v", err)
	}

	f := &fakeIdentityIPAM{next: 1, retained: map[string]string{}}
	f.client = fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			ipClaim, ok := obj.(*ipamv1alpha1.IPClaim)
			if !ok {
				return c.Create(ctx, obj, opts...)
			}
			f.created = append(f.created, ipClaim.Name)

			if err := refuseWhatTheServerWouldRefuse(ipClaim); err != nil {
				return err
			}

			// An allocation left behind by a deleted claim blocks the name it
			// used, which is exactly what retention is for.
			allocationName := allocationNameFor(ipClaim.Name)
			if _, held := f.retained[allocationName]; held {
				return ipamerrors.NewRetainedAllocation(
					ipamv1alpha1.SchemeGroupVersion.WithResource("ipclaims").GroupResource(),
					ipClaim.Name, allocationName,
					"an allocation under this identity already exists, retained by an earlier claim of the same name")
			}

			index := f.next
			f.next++
			ipClaim.Status.Phase = ipamv1alpha1.ClaimBound
			ipClaim.Status.AllocatedCIDR = blockForIndex(index)
			return c.Create(ctx, obj, opts...)
		},
	}).Build()
	return f
}

// blockForIndex renders the block a pool rooted at fc00::/32 hands out for an
// index, which is what the identity is read back out of.
func blockForIndex(index int) string {
	return "fc00:0:" + hex16(index>>16) + ":" + hex16(index&0xffff) + "::/64"
}

func hex16(v int) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0"
	}
	out := ""
	for v > 0 {
		out = string(digits[v&0xf]) + out
		v >>= 4
	}
	return out
}

// release models a claim deleted under Retain: the claim goes, the allocation
// stays, and the block it holds becomes readable through the allocation.
func (f *fakeIdentityIPAM) release(t *testing.T, ctx context.Context, claimName string) {
	t.Helper()
	var ipClaim ipamv1alpha1.IPClaim
	if err := f.client.Get(ctx, client.ObjectKey{Namespace: "default", Name: claimName}, &ipClaim); err != nil {
		t.Fatalf("read the claim being released: %v", err)
	}

	allocation := &ipamv1alpha1.IPAllocation{}
	allocation.Namespace = "default"
	allocation.Name = allocationNameFor(claimName)
	allocation.Status.AllocatedCIDR = ipClaim.Status.AllocatedCIDR
	if err := f.client.Create(ctx, allocation); err != nil {
		t.Fatalf("retain the allocation: %v", err)
	}
	if err := f.client.Delete(ctx, &ipClaim); err != nil {
		t.Fatalf("delete the claim: %v", err)
	}
	f.retained[allocation.Name] = ipClaim.Status.AllocatedCIDR
}

func (f *fakeIdentityIPAM) ClientForPlatform() (client.Client, error) { return f.client, nil }
func (f *fakeIdentityIPAM) ClientForProject(string) (client.Client, error) {
	return nil, errors.New("a fabric identity is never drawn from a consumer's project")
}

type identityFixture struct {
	t          *testing.T
	ctx        context.Context
	networks   client.Client
	hub        client.Client
	ipam       *fakeIdentityIPAM
	reconciler *NetworkFabricIdentityReconciler
	network    *networkingv1alpha.Network
}

func newIdentityFixture(t *testing.T, presences ...string) *identityFixture {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := networkingv1alpha.AddToScheme(scheme); err != nil {
		t.Fatalf("build the networking scheme: %v", err)
	}
	if err := cloudv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("build the cloud scheme: %v", err)
	}
	scheme.AddKnownTypeWithName(clusterPropagationPolicyGVK, &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(clusterPropagationPolicyGVK.GroupVersion().WithKind("ClusterPropagationPolicyList"),
		&unstructured.UnstructuredList{})

	network := &networkingv1alpha.Network{}
	network.Namespace = testNamespace
	network.Name = testNetworkName
	network.UID = types.UID(testNetworkUID)

	objects := make([]client.Object, 0, 1+len(presences))
	objects = append(objects, network)
	for _, location := range presences {
		presence := &networkingv1alpha.NetworkContext{}
		presence.Namespace = testNamespace
		presence.Name = testNetworkName + "-" + location
		presence.Spec.Network = networkingv1alpha.LocalNetworkRef{Name: testNetworkName}
		presence.Spec.Location.Name = location
		objects = append(objects, presence)
	}

	networks := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	hub := fake.NewClientBuilder().WithScheme(scheme).Build()
	ipam := newFakeIdentityIPAM(t)

	return &identityFixture{
		t:        t,
		ctx:      context.Background(),
		networks: networks,
		hub:      hub,
		ipam:     ipam,
		reconciler: &NetworkFabricIdentityReconciler{
			Networks:          networks,
			Hub:               hub,
			IPAM:              ipam,
			IdentityClass:     testClass,
			IdentityNamespace: "default",
		},
		network: network,
	}
}

func (f *identityFixture) deletePresence(location string) {
	f.t.Helper()
	if err := f.networks.Delete(f.ctx, newPresence(location)); err != nil {
		f.t.Fatalf("delete the presence: %v", err)
	}
}

func (f *identityFixture) deleteNetwork() {
	f.t.Helper()
	network := &networkingv1alpha.Network{}
	network.Namespace = testNamespace
	network.Name = testNetworkName
	if err := f.networks.Delete(f.ctx, network); err != nil {
		f.t.Fatalf("delete the network: %v", err)
	}
}

// addNetwork declares a second network alongside the fixture's own, with a
// presence in each location named.
func (f *identityFixture) addNetwork(name string, locations ...string) {
	f.t.Helper()
	network := &networkingv1alpha.Network{}
	network.Namespace = testNamespace
	network.Name = name
	if err := f.networks.Create(f.ctx, network); err != nil {
		f.t.Fatalf("create network %q: %v", name, err)
	}
	for _, location := range locations {
		presence := &networkingv1alpha.NetworkContext{}
		presence.Namespace = testNamespace
		presence.Name = name + "-" + location
		presence.Spec.Network = networkingv1alpha.LocalNetworkRef{Name: name}
		presence.Spec.Location.Name = location
		if err := f.networks.Create(f.ctx, presence); err != nil {
			f.t.Fatalf("declare the presence of %q in %q: %v", name, location, err)
		}
	}
}

func (f *identityFixture) createNetwork() {
	f.t.Helper()
	network := &networkingv1alpha.Network{}
	network.Namespace = testNamespace
	network.Name = testNetworkName
	if err := f.networks.Create(f.ctx, network); err != nil {
		f.t.Fatalf("create the network: %v", err)
	}
}

func (f *identityFixture) reconcile() {
	f.t.Helper()
	_, err := f.reconciler.Reconcile(f.ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testNetworkName},
	})
	if err != nil {
		f.t.Fatalf("reconcile: %v", err)
	}
}

func (f *identityFixture) published() (*cloudv1alpha1.NetworkFabricIdentity, bool) {
	f.t.Helper()
	var identity cloudv1alpha1.NetworkFabricIdentity
	err := f.hub.Get(f.ctx, client.ObjectKey{Namespace: testNamespace, Name: testNetworkName}, &identity)
	if err != nil {
		return nil, false
	}
	return &identity, true
}

// placement reads the locations off the identity itself, which is what the
// per-location policies select on.
func (f *identityFixture) placement() ([]string, bool) {
	f.t.Helper()
	identity, ok := f.published()
	if !ok {
		return nil, false
	}
	locations := make([]string, 0, len(identity.Labels))
	for key, value := range identity.Labels {
		if strings.HasPrefix(key, fabricIdentityLocationLabelPrefix) && value == "true" {
			locations = append(locations, strings.TrimPrefix(key, fabricIdentityLocationLabelPrefix))
		}
	}
	sort.Strings(locations)
	return locations, len(locations) > 0
}

// policyFor reads the one policy that carries one identity to every location
// it is required at. There is one of these per network, not per location.
func (f *identityFixture) policyFor(networkName string) (*unstructured.Unstructured, bool) {
	f.t.Helper()
	policy := &unstructured.Unstructured{}
	policy.SetGroupVersionKind(clusterPropagationPolicyGVK)
	key := client.ObjectKey{Name: FabricIdentityPolicyName(testNamespace, networkName)}
	if err := f.hub.Get(f.ctx, key, policy); err != nil {
		return nil, false
	}
	return policy, true
}

// placementLocations reads the locations a policy places its identity on.
func placementLocations(t *testing.T, policy *unstructured.Unstructured) []string {
	t.Helper()
	expressions, _, err := unstructured.NestedSlice(policy.Object,
		"spec", "placement", "clusterAffinity", "labelSelector", "matchExpressions")
	if err != nil || len(expressions) != 1 {
		t.Fatalf("expected one placement expression, got %v (%v)", expressions, err)
	}
	expression, _ := expressions[0].(map[string]any)
	if key, _, _ := unstructured.NestedString(expression, "key"); key != servingLocationTopologyLabel {
		t.Fatalf("placement must select the label a cell claims its location with, got %q", key)
	}
	if op, _, _ := unstructured.NestedString(expression, "operator"); op != "In" {
		t.Fatalf("placement must match any of the locations, got operator %q", op)
	}
	values, _, _ := unstructured.NestedStringSlice(expression, "values")
	sort.Strings(values)
	return values
}

// The identity is published on a cloud object, not on the Network. Nothing a
// consumer reads carries it.
func TestIdentityIsPublishedOnItsOwnObject(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1")
	f.reconcile()

	identity, ok := f.published()
	if !ok {
		t.Fatal("the identity must be published")
	}
	if identity.Spec.Identity == 0 {
		t.Fatal("a published identity is never zero")
	}
	if identity.Spec.NetworkRef.Name != testNetworkName {
		t.Fatalf("the identity must name the network it belongs to, got %+v", identity.Spec.NetworkRef)
	}
	if len(f.ipam.created) != 1 || f.ipam.created[0] != fabricidentity.ClaimName(testNamespace, testNetworkName) {
		t.Fatalf("the identity must be claimed from the platform tenancy under the network's UID, got %v", f.ipam.created)
	}
}

// One network, one identity, however many times it is reconciled.
func TestIdentityIsAllocatedOnlyOnce(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1")
	f.reconcile()

	first, _ := f.published()
	for range 3 {
		f.reconcile()
	}
	again, _ := f.published()

	if first.Spec.Identity != again.Spec.Identity {
		t.Fatalf("the identity moved from %d to %d", first.Spec.Identity, again.Spec.Identity)
	}
	if len(f.ipam.created) != 1 {
		t.Fatalf("a network already holding an identity must not ask for another, got %v", f.ipam.created)
	}
}

// Two networks are two identities. One shared between them would make them one
// network on the fabric: each would import the other's routes.
func TestEachNetworkGetsItsOwnIdentity(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1")
	f.reconcile()
	first, _ := f.published()

	f.addNetwork("staging", "us-central-1")
	if _, err := f.reconciler.Reconcile(f.ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: "staging"},
	}); err != nil {
		t.Fatalf("reconcile the second network: %v", err)
	}

	var second cloudv1alpha1.NetworkFabricIdentity
	if err := f.hub.Get(f.ctx, client.ObjectKey{Namespace: testNamespace, Name: "staging"}, &second); err != nil {
		t.Fatalf("the second network must be published too: %v", err)
	}
	if first.Spec.Identity == second.Spec.Identity {
		t.Fatal("two networks must not share an identity")
	}
}

// Placement follows the presences: the identity reaches exactly the cells
// backing the network's NetworkContexts, and no others.
func TestIdentityIsPlacedOnTheCellsTheNetworkIsRequiredIn(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1", "us-east-1")
	f.reconcile()

	locations, placed := f.placement()
	if !placed {
		t.Fatal("a network required somewhere must be placed there")
	}
	if len(locations) != 2 || locations[0] != "us-central-1" || locations[1] != "us-east-1" {
		t.Fatalf("expected both locations, got %v", locations)
	}
}

// A network that exists is a network with an identity, whether or not anything
// has asked for it in a location yet. It is placed nowhere until something
// does, so no cell carries a value it has no use for, but the value is settled
// before the first context appears rather than while one is waiting on it.
func TestANetworkRequiredNowhereStillHasAnIdentity(t *testing.T) {
	f := newIdentityFixture(t)
	f.reconcile()

	published, ok := f.published()
	if !ok {
		t.Fatal("a network that exists must have an identity")
	}
	if published.Spec.Identity == 0 {
		t.Fatal("an identity of zero reads as a network holding none")
	}
	if _, placed := f.placement(); placed {
		t.Fatal("nothing requires it anywhere, so nothing should carry it")
	}

	// Again, to prove it settles rather than drawing a second value.
	f.reconcile()
	again, ok := f.published()
	if !ok {
		t.Fatal("a second pass must not collect it")
	}
	if again.Spec.Identity != published.Spec.Identity {
		t.Fatalf("the identity must not move, got %d then %d", published.Spec.Identity, again.Spec.Identity)
	}
	if len(f.ipam.created) != 1 {
		t.Fatalf("exactly one claim for one network, got %v", f.ipam.created)
	}
}

// The last presence going withdraws the placement and nothing else. The
// network still exists, so it keeps the identity the fabric knows it by, and
// the next location it reaches is given that value straight away instead of
// waiting on an allocation.
func TestLastPresenceWithdrawsThePlacementButKeepsTheIdentity(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1")
	f.reconcile()

	before, ok := f.published()
	if !ok {
		t.Fatal("expected an identity to start from")
	}

	f.deletePresence("us-central-1")
	f.reconcile()

	kept, ok := f.published()
	if !ok {
		t.Fatal("the network still exists, so it must keep its identity")
	}
	if _, placed := f.placement(); placed {
		t.Fatal("nothing requires it anywhere, so nothing should carry it")
	}
	if kept.Spec.Identity != before.Spec.Identity {
		t.Fatalf("the identity must not move, got %d then %d", before.Spec.Identity, kept.Spec.Identity)
	}

	if err := f.networks.Create(f.ctx, newPresence("us-central-1")); err != nil {
		t.Fatalf("declare the presence again: %v", err)
	}
	f.reconcile()

	after, ok := f.published()
	if !ok {
		t.Fatal("the identity must still be there when the network is required again")
	}
	if after.Spec.Identity != before.Spec.Identity {
		t.Fatalf("the same network must keep the same identity, got %d then %d",
			before.Spec.Identity, after.Spec.Identity)
	}
	if len(f.ipam.created) != 1 {
		t.Fatalf("a presence coming and going must not draw again, got %v", f.ipam.created)
	}
}

// The network going is what collects the object. It is the one signal that
// separates a network that is gone from one that is required nowhere right
// now, and it is the only thing this acts on.
//
// The allocation itself is retained: a Route Target still installed in a remote
// location would merge a new network into a dead one's routes.
func TestTheNetworkGoingCollectsTheObjectButNotTheAllocation(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1")
	f.reconcile()

	before, ok := f.published()
	if !ok {
		t.Fatal("expected an identity to start from")
	}

	f.deleteNetwork()
	f.reconcile()

	if _, ok := f.published(); ok {
		t.Fatal("the network is gone, so the object should be collected")
	}

	// A network of the same name comes back. It must come back with the
	// identity the name always had, because the claim was retained and is named
	// from the network's namespace and name.
	f.createNetwork()
	f.reconcile()

	after, ok := f.published()
	if !ok {
		t.Fatal("the identity must be republished when the network comes back")
	}
	if after.Spec.Identity != before.Spec.Identity {
		t.Fatalf("a retained allocation must give back the same identity, got %d then %d",
			before.Spec.Identity, after.Spec.Identity)
	}
}

// A network that cannot be read is not a network that is gone. Nothing may be
// collected on the strength of a failed read, because collecting takes the
// value a live VRF is named from with it.
func TestAnUnreadableNetworkCollectsNothing(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1")
	f.reconcile()

	before, ok := f.published()
	if !ok {
		t.Fatal("expected an identity to start from")
	}

	f.reconciler.Networks = failingGetter{Client: f.networks}
	if _, err := f.reconciler.Reconcile(f.ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testNetworkName},
	}); err == nil {
		t.Fatal("an unreadable network must be an error, never a collection")
	}

	f.reconciler.Networks = f.networks
	after, ok := f.published()
	if !ok {
		t.Fatal("a failed read must not collect the identity")
	}
	if after.Spec.Identity != before.Spec.Identity {
		t.Fatalf("the identity must be left exactly as it was, got %d then %d",
			before.Spec.Identity, after.Spec.Identity)
	}
	if _, placed := f.placement(); !placed {
		t.Fatal("a failed read must not withdraw the placement either")
	}
}

// failingGetter stands in for a control plane that cannot answer a read of the
// network itself. Every get is an error, which is the case a collection must
// never mistake for "the network is gone".
type failingGetter struct {
	client.Client
}

func (failingGetter) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("the control plane is unreachable")
}

func newPresence(location string) *networkingv1alpha.NetworkContext {
	presence := &networkingv1alpha.NetworkContext{}
	presence.Namespace = testNamespace
	presence.Name = testNetworkName + "-" + location
	presence.Spec.Network = networkingv1alpha.LocalNetworkRef{Name: testNetworkName}
	presence.Spec.Location.Name = location
	return presence
}

// One policy per identity, naming that one object and listing every location
// it is required at.
//
// Karmada binds a resource to exactly one policy. Per-location policies each
// selecting the same identity by label therefore compete for it, and only the
// winner's placement takes effect -- an identity required in two locations
// reaches one of them, silently. Naming the object is what makes that
// impossible.
func TestOnePolicyPerIdentityCarriesItToEveryLocation(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1", "us-east-1")
	f.reconcile()

	policy, ok := f.policyFor(testNetworkName)
	if !ok {
		t.Fatalf("expected a policy for %q", testNetworkName)
	}

	selectors, _, err := unstructured.NestedSlice(policy.Object, "spec", "resourceSelectors")
	if err != nil || len(selectors) != 1 {
		t.Fatalf("expected one resource selector, got %v (%v)", selectors, err)
	}
	entry, _ := selectors[0].(map[string]any)
	name, _, _ := unstructured.NestedString(entry, "name")
	namespace, _, _ := unstructured.NestedString(entry, "namespace")
	if name != testNetworkName || namespace != testNamespace {
		t.Fatalf("the policy must name the one identity it carries, got %s/%s", namespace, name)
	}
	if _, found, _ := unstructured.NestedMap(entry, "labelSelector"); found {
		t.Fatal("selecting by label is what lets two policies contend for one identity")
	}

	if locations := placementLocations(t, policy); !slices.Equal(locations, []string{"us-central-1", "us-east-1"}) {
		t.Fatalf("the policy must place on every location the network reaches, got %v", locations)
	}

	// A second network needs its own policy: one identity, one policy.
	f.addNetwork("staging", "us-central-1")
	if _, err := f.reconciler.Reconcile(f.ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: "staging"},
	}); err != nil {
		t.Fatalf("reconcile the second network: %v", err)
	}

	var policies unstructured.UnstructuredList
	policies.SetGroupVersionKind(clusterPropagationPolicyGVK.GroupVersion().WithKind("ClusterPropagationPolicyList"))
	if err := f.hub.List(f.ctx, &policies); err != nil {
		t.Fatalf("list policies: %v", err)
	}
	if len(policies.Items) != 2 {
		t.Fatalf("two networks must have two policies however many locations they reach, got %d", len(policies.Items))
	}

	// No identity may be selected by more than one policy.
	named := map[string]int{}
	for i := range policies.Items {
		selectors, _, _ := unstructured.NestedSlice(policies.Items[i].Object, "spec", "resourceSelectors")
		for _, selector := range selectors {
			entry, _ := selector.(map[string]any)
			namespace, _, _ := unstructured.NestedString(entry, "namespace")
			name, _, _ := unstructured.NestedString(entry, "name")
			named[namespace+"/"+name]++
		}
	}
	for identity, count := range named {
		if count != 1 {
			t.Fatalf("identity %s is selected by %d policies; Karmada honours only one", identity, count)
		}
	}
}

// The per-location policies this replaces select by label, so they keep
// competing for identities until they are gone.
func TestLegacyPerLocationPoliciesAreSweptAway(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1", "us-east-1")

	legacy := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{
			"resourceSelectors": []any{map[string]any{
				"apiVersion":    cloudv1alpha1.GroupVersion.String(),
				"kind":          "NetworkFabricIdentity",
				"labelSelector": map[string]any{"matchLabels": map[string]any{LocationLabel("us-central-1"): "true"}},
			}},
		},
	}}
	legacy.SetGroupVersionKind(clusterPropagationPolicyGVK)
	legacy.SetName("cloud-fabric-identity-us-central-1")
	legacy.SetLabels(map[string]string{FabricIdentityPolicyLabel: "true"})
	if err := f.hub.Create(f.ctx, legacy); err != nil {
		t.Fatalf("create the legacy policy: %v", err)
	}

	f.reconcile()
	if err := f.reconciler.sweepLegacyPlacements(f.ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	swept := &unstructured.Unstructured{}
	swept.SetGroupVersionKind(clusterPropagationPolicyGVK)
	err := f.hub.Get(f.ctx, client.ObjectKey{Name: "cloud-fabric-identity-us-central-1"}, swept)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("the legacy policy must be gone, got %v", err)
	}

	// The policy written under the new scheme is left alone.
	if _, ok := f.policyFor(testNetworkName); !ok {
		t.Fatal("the sweep must not remove a policy that names its identity")
	}
}

// Withdrawal is what tears a data plane down, so it happens only when a
// presence is positively observed to be gone.
func TestPlacementShrinksOnlyOnAnObservedDeletion(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1", "us-east-1")
	f.reconcile()

	f.deletePresence("us-east-1")
	f.reconcile()

	locations, placed := f.placement()
	if !placed {
		t.Fatal("the placement must survive one presence going")
	}
	if len(locations) != 1 || locations[0] != "us-central-1" {
		t.Fatalf("a presence that is actually gone withdraws only that cell, got %v", locations)
	}
}

// A read that failed says nothing about where the network is required. The
// placement already in force must survive it untouched.
func TestPlacementSurvivesAnUnreadablePresence(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1", "us-east-1")
	f.reconcile()

	before, placed := f.placement()
	if !placed {
		t.Fatal("expected a placement to start from")
	}

	f.reconciler.Networks = failingLister{Client: f.networks}
	if _, err := f.reconciler.Reconcile(f.ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: testNetworkName},
	}); err == nil {
		t.Fatal("an unreadable presence must be an error, never a withdrawal")
	}

	f.reconciler.Networks = f.networks
	after, placed := f.placement()
	if !placed {
		t.Fatal("the placement must not be withdrawn by a failed read")
	}
	if len(after) != len(before) || after[0] != before[0] || after[1] != before[1] {
		t.Fatalf("the placement must be left exactly as it was: %v became %v", before, after)
	}
}

// failingLister stands in for a control plane that cannot answer. Every list is
// an error, which is the case a placement must never mistake for "the network
// is required nowhere".
// A sweep that cannot delete must not stop the manager: a controller that
// refuses to start reconciles nothing, which is strictly worse than a leftover
// policy it complains about.
func TestASweepThatCannotDeleteStillStarts(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1")

	legacy := &unstructured.Unstructured{Object: map[string]any{
		"spec": map[string]any{
			"resourceSelectors": []any{map[string]any{
				"apiVersion":    cloudv1alpha1.GroupVersion.String(),
				"kind":          "NetworkFabricIdentity",
				"labelSelector": map[string]any{"matchLabels": map[string]any{LocationLabel("us-central-1"): "true"}},
			}},
		},
	}}
	legacy.SetGroupVersionKind(clusterPropagationPolicyGVK)
	legacy.SetName("cloud-fabric-identity-us-central-1")
	legacy.SetLabels(map[string]string{FabricIdentityPolicyLabel: "true"})
	if err := f.hub.Create(f.ctx, legacy); err != nil {
		t.Fatalf("create the legacy policy: %v", err)
	}

	f.reconciler.Hub = failingDeleter{Client: f.hub}
	if err := f.reconciler.sweepLegacyPlacements(f.ctx); err != nil {
		t.Fatalf("a sweep that cannot delete must not be an error, got %v", err)
	}

	// A hub it cannot even read is equally survivable.
	f.reconciler.Hub = failingLister{Client: f.hub}
	if err := f.reconciler.sweepLegacyPlacements(f.ctx); err != nil {
		t.Fatalf("a sweep that cannot read must not be an error, got %v", err)
	}
}

type failingDeleter struct {
	client.Client
}

func (failingDeleter) Delete(context.Context, client.Object, ...client.DeleteOption) error {
	return apierrors.NewForbidden(schema.GroupResource{
		Group: "policy.karmada.io", Resource: "clusterpropagationpolicies",
	}, "cloud-fabric-identity-us-central-1", errors.New("not permitted"))
}

type failingLister struct {
	client.Client
}

func (failingLister) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("the control plane is unreachable")
}

// A claim whose allocation was retained comes back through the conflict, not
// through a fresh allocation. This is a different path from the collection
// round trip: there the claim still existed and was read back, here the claim
// is gone and only the retained allocation remains.
//
// Retention is what stops a released identifier returning to the pool, where
// the allocator could hand it to any network at all. The cost is that a network
// recreated under the same name in the same namespace inherits its predecessor's
// identity, which is confined to one name in one namespace.
func TestARetainedAllocationIsAdoptedRatherThanReallocated(t *testing.T) {
	f := newIdentityFixture(t, "us-central-1")
	f.reconcile()

	before, ok := f.published()
	if !ok {
		t.Fatal("expected an identity to start from")
	}

	// The network goes: its object is collected, and its claim is released
	// under Retain, which leaves the allocation behind.
	claimName := fabricidentity.ClaimName(testNamespace, testNetworkName)
	f.ipam.release(t, f.ctx, claimName)

	f.deleteNetwork()
	f.reconcile()
	if _, ok := f.published(); ok {
		t.Fatal("the network is gone, so the object should be collected")
	}

	// A network of the same name comes back. The claim no longer exists, so the
	// allocate path runs and must hit the retained allocation.
	claimsBefore := len(f.ipam.created)
	f.createNetwork()
	f.reconcile()

	after, ok := f.published()
	if !ok {
		t.Fatal("the identity must be republished")
	}
	if after.Spec.Identity != before.Spec.Identity {
		t.Fatalf("a retained allocation must be adopted, got %d where %d was held",
			after.Spec.Identity, before.Spec.Identity)
	}
	if len(f.ipam.created) != claimsBefore+1 {
		t.Fatalf("the adopt path runs through a refused create, got %d creates then %d",
			claimsBefore, len(f.ipam.created))
	}

	// And the identity that came back is not merely the next one the pool would
	// have handed out.
	if next := blockForIndex(f.ipam.next); next == "" {
		t.Fatal("unreachable")
	}
	fresh, err := fabricidentity.FromBlock(blockForIndex(f.ipam.next))
	if err != nil {
		t.Fatalf("read the next free block: %v", err)
	}
	if after.Spec.Identity == fresh {
		t.Fatal("the identity must come from the retained allocation, not from a fresh one")
	}
}

// The watches are sourced from the hub's cache, not the manager's own, because
// the manager runs against the cluster this is scheduled on and only the leader
// election lease lives there. Wired without a hub, the controller would come up
// watching a plane that holds none of the objects it exists for and would sit
// idle rather than fail, so setup refuses instead.
func TestSetupRefusesWithoutAHubToWatch(t *testing.T) {
	reconciler := &NetworkFabricIdentityReconciler{
		IPAM:          newFakeIdentityIPAM(t),
		IdentityClass: testClass,
	}

	if err := reconciler.SetupWithManager(nil); err == nil {
		t.Fatal("a reconciler with no hub to watch must refuse to start")
	}
}
