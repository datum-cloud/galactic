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
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	"go.datum.net/galactic/internal/cloud/fabricidentity"
	"go.datum.net/galactic/internal/cloud/ipam"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

const (
	labelTrue                    = "true"
	fabricIdentityKind           = "NetworkFabricIdentity"
	policySpecField              = "spec"
	policyResourceSelectorsField = "resourceSelectors"
	policyAPIVersionField        = "apiVersion"
	policyKindField              = "kind"
	policyLabelSelectorField     = "labelSelector"
	// fabricIdentityFieldManager owns every placement policy this writes.
	fabricIdentityFieldManager = "cloud-fabric-identity"

	// FabricIdentityPolicyLabel marks the placement policies this controller
	// owns, so nothing else is ever rewritten or removed by it.
	FabricIdentityPolicyLabel = "galactic.datumapis.com/fabric-identity-policy"

	// servingLocationTopologyLabel is the cluster label a cell carries to claim
	// the location it serves. Placement selects on it.
	servingLocationTopologyLabel = "topology.datum.net/location"

	// fabricIdentityLocationLabelPrefix records that an identity is required at
	// one location, with the location in the key rather than the value: a label
	// key holds one value, and one network is required in several locations at
	// once. Placement no longer selects on it -- see place -- but it stays as
	// the readable record of where an identity is needed.
	fabricIdentityLocationLabelPrefix = "galactic.datumapis.com/location-"
)

// LocationLabel is the label marking an identity as required at one location.
func LocationLabel(location string) string {
	return fabricIdentityLocationLabelPrefix + location
}

var clusterPropagationPolicyGVK = schema.GroupVersionKind{
	Group:   "policy.karmada.io",
	Version: "v1alpha1",
	Kind:    "ClusterPropagationPolicy",
}

// NetworkFabricIdentityReconciler gives each network the identity the fabric
// knows it by, once, and carries it to the locations that need it.
//
// It runs centrally, not in a cell. A network spans locations, so the one thing
// that must be the same in all of them cannot be decided in any one of them —
// which is exactly the defect this replaces, where each location drew its own
// value and two locations of one network were two networks on the fabric.
type NetworkFabricIdentityReconciler struct {
	// Networks reads the Networks identities are allocated for, and the
	// NetworkContexts saying where each one is required.
	//
	// Both arrive on the hub as copies published by the operator that owns
	// them, because reaching every consumer's project control plane needs a
	// multi-cluster provider this component does not have. A copy is a
	// different object from its source and does not carry the source's UID, so
	// nothing here reads one.
	//
	// Kept separate from Hub even though a deployment points both at the hub:
	// it is what lets a failed read be exercised on its own, and every
	// withdrawal in this controller is conditioned on a read having succeeded.
	Networks client.Client

	// Hub is where the identity and its placement are written, and from where
	// federation carries them to the cells.
	Hub client.Client

	// HubCluster is the hub as a cluster rather than a client, and is what the
	// watches are sourced from.
	//
	// The manager itself runs against the cluster this is scheduled on, not
	// against the hub. Leases on the hub would put a constant write load on a
	// control plane everything else federates through, and would tie this
	// component's leadership to that plane being reachable: a hub hiccup would
	// churn leadership and restart the controller. Keeping the lease local
	// means an unreachable hub costs this component its work, which cannot be
	// avoided, and not its identity, which can.
	HubCluster cluster.Cluster

	// IPAM reaches the identifier space.
	IPAM ipam.ClientFactory

	// IdentityClass is the IPClass that hands out identities.
	IdentityClass string

	// IdentityNamespace is the namespace in the platform's own tenancy that
	// identity claims are written to.
	IdentityNamespace string
}

// Reconcile is keyed by a network. The network decides whether the identity
// exists at all; its NetworkContexts decide only where that identity is
// carried.
//
// Reading the network is what separates "deleted" from "required nowhere". A
// network that exists but has no context anywhere keeps its identity: it is a
// network the consumer still has, and the next context to appear must find the
// value the fabric already knows it by rather than wait for one to be drawn
// again.
func (r *NetworkFabricIdentityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	network := &networkingv1alpha.Network{}
	err := r.Networks.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Name}, network)
	switch {
	case apierrors.IsNotFound(err):
		// The one thing that collects an identity.
		return ctrl.Result{}, r.collect(ctx, req.Namespace, req.Name)
	case err != nil:
		// A read that failed says nothing about whether the network is still
		// there. Changing nothing is the only safe answer.
		return ctrl.Result{}, err
	}

	// A network on its way out still has an identity, and deliberately keeps it
	// until it is actually gone. The VRF device is named from the identity and
	// the Route Target derives from it, so tearing a network down needs it as
	// much as standing it up did; collecting on the deletion timestamp would
	// pull it out from under a teardown still in flight. The cost is that a
	// network wedged on a stuck finalizer holds its object indefinitely, which
	// is a leak, and a leak is recoverable where a torn-down data plane is not.

	presences, err := r.presences(ctx, req.Namespace, req.Name)
	if err != nil {
		// A list that failed says nothing about where the network is required.
		return ctrl.Result{}, err
	}

	locations := locationsFrom(presences)

	if err := r.publish(ctx, req.Namespace, req.Name, locations); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, r.place(ctx, req.Namespace, req.Name, locations)
}

// presences reads the contexts declaring the network is required somewhere.
func (r *NetworkFabricIdentityReconciler) presences(
	ctx context.Context,
	namespace string,
	networkName string,
) ([]networkingv1alpha.NetworkContext, error) {
	var contexts networkingv1alpha.NetworkContextList
	if err := r.Networks.List(ctx, &contexts, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("read the presences of network %q: %w", networkName, err)
	}

	matching := make([]networkingv1alpha.NetworkContext, 0, len(contexts.Items))
	for i := range contexts.Items {
		presence := &contexts.Items[i]
		if presence.Spec.Network.Name != networkName {
			continue
		}
		// A presence on its way out is still a presence. The location keeps the
		// identity until the context is actually gone, because the traffic it
		// carries is still there while it drains.
		matching = append(matching, *presence)
	}
	return matching, nil
}

func locationsFrom(presences []networkingv1alpha.NetworkContext) []string {
	seen := map[string]struct{}{}
	locations := make([]string, 0, len(presences))
	for i := range presences {
		location := presences[i].Spec.Location.Name
		if location == "" {
			continue
		}
		if _, ok := seen[location]; ok {
			continue
		}
		seen[location] = struct{}{}
		locations = append(locations, location)
	}
	sort.Strings(locations)
	return locations
}

// publish allocates the identity if it does not have one yet, and marks it as
// required at each location the network reaches.
func (r *NetworkFabricIdentityReconciler) publish(
	ctx context.Context,
	namespace string,
	networkName string,
	locations []string,
) error {
	key := client.ObjectKey{Namespace: namespace, Name: networkName}

	published := &cloudv1alpha1.NetworkFabricIdentity{}
	err := r.Hub.Get(ctx, key, published)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("read the published identity for network %q: %w", networkName, err)
	}

	identity := published.Spec.Identity
	if identity == 0 {
		identity, err = r.claim(ctx, namespace, networkName)
		if err != nil {
			return err
		}
	}

	object := &cloudv1alpha1.NetworkFabricIdentity{}
	object.Namespace = key.Namespace
	object.Name = key.Name

	if _, err := controllerutil.CreateOrUpdate(ctx, r.Hub, object, func() error {
		// Never moved once set. A network that changed identity would be a
		// different network to every location already carrying its traffic, and
		// the API refuses the write in any case.
		if object.Spec.Identity == 0 {
			object.Spec.Identity = identity
		}
		object.Spec.NetworkRef = cloudv1alpha1.NetworkFabricIdentityNetworkRef{Name: networkName}
		setLocationLabels(object, locations)
		return nil
	}); err != nil {
		return fmt.Errorf("publish the fabric identity for network %q: %w", networkName, err)
	}
	return nil
}

// setLocationLabels marks the identity as required at exactly these locations.
//
// A label is dropped only because a location is absent from a set built from a
// successful read of the presences. Every failure returns before reaching here,
// so a context that was briefly unreadable, or a cell that went quiet, never
// withdraws an identity. That matters because the fabric keys a VRF on it:
// withdrawing it under live traffic tears the data plane down at that location.
func setLocationLabels(object *cloudv1alpha1.NetworkFabricIdentity, locations []string) {
	if object.Labels == nil {
		object.Labels = map[string]string{}
	}
	required := make(map[string]struct{}, len(locations))
	for _, location := range locations {
		key := LocationLabel(location)
		required[key] = struct{}{}
		object.Labels[key] = labelTrue
	}
	for key := range object.Labels {
		if !strings.HasPrefix(key, fabricIdentityLocationLabelPrefix) {
			continue
		}
		if _, ok := required[key]; !ok {
			delete(object.Labels, key)
		}
	}
}

func (r *NetworkFabricIdentityReconciler) claim(
	ctx context.Context,
	networkNamespace string,
	networkName string,
) (int64, error) {
	ipamClient, err := r.IPAM.ClientForPlatform()
	if err != nil {
		return 0, fmt.Errorf("reach the platform identifier space: %w", err)
	}

	identity, err := fabricidentity.Claim(ctx, ipamClient, fabricidentity.Request{
		ClassName:        r.IdentityClass,
		Namespace:        r.IdentityNamespace,
		NetworkNamespace: networkNamespace,
		NetworkName:      networkName,
	})
	if err != nil {
		// An unusable answer is a wait on an operator, not on the service:
		// retrying reaches the same block. Fail closed either way — a network
		// given an ambiguous identity is worse than one given none.
		var unusable *fabricidentity.UnusableError
		if errors.As(err, &unusable) {
			log.FromContext(ctx).Error(err, "the identifier space handed out a block no identity can be read from",
				"network", networkName)
		}
		return 0, fmt.Errorf("allocate a fabric identity for network %q: %w", networkName, err)
	}
	return identity, nil
}

// collect removes the published identity once the network it belongs to is
// gone.
//
// The IPAM claim is deliberately not released. A Route Target still installed
// in a remote location's import policy would silently merge a new network into
// a dead one's routes, so the allocation is retained forever and the identity
// is never reissued. Only the object goes; the per-location policies are shared
// and stay.
func (r *NetworkFabricIdentityReconciler) collect(
	ctx context.Context,
	namespace string,
	networkName string,
) error {
	object := &cloudv1alpha1.NetworkFabricIdentity{}
	object.Namespace = namespace
	object.Name = networkName

	if err := r.Hub.Delete(ctx, object); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("collect the fabric identity for network %q: %w", networkName, err)
	}
	// The policy names this one identity, so nothing else can be left holding
	// it and it would otherwise outlive the network forever.
	return r.unplace(ctx, namespace, networkName)
}

// placeLocations keeps one policy per location, not one per network.
//
// A policy per network would put the policy count on the order of the number of
// networks, and federation evaluates its policy set against candidate
// resources, so that cost is paid by everything else propagating through the
// same hub rather than by this alone. One policy per location selects every
// identity required there by label, so the object count stays per network while
// the policy count falls to the number of locations.
//
// Placing it fleet-wide is not an option: the identity is capability-like, and
// what holds it can name a network's forwarding state.
// place carries one identity to every location it is required at, with a
// single policy that names that one object.
//
// One policy per identity, not one per location: Karmada binds a resource to
// exactly one policy, so per-location policies all selecting the same identity
// by label compete for it, and only the winner's placement takes effect. An
// identity required in two locations then reaches one of them, silently, which
// is exactly the split this whole mechanism exists to prevent.
func (r *NetworkFabricIdentityReconciler) place(
	ctx context.Context,
	namespace string,
	networkName string,
	locations []string,
) error {
	if len(locations) == 0 {
		return r.unplace(ctx, namespace, networkName)
	}

	policy := &unstructured.Unstructured{Object: map[string]any{
		policySpecField: map[string]any{
			"conflictResolution": "Overwrite",
			policyResourceSelectorsField: []any{
				map[string]any{
					policyAPIVersionField: cloudv1alpha1.GroupVersion.String(),
					policyKindField:       fabricIdentityKind,
					"namespace":           namespace,
					"name":                networkName,
				},
			},
			"placement": map[string]any{
				"clusterAffinity": map[string]any{
					policyLabelSelectorField: map[string]any{
						"matchExpressions": []any{
							map[string]any{
								"key":      servingLocationTopologyLabel,
								"operator": "In",
								"values":   locationValues(locations),
							},
						},
					},
				},
			},
		},
	}}
	policy.SetGroupVersionKind(clusterPropagationPolicyGVK)
	policy.SetName(FabricIdentityPolicyName(namespace, networkName))
	policy.SetLabels(map[string]string{FabricIdentityPolicyLabel: labelTrue})

	if err := r.Hub.Patch(ctx, policy, client.Apply, //nolint:staticcheck // SA1019: the typed Apply API needs a generated ApplyConfiguration this unstructured policy has none of
		client.FieldOwner(fabricIdentityFieldManager), client.ForceOwnership); err != nil {
		return fmt.Errorf("place the fabric identity for network %q: %w", networkName, err)
	}
	return nil
}

// unplace removes the policy for an identity required nowhere. The identity
// itself stays: the next context to appear must find the value the fabric
// already knows the network by.
func (r *NetworkFabricIdentityReconciler) unplace(ctx context.Context, namespace, networkName string) error {
	policy := &unstructured.Unstructured{}
	policy.SetGroupVersionKind(clusterPropagationPolicyGVK)
	policy.SetName(FabricIdentityPolicyName(namespace, networkName))

	if err := r.Hub.Delete(ctx, policy); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("unplace the fabric identity for network %q: %w", networkName, err)
	}
	return nil
}

// sweepLegacyPlacements removes the per-location policies this controller used
// to write. They select identities by label, so they keep competing with the
// per-identity policies that replaced them for as long as they exist, and a
// resource Karmada binds to the wrong one reaches the wrong cells.
//
// Identified by shape rather than by name: a policy this controller owns whose
// selectors carry no resource name is selecting by label, which only the old
// form did.
// It is deliberately best-effort and never returns an error. It runs as a
// manager runnable, where an error stops the manager, and a leftover policy is
// a correctness problem worth logging loudly where a controller that will not
// start reconciles nothing at all.
func (r *NetworkFabricIdentityReconciler) sweepLegacyPlacements(ctx context.Context) error {
	logger := ctrl.LoggerFrom(ctx)

	var policies unstructured.UnstructuredList
	policies.SetGroupVersionKind(clusterPropagationPolicyGVK.GroupVersion().WithKind("ClusterPropagationPolicyList"))
	if err := r.Hub.List(ctx, &policies, client.MatchingLabels{FabricIdentityPolicyLabel: labelTrue}); err != nil {
		logger.Error(err, "could not read the fabric identity placement policies to sweep")
		return nil
	}

	for i := range policies.Items {
		policy := &policies.Items[i]
		if !selectsByLabel(policy) {
			continue
		}
		if err := r.Hub.Delete(ctx, policy); err != nil && !apierrors.IsNotFound(err) {
			logger.Error(err, "could not remove a legacy per-location placement policy, it will keep competing for identities",
				"policy", policy.GetName())
			continue
		}
		logger.Info("removed a legacy per-location placement policy", "policy", policy.GetName())
	}
	return nil
}

// selectsByLabel reports whether a policy selects resources without naming one.
func selectsByLabel(policy *unstructured.Unstructured) bool {
	selectors, found, err := unstructured.NestedSlice(policy.Object, policySpecField, policyResourceSelectorsField)
	if err != nil || !found || len(selectors) == 0 {
		return false
	}
	for _, entry := range selectors {
		selector, ok := entry.(map[string]any)
		if !ok {
			return false
		}
		if name, _, _ := unstructured.NestedString(selector, "name"); name == "" {
			return true
		}
	}
	return false
}

// locationValues is locations as the []any an unstructured policy needs.
func locationValues(locations []string) []any {
	values := make([]any, 0, len(locations))
	for _, location := range locations {
		values = append(values, location)
	}
	return values
}

func FabricIdentityPolicyName(namespace, networkName string) string {
	return "cloud-fabric-identity-" + namespace + "-" + networkName
}

// The manager runs locally, so what this ServiceAccount has to be able to do is
// hold a leader election lease and record events. Everything else is read and
// written on the hub under the federation credential, and is declared here
// because this role is also what an operator binds there.
//
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=networking.datumapis.com,resources=networks;networkcontexts,verbs=get;list;watch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=networkfabricidentities,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups=policy.karmada.io,resources=clusterpropagationpolicies,verbs=create;delete;get;list;patch;update;watch

// SetupWithManager registers the reconciler.
//
// The network is the primary object: it decides whether an identity exists.
// Contexts still have to wake it, because placement follows them and nothing
// else would carry the identity to a location the network has just reached.
//
// Every request is keyed by a network, never by a context, because one
// network's identity is decided from all of its contexts at once.
//
// Both watches are sourced from the hub's cache rather than the manager's own,
// because that is where the copies live. The manager's cluster holds only the
// lease.
func (r *NetworkFabricIdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.IdentityClass == "" {
		return errors.New("an identifier class is required")
	}
	if r.IPAM == nil {
		return errors.New("an identifier space is required")
	}
	if r.HubCluster == nil {
		return errors.New("a hub to watch is required")
	}

	hubCache := r.HubCluster.GetCache()

	// Once, on the leader, before anything is placed under the new scheme.
	if err := mgr.Add(manager.RunnableFunc(r.sweepLegacyPlacements)); err != nil {
		return fmt.Errorf("schedule the legacy placement sweep: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named("networkfabricidentity").
		WatchesRawSource(source.Kind(hubCache, &networkingv1alpha.Network{},
			&handler.TypedEnqueueRequestForObject[*networkingv1alpha.Network]{})).
		WatchesRawSource(source.Kind(hubCache, &networkingv1alpha.NetworkContext{},
			handler.TypedEnqueueRequestsFromMapFunc(
				func(_ context.Context, presence *networkingv1alpha.NetworkContext) []reconcile.Request {
					if presence == nil || presence.Spec.Network.Name == "" {
						return nil
					}
					return []reconcile.Request{{NamespacedName: types.NamespacedName{
						Namespace: presence.Namespace,
						Name:      presence.Spec.Network.Name,
					}}}
				}))).
		Complete(r)
}
