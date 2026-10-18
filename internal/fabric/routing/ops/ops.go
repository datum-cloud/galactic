// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ops implements the fabric routing operator workflows: releases
// and emergency withdrawals, source moves and handoffs, suspension,
// rebinding, moving a router to another node, and the fleet status. Each
// writes only the fields the workflow owns, through the API, where the
// CRDs' admission rules hold it to the activation contract; none writes
// FRR or a node's status.
package ops

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/fabric/routing/rollout"
)

// RecoveryVerifiedAnnotation is the rollout manager's annotation an
// operator sets to release a failed release whose routers cannot recover
// by themselves.
const RecoveryVerifiedAnnotation = "galactic.datumapis.com/recovery-verified-by"

// ReleaseSpec is what a release authorizes.
type ReleaseSpec struct {
	Namespace     string
	Name          string
	RoutingDomain string
	// FleetReleaseID defaults to Name.
	FleetReleaseID string
	FleetSequence  int64
	// Deployments are the deployments to promote, each to its current
	// candidate revision. Empty means every deployment on the CRD source
	// whose candidate differs from what it runs.
	Deployments []string
	// Withdraw makes the release an emergency withdrawal of these
	// prefixes.
	Withdraw []string
	// Retire decommissions every named router with this promotion, for
	// good. It needs Deployments.
	Retire bool
	// StartWithin bounds when the release may start; zero leaves it open.
	StartWithin time.Duration
}

// ErrNothingToRelease is a release that would promote nothing.
var ErrNothingToRelease = errors.New("no deployment has a candidate to release")

// BuildRelease reads the deployments and their candidate revisions and
// returns the release authorization for them, without creating it. Every
// target must be on the CRD source, not suspended, and have a candidate
// revision that exists.
func BuildRelease(ctx context.Context, c client.Client, spec ReleaseSpec,
	now time.Time) (*networkv1alpha1.FabricReleaseAuthorization, error) {
	if spec.Retire && len(spec.Deployments) == 0 {
		// Retirement cannot be undone, so it never applies to the fleet.
		return nil, errors.New("name the deployments to retire")
	}
	deps, err := deploymentsFor(ctx, c, spec.Namespace, spec.Deployments)
	if err != nil {
		return nil, err
	}
	auth := &networkv1alpha1.FabricReleaseAuthorization{
		TypeMeta: metav1.TypeMeta{
			APIVersion: networkv1alpha1.GroupVersion.String(), Kind: "FabricReleaseAuthorization",
		},
		ObjectMeta: metav1.ObjectMeta{Namespace: spec.Namespace, Name: spec.Name},
		Spec: networkv1alpha1.FabricReleaseAuthorizationSpec{
			Type:           networkv1alpha1.FabricReleaseTypeRelease,
			RoutingDomain:  spec.RoutingDomain,
			FleetReleaseID: spec.FleetReleaseID,
			FleetSequence:  spec.FleetSequence,
		},
	}
	if auth.Spec.FleetReleaseID == "" {
		auth.Spec.FleetReleaseID = spec.Name
	}
	if len(spec.Withdraw) > 0 {
		auth.Spec.Type = networkv1alpha1.FabricReleaseTypeEmergencyWithdrawal
		auth.Spec.WithdrawnPrefixes = slices.Clone(spec.Withdraw)
	}
	if spec.StartWithin > 0 {
		deadline := metav1.NewTime(now.Add(spec.StartWithin))
		auth.Spec.StartDeadline = &deadline
	}
	explicit := len(spec.Deployments) > 0
	for i := range deps {
		d := &deps[i]
		if d.Spec.CandidateRevisionRef == nil {
			if explicit {
				return nil, fmt.Errorf("deployment %s has no candidate revision", d.Name)
			}
			continue
		}
		rev := &networkv1alpha1.FabricRouterRevision{}
		key := types.NamespacedName{Namespace: d.Namespace, Name: d.Spec.CandidateRevisionRef.Name}
		if err := c.Get(ctx, key, rev); err != nil {
			if apierrors.IsNotFound(err) && !explicit {
				continue
			}
			return nil, fmt.Errorf("deployment %s's candidate revision %s: %w", d.Name, key.Name, err)
		}
		runs := d.Spec.ActiveRevisionRef != nil && d.Spec.ActiveRevisionRef.Name == rev.Name &&
			d.Spec.ActivationDependencyDigest == rev.Spec.ActivationDependencyDigest
		if runs && !explicit {
			continue
		}
		target := networkv1alpha1.FabricReleaseTarget{
			Deployment: d.Name, DeploymentUID: string(d.UID),
			Revision: rev.Name, ActivationDependencyDigest: rev.Spec.ActivationDependencyDigest,
			Retire: spec.Retire,
		}
		// The rollout manager fails a release on any target it cannot
		// promote, so refuse here what it would refuse there.
		if err := rollout.CheckTarget(d, rev, target); err != nil {
			if explicit {
				return nil, err
			}
			continue
		}
		auth.Spec.Deployments = append(auth.Spec.Deployments, target)
	}
	if len(auth.Spec.Deployments) == 0 {
		return nil, ErrNothingToRelease
	}
	return auth, nil
}

func deploymentsFor(ctx context.Context, c client.Client, namespace string,
	names []string) ([]networkv1alpha1.FabricRouterDeployment, error) {
	if len(names) == 0 {
		list := &networkv1alpha1.FabricRouterDeploymentList{}
		if err := c.List(ctx, list, client.InNamespace(namespace)); err != nil {
			return nil, err
		}
		slices.SortFunc(list.Items, func(a, b networkv1alpha1.FabricRouterDeployment) int {
			return strings.Compare(a.Name, b.Name)
		})
		return list.Items, nil
	}
	out := make([]networkv1alpha1.FabricRouterDeployment, 0, len(names))
	for _, n := range names {
		d := networkv1alpha1.FabricRouterDeployment{}
		if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: n}, &d); err != nil {
			return nil, fmt.Errorf("deployment %s: %w", n, err)
		}
		out = append(out, d)
	}
	return out, nil
}

// ConfirmRecovery marks a failed release's recovery verified by an
// operator, releasing its routing domain.
func ConfirmRecovery(ctx context.Context, c client.Client, namespace, name, by string) error {
	if by == "" {
		return errors.New("name who confirmed the routers are safe")
	}
	auth := &networkv1alpha1.FabricReleaseAuthorization{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, auth); err != nil {
		return err
	}
	if auth.Status.Phase != networkv1alpha1.FabricReleasePhaseFailed {
		return fmt.Errorf("release %s is %q; only a failed release needs its recovery confirmed", name,
			auth.Status.Phase)
	}
	if prev := auth.Annotations[RecoveryVerifiedAnnotation]; prev != "" {
		return fmt.Errorf("release %s's recovery was already confirmed by %s", name, prev)
	}
	return patch(ctx, c, auth, func() {
		if auth.Annotations == nil {
			auth.Annotations = map[string]string{}
		}
		auth.Annotations[RecoveryVerifiedAnnotation] = by
	})
}

// SetSource moves a deployment to source. Leaving CRD for ConfigMap names
// the node's ConfigMap, as it is now, in the handoff the agent checks.
func SetSource(ctx context.Context, c client.Client, namespace, name string,
	source networkv1alpha1.FabricConfigSource) error {
	d := &networkv1alpha1.FabricRouterDeployment{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, d); err != nil {
		return err
	}
	// A handoff the agent has not completed names the ConfigMap as it was
	// when it was asked for; running the move again names it as it is now,
	// in case it changed since.
	pending := d.Spec.Source == networkv1alpha1.FabricConfigSourceConfigMap &&
		d.Status.EffectiveSource == networkv1alpha1.FabricConfigSourceCRD
	if d.Spec.Source == source && !pending {
		return nil
	}
	var handoff *networkv1alpha1.FabricSourceHandoff
	switch {
	case d.Spec.Source == networkv1alpha1.FabricConfigSourceCRD && source == networkv1alpha1.FabricConfigSourceShadow:
		return errors.New("a node leaves CRD only for its ConfigMap")
	case d.Spec.Source == networkv1alpha1.FabricConfigSourceCRD || pending && source == d.Spec.Source:
		cm := &corev1.ConfigMap{}
		cmName := "fabric-router." + d.Spec.Target.NodeName
		if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: cmName}, cm); apierrors.IsNotFound(err) {
			return fmt.Errorf("the handoff needs node %s's ConfigMap %s; if the ConfigMap path is retired, "+
				"re-create it from the active revision and remove the configmap-retired component first: %w",
				d.Spec.Target.NodeName, cmName, err)
		} else if err != nil {
			return fmt.Errorf("the handoff needs node %s's ConfigMap %s: %w", d.Spec.Target.NodeName, cmName, err)
		}
		handoff = &networkv1alpha1.FabricSourceHandoff{
			ConfigMap:       networkv1alpha1.FabricObjectIdentity{Name: cm.Name, UID: string(cm.UID)},
			ResourceVersion: cm.ResourceVersion,
		}
	}
	return patch(ctx, c, d, func() {
		d.Spec.Source = source
		d.Spec.SourceHandoff = handoff
	})
}

// SetSuspended stops or resumes promotion of a deployment.
func SetSuspended(ctx context.Context, c client.Client, namespace, name string, suspended bool) error {
	d := &networkv1alpha1.FabricRouterDeployment{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, d); err != nil {
		return err
	}
	return patch(ctx, c, d, func() { d.Spec.Suspended = suspended })
}

// Rebind approves a deployment taking over a node whose journal is bound
// to fromUID, the deployment that was deleted or restored away.
func Rebind(ctx context.Context, c client.Client, namespace, name, fromUID, by string, now time.Time) error {
	if fromUID == "" || by == "" {
		return errors.New("name the deployment UID the journal holds and who confirmed it is gone")
	}
	d := &networkv1alpha1.FabricRouterDeployment{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, d); err != nil {
		return err
	}
	if string(d.UID) == fromUID {
		return fmt.Errorf("deployment %s is UID %s already; nothing to rebind", name, fromUID)
	}
	return patch(ctx, c, d, func() {
		d.Spec.Rebind = &networkv1alpha1.FabricRebind{FromDeploymentUID: fromUID, ApprovedBy: by,
			ApprovedAt: metav1.NewTime(now)}
	})
}

// Move retargets a deployment to another Node, recording that the Node it
// leaves was fenced from the fabric.
func Move(ctx context.Context, c client.Client, namespace, name, toNode, method, by string, now time.Time) error {
	if method == "" || by == "" {
		return errors.New("say how the old node was fenced and who confirmed it")
	}
	d := &networkv1alpha1.FabricRouterDeployment{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, d); err != nil {
		return err
	}
	if rollout.Busy(d) {
		return fmt.Errorf("deployment %s is activating epoch %d; move it once that finishes", name,
			d.Spec.ActivationEpoch)
	}
	node := &metav1.PartialObjectMetadata{}
	node.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Node"))
	if err := c.Get(ctx, types.NamespacedName{Name: toNode}, node); err != nil {
		return fmt.Errorf("node %s: %w", toNode, err)
	}
	if string(node.UID) == d.Spec.Target.NodeUID {
		return fmt.Errorf("deployment %s already targets node %s", name, toNode)
	}
	old := d.Spec.Target.NodeUID
	return patch(ctx, c, d, func() {
		d.Spec.Fence = &networkv1alpha1.FabricFence{NodeUID: old, Method: method, FencedBy: by,
			FencedAt: metav1.NewTime(now)}
		d.Spec.Target = networkv1alpha1.FabricNodeIdentity{NodeName: toNode, NodeUID: string(node.UID)}
	})
}

// patch applies edit to obj and writes it with optimistic locking, so an
// edit never overwrites a change made since obj was read.
func patch(ctx context.Context, c client.Client, obj client.Object, edit func()) error {
	before, ok := obj.DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("%T cannot be copied", obj)
	}
	edit()
	return c.Patch(ctx, obj, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
}
