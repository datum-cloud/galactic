// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rollout

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// RecoveryVerifiedAnnotation marks a failed release's recovery verified,
// set by an operator who confirmed every router it touched is safe,
// when the controller cannot: a router that failed with no recovery target
// stays Degraded and never reports a recovery. Its value names who
// confirmed it.
const RecoveryVerifiedAnnotation = "galactic.datumapis.com/recovery-verified-by"

// ReleaseFinalizer keeps an outstanding release, which still blocks others
// in its routing domain, from being deleted.
const ReleaseFinalizer = "galactic.datumapis.com/release-outstanding"

// Release condition types and reasons.
const (
	ConditionProgressing = "Progressing"

	reasonWaitingForRelease = "WaitingForRelease"
	reasonSuperseded        = "Superseded"
	reasonDeadlinePassed    = "StartDeadlinePassed"
	reasonInvalidTarget     = "InvalidTarget"
	reasonPromoting         = "Promoting"
	reasonTargetFailed      = "TargetFailed"
	reasonTargetSilent      = "TargetSilent"
	reasonAllCommitted      = "AllCommitted"
	reasonRecoveryPending   = "RecoveryPending"
	reasonRecoveryVerified  = "RecoveryVerified"
)

// progressInterval is how often a release in progress is looked at again
// even without a watch event, for heartbeat timeouts.
const progressInterval = 10 * time.Second

// ReleaseReconciler runs FabricReleaseAuthorizations.
//
// It does not yet enforce a release's failureDomains, its inputManifest,
// or that an emergency withdrawal's revisions change nothing but the
// withdrawn originations; the fleet release tool checks those before it
// creates the release.
type ReleaseReconciler struct {
	client.Client
	// APIReader reads releases around the cache, so the start gate sees
	// every release that started; one worker reconciles releases, so two
	// never start in one domain. Nil uses the client.
	APIReader client.Reader
	// Recorder emits events; nil disables them.
	Recorder events.EventRecorder
	// Now reads the clock; nil is time.Now.
	Now func() time.Time
}

// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=fabricreleaseauthorizations,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=fabricreleaseauthorizations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=fabricrolloutpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=fabricreleaseauthorizations/finalizers,verbs=update

func (r *ReleaseReconciler) reader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func (r *ReleaseReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Reconcile advances one release.
func (r *ReleaseReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	auth := &networkv1alpha1.FabricReleaseAuthorization{}
	if err := r.Get(ctx, req.NamespacedName, auth); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	outstanding := auth.Status.Outstanding()
	if !auth.DeletionTimestamp.IsZero() {
		// A pending release has touched nothing and may go; one that
		// started blocks its domain until it finishes or recovers.
		if !outstanding || auth.Status.Phase == "" || auth.Status.Phase == networkv1alpha1.FabricReleasePhasePending {
			return ctrl.Result{}, r.dropFinalizer(ctx, auth)
		}
	}
	if !outstanding {
		return ctrl.Result{}, r.dropFinalizer(ctx, auth)
	}
	if !controllerutil.ContainsFinalizer(auth, ReleaseFinalizer) {
		before := auth.DeepCopy()
		controllerutil.AddFinalizer(auth, ReleaseFinalizer)
		if err := r.Patch(ctx, auth, client.MergeFromWithOptions(before,
			client.MergeFromWithOptimisticLock{})); err != nil {
			return ctrl.Result{}, err
		}
	}

	before := auth.Status.DeepCopy()
	var result ctrl.Result
	var err error
	switch auth.Status.Phase {
	case "", networkv1alpha1.FabricReleasePhasePending:
		result, err = r.tryStart(ctx, auth)
	case networkv1alpha1.FabricReleasePhaseStarted, networkv1alpha1.FabricReleasePhaseUnknown:
		result, err = r.progress(ctx, auth)
	case networkv1alpha1.FabricReleasePhaseFailed:
		result, err = r.verifyRecovery(ctx, auth)
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	if !equalStatus(before, &auth.Status) {
		if err := r.Status().Update(ctx, auth); err != nil {
			return ctrl.Result{}, err
		}
	}
	return result, nil
}

func (r *ReleaseReconciler) dropFinalizer(ctx context.Context, auth *networkv1alpha1.FabricReleaseAuthorization) error {
	if !controllerutil.ContainsFinalizer(auth, ReleaseFinalizer) {
		return nil
	}
	before := auth.DeepCopy()
	controllerutil.RemoveFinalizer(auth, ReleaseFinalizer)
	return client.IgnoreNotFound(r.Patch(ctx, auth, client.MergeFromWithOptions(before,
		client.MergeFromWithOptimisticLock{})))
}

// tryStart starts a pending release once nothing blocks it, or cancels it
// when it can never start.
func (r *ReleaseReconciler) tryStart(ctx context.Context,
	auth *networkv1alpha1.FabricReleaseAuthorization) (ctrl.Result, error) {
	now := r.now()
	if d := auth.Spec.StartDeadline; d != nil && now.After(d.Time) {
		r.finish(auth, networkv1alpha1.FabricReleasePhaseCancelled, reasonDeadlinePassed,
			"the start deadline "+d.UTC().Format(time.RFC3339)+" passed before the release could start")
		return ctrl.Result{}, nil
	}
	others := &networkv1alpha1.FabricReleaseAuthorizationList{}
	if err := r.reader().List(ctx, others, client.InNamespace(auth.Namespace)); err != nil {
		return ctrl.Result{}, err
	}
	for i := range others.Items {
		o := &others.Items[i]
		if o.UID == auth.UID || o.Spec.RoutingDomain != auth.Spec.RoutingDomain {
			continue
		}
		started := o.Status.Phase != "" && o.Status.Phase != networkv1alpha1.FabricReleasePhasePending &&
			o.Status.Phase != networkv1alpha1.FabricReleasePhaseCancelled
		if started && o.Spec.FleetSequence >= auth.Spec.FleetSequence &&
			auth.Spec.Type == networkv1alpha1.FabricReleaseTypeRelease {
			r.finish(auth, networkv1alpha1.FabricReleasePhaseCancelled, reasonSuperseded,
				fmt.Sprintf("release %s at fleet sequence %d already started; sequences only rise", o.Name,
					o.Spec.FleetSequence))
			return ctrl.Result{}, nil
		}
		// An emergency withdrawal may start while a release is outstanding.
		blocks := o.Status.Outstanding() && auth.Spec.Type == networkv1alpha1.FabricReleaseTypeRelease &&
			(started || o.Spec.FleetSequence < auth.Spec.FleetSequence)
		if blocks {
			auth.Status.Phase = networkv1alpha1.FabricReleasePhasePending
			r.condition(auth, metav1.ConditionFalse, reasonWaitingForRelease, "waiting for release "+o.Name)
			return ctrl.Result{RequeueAfter: progressInterval}, nil
		}
	}
	for _, t := range auth.Spec.Deployments {
		if _, _, err := r.target(ctx, auth, t); err != nil {
			r.finish(auth, networkv1alpha1.FabricReleasePhaseCancelled, reasonInvalidTarget, err.Error())
			return ctrl.Result{}, nil
		}
	}
	start := metav1.NewTime(now)
	auth.Status.Phase = networkv1alpha1.FabricReleasePhaseStarted
	auth.Status.StartedAt = &start
	r.condition(auth, metav1.ConditionTrue, reasonPromoting, "started")
	r.event(auth, corev1.EventTypeNormal, ReasonReleaseStarted, "release %s started", auth.Spec.FleetReleaseID)
	return ctrl.Result{Requeue: true}, nil
}

// targetError is a target that cannot be promoted.
type targetError struct{ msg string }

func (e targetError) Error() string { return e.msg }

// target reads and checks one release target: its deployment, by name and
// UID, on the CRD source and not suspended; its revision, with the digest
// the release names, compiled for the deployment's router.
func (r *ReleaseReconciler) target(ctx context.Context, auth *networkv1alpha1.FabricReleaseAuthorization,
	t networkv1alpha1.FabricReleaseTarget,
) (*networkv1alpha1.FabricRouterDeployment, *networkv1alpha1.FabricRouterRevision, error) {
	dep := &networkv1alpha1.FabricRouterDeployment{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: auth.Namespace, Name: t.Deployment}, dep); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, targetError{"deployment " + t.Deployment + " does not exist"}
		}
		return nil, nil, err
	}
	rev := &networkv1alpha1.FabricRouterRevision{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: auth.Namespace, Name: t.Revision}, rev); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, targetError{"revision " + t.Revision + " does not exist"}
		}
		return nil, nil, err
	}
	switch {
	case string(dep.UID) != t.DeploymentUID:
		return nil, nil, targetError{fmt.Sprintf("deployment %s is UID %s, the release names %s", dep.Name, dep.UID,
			t.DeploymentUID)}
	case dep.Spec.Source != networkv1alpha1.FabricConfigSourceCRD:
		return nil, nil, targetError{fmt.Sprintf("deployment %s is on the %s source, not CRD", dep.Name, dep.Spec.Source)}
	case dep.Spec.Suspended:
		return nil, nil, targetError{"deployment " + dep.Name + " is suspended"}
	case rev.Spec.ActivationDependencyDigest != t.ActivationDependencyDigest:
		return nil, nil, targetError{fmt.Sprintf("revision %s has digest %s, the release names %s",
			rev.Name, rev.Spec.ActivationDependencyDigest, t.ActivationDependencyDigest)}
	case rev.Labels[routerLabel] != dep.Spec.RouterRef.Name:
		return nil, nil, targetError{fmt.Sprintf("revision %s was compiled for router %q, not %s",
			rev.Name, rev.Labels[routerLabel], dep.Spec.RouterRef.Name)}
	}
	if dep.Spec.Recovery != nil {
		if p := revokedOrigination(dep.Spec.Recovery.RevokedPrefixes, rev); p != "" {
			// An emergency withdrawal revoked it; no release brings it back.
			return nil, nil, targetError{fmt.Sprintf("revision %s originates %s, revoked on deployment %s",
				rev.Name, p, dep.Name)}
		}
	}
	return dep, rev, nil
}

// routerLabel names a revision's router; the revision controller sets it.
const routerLabel = "galactic.datumapis.com/router"

// progress promotes waiting targets within the policy's concurrency and
// records the release's outcome.
func (r *ReleaseReconciler) progress(ctx context.Context,
	auth *networkv1alpha1.FabricReleaseAuthorization) (ctrl.Result, error) {
	now := r.now()
	type entry struct {
		target networkv1alpha1.FabricReleaseTarget
		dep    *networkv1alpha1.FabricRouterDeployment
		policy networkv1alpha1.FabricRolloutPolicySpec
		domain string
		state  targetState
	}
	var entries []entry
	inFlight := map[string]int{}
	var failed, silent []string
	committedCount := 0
	for _, t := range auth.Spec.Deployments {
		dep := &networkv1alpha1.FabricRouterDeployment{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: auth.Namespace, Name: t.Deployment}, dep); err != nil {
			if apierrors.IsNotFound(err) {
				failed = append(failed, t.Deployment+": deployment deleted")
				continue
			}
			return ctrl.Result{}, err
		}
		policy, err := r.policy(ctx, dep)
		if err != nil {
			return ctrl.Result{}, err
		}
		domain, err := r.domain(ctx, dep, policy.FailureDomainLabel)
		if err != nil {
			return ctrl.Result{}, err
		}
		state := stateOf(dep, auth, t, time.Duration(policy.HeartbeatTimeoutSeconds)*time.Second, now)
		switch state {
		case targetSilent:
			silent = append(silent, t.Deployment)
		case targetFailed:
			failed = append(failed, t.Deployment)
		case targetCommitted:
			committedCount++
		}
		entries = append(entries, entry{target: t, dep: dep, policy: policy, domain: domain, state: state})
	}

	switch {
	case len(failed) > 0:
		r.finish(auth, networkv1alpha1.FabricReleasePhaseFailed, reasonTargetFailed,
			"failed: "+strings.Join(failed, ", ")+"; no further routers are promoted")
		r.event(auth, corev1.EventTypeWarning, ReasonReleaseFailed, "release %s failed on %s",
			auth.Spec.FleetReleaseID, strings.Join(failed, ", "))
		return ctrl.Result{RequeueAfter: progressInterval}, nil
	case committedCount == len(auth.Spec.Deployments):
		r.finish(auth, networkv1alpha1.FabricReleasePhaseCompleted, reasonAllCommitted, "every router committed")
		r.event(auth, corev1.EventTypeNormal, ReasonReleaseCompleted, "release %s completed", auth.Spec.FleetReleaseID)
		return ctrl.Result{}, nil
	case len(silent) > 0:
		// The outcome is unknown, not failed: the routers may be fine.
		auth.Status.Phase = networkv1alpha1.FabricReleasePhaseUnknown
		r.condition(auth, metav1.ConditionUnknown, reasonTargetSilent,
			"no report from "+strings.Join(silent, ", ")+"; no further routers are promoted until they report")
		return ctrl.Result{RequeueAfter: progressInterval}, nil
	}
	auth.Status.Phase = networkv1alpha1.FabricReleasePhaseStarted

	// Count every deployment still activating, under any release, so an
	// emergency withdrawal running beside this release shares the limit.
	labels := map[string]bool{}
	for _, e := range entries {
		labels[e.policy.FailureDomainLabel] = true
	}
	all := &networkv1alpha1.FabricRouterDeploymentList{}
	// From the API server: the cache may not show a promotion just made.
	if err := r.reader().List(ctx, all, client.InNamespace(auth.Namespace)); err != nil {
		return ctrl.Result{}, err
	}
	for i := range all.Items {
		if !busy(&all.Items[i]) {
			continue
		}
		for label := range labels {
			domain, err := r.domain(ctx, &all.Items[i], label)
			if err != nil {
				return ctrl.Result{}, err
			}
			inFlight[domain]++
		}
	}

	promoted := 0
	for _, e := range entries {
		if e.state != targetWaiting || inFlight[e.domain] >= int(e.policy.MaxUnavailable) {
			continue
		}
		dep, rev, err := r.target(ctx, auth, e.target)
		if err == nil && busy(dep) {
			// Promoted under another release since it was read.
			continue
		}
		if err != nil {
			var bad targetError
			if errors.As(err, &bad) {
				r.finish(auth, networkv1alpha1.FabricReleasePhaseFailed, reasonInvalidTarget, err.Error())
				return ctrl.Result{RequeueAfter: progressInterval}, nil
			}
			return ctrl.Result{}, err
		}
		dep.Spec = promote(dep, rev, auth, activationSettings(e.policy, rev))
		if err := r.Update(ctx, dep); err != nil {
			return ctrl.Result{}, err
		}
		inFlight[e.domain]++
		promoted++
		r.event(auth, corev1.EventTypeNormal, ReasonPromoted, "promoted %s to %s at epoch %d",
			dep.Name, rev.Name, dep.Spec.ActivationEpoch)
	}
	r.condition(auth, metav1.ConditionTrue, reasonPromoting,
		fmt.Sprintf("%d of %d routers committed", committedCount, len(auth.Spec.Deployments)))
	return ctrl.Result{RequeueAfter: progressInterval}, nil
}

// verifyRecovery marks a failed release recovered once nothing it promoted
// is still activating and every failed router is back on its recovery
// target. Until then it blocks its routing domain.
func (r *ReleaseReconciler) verifyRecovery(ctx context.Context,
	auth *networkv1alpha1.FabricReleaseAuthorization) (ctrl.Result, error) {
	now := r.now()
	var pending []string
	for _, t := range auth.Spec.Deployments {
		dep := &networkv1alpha1.FabricRouterDeployment{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: auth.Namespace, Name: t.Deployment}, dep); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return ctrl.Result{}, err
		}
		policy, err := r.policy(ctx, dep)
		if err != nil {
			return ctrl.Result{}, err
		}
		switch stateOf(dep, auth, t, time.Duration(policy.HeartbeatTimeoutSeconds)*time.Second, now) {
		case targetActivating, targetSilent:
			pending = append(pending, t.Deployment+" activating")
		case targetFailed:
			if !recovered(dep) {
				pending = append(pending, t.Deployment+" not recovered")
			}
		}
	}
	if by := auth.Annotations[RecoveryVerifiedAnnotation]; by != "" && len(pending) > 0 {
		auth.Status.RecoveryVerified = true
		r.condition(auth, metav1.ConditionFalse, reasonRecoveryVerified,
			"recovery confirmed by "+by+" with "+strings.Join(pending, ", "))
		return ctrl.Result{}, nil
	}
	if len(pending) > 0 {
		r.condition(auth, metav1.ConditionFalse, reasonRecoveryPending, strings.Join(pending, ", ")+
			"; set the "+RecoveryVerifiedAnnotation+" annotation once an operator confirms the routers are safe")
		return ctrl.Result{RequeueAfter: progressInterval}, nil
	}
	auth.Status.RecoveryVerified = true
	r.condition(auth, metav1.ConditionFalse, reasonRecoveryVerified,
		"every failed router is back on its recovery target")
	return ctrl.Result{}, nil
}

// policy is the effective rollout policy of a deployment's router.
func (r *ReleaseReconciler) policy(ctx context.Context,
	dep *networkv1alpha1.FabricRouterDeployment) (networkv1alpha1.FabricRolloutPolicySpec, error) {
	router := &networkv1alpha1.BGPRouter{}
	err := r.Get(ctx, types.NamespacedName{Namespace: dep.Namespace, Name: dep.Spec.RouterRef.Name}, router)
	if apierrors.IsNotFound(err) || (err == nil && (router.Spec.FRR == nil || router.Spec.FRR.RolloutPolicyRef == nil)) {
		return effectivePolicy(nil), nil
	}
	if err != nil {
		return networkv1alpha1.FabricRolloutPolicySpec{}, err
	}
	p := &networkv1alpha1.FabricRolloutPolicy{}
	err = r.Get(ctx, types.NamespacedName{Namespace: dep.Namespace, Name: router.Spec.FRR.RolloutPolicyRef.Name}, p)
	if apierrors.IsNotFound(err) {
		// A missing policy is the strictest default, not a stalled release.
		return effectivePolicy(nil), nil
	}
	if err != nil {
		return networkv1alpha1.FabricRolloutPolicySpec{}, err
	}
	return effectivePolicy(p), nil
}

// domain is the failure domain of a deployment's Node, by label; a Node
// without the label is its own domain.
func (r *ReleaseReconciler) domain(ctx context.Context, dep *networkv1alpha1.FabricRouterDeployment,
	label string) (string, error) {
	node := &metav1.PartialObjectMetadata{}
	node.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Node"))
	if err := r.Get(ctx, types.NamespacedName{Name: dep.Spec.Target.NodeName}, node); err != nil {
		if apierrors.IsNotFound(err) {
			return "node/" + dep.Spec.Target.NodeName, nil
		}
		return "", err
	}
	if v, ok := node.Labels[label]; ok {
		return label + "=" + v, nil
	}
	return "node/" + dep.Spec.Target.NodeName, nil
}

func (r *ReleaseReconciler) finish(auth *networkv1alpha1.FabricReleaseAuthorization,
	phase networkv1alpha1.FabricReleasePhase,
	reason, msg string) {
	auth.Status.Phase = phase
	if phase != networkv1alpha1.FabricReleasePhaseCancelled {
		end := metav1.NewTime(r.now())
		auth.Status.FinishedAt = &end
	}
	status := metav1.ConditionFalse
	r.condition(auth, status, reason, msg)
}

func (r *ReleaseReconciler) condition(auth *networkv1alpha1.FabricReleaseAuthorization, s metav1.ConditionStatus,
	reason, msg string) {
	if len(msg) > 32768 {
		msg = msg[:32768]
	}
	meta.SetStatusCondition(&auth.Status.Conditions, metav1.Condition{
		Type: ConditionProgressing, Status: s, Reason: reason, Message: msg, ObservedGeneration: auth.Generation,
	})
}

func (r *ReleaseReconciler) event(auth *networkv1alpha1.FabricReleaseAuthorization, eventType, reason,
	format string, args ...any) {
	if r.Recorder != nil {
		r.Recorder.Eventf(auth, nil, eventType, reason, "Rollout", format, args...)
	}
}

// SetupWithManager reconciles a release on its own changes and on changes
// to the deployments it names.
func (r *ReleaseReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	releases := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		list := &networkv1alpha1.FabricReleaseAuthorizationList{}
		if err := r.List(ctx, list, client.InNamespace(o.GetNamespace())); err != nil {
			return nil
		}
		var out []reconcile.Request
		for _, a := range list.Items {
			if !a.Status.Outstanding() {
				continue
			}
			for _, t := range a.Spec.Deployments {
				if t.Deployment == o.GetName() {
					out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&a)})
					break
				}
			}
		}
		return out
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("fabric-releases").
		For(&networkv1alpha1.FabricReleaseAuthorization{}).
		Watches(&networkv1alpha1.FabricRouterDeployment{}, releases).
		Complete(r)
}

func equalStatus(a, b *networkv1alpha1.FabricReleaseAuthorizationStatus) bool {
	if a.Phase != b.Phase || a.RecoveryVerified != b.RecoveryVerified ||
		!a.StartedAt.Equal(b.StartedAt) || !a.FinishedAt.Equal(b.FinishedAt) || len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for i := range a.Conditions {
		x, y := a.Conditions[i], b.Conditions[i]
		if x.Type != y.Type || x.Status != y.Status || x.Reason != y.Reason || x.Message != y.Message ||
			x.ObservedGeneration != y.ObservedGeneration {
			return false
		}
	}
	return true
}
