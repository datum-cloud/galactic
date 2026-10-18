// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package rollout

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

// Event reasons the rollout manager raises on routers and releases.
const (
	ReasonDeploymentMismatch = "DeploymentMismatch"
	ReasonReleaseStarted     = "ReleaseStarted"
	ReasonReleaseFailed      = "ReleaseFailed"
	ReasonReleaseCompleted   = "ReleaseCompleted"
	ReasonPromoted           = "Promoted"
)

// DeploymentReconciler gives each compiled fabric router a
// FabricRouterDeployment and keeps its candidate on the router's newest
// revision. It never promotes: ReleaseReconciler does, under a release.
type DeploymentReconciler struct {
	client.Client
	// Recorder emits events; nil disables them.
	Recorder events.EventRecorder
}

// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=fabricrouterdeployments,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=bgprouters/finalizers,verbs=update

// Reconcile ensures one router's deployment.
func (r *DeploymentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	router := &networkv1alpha1.BGPRouter{}
	if err := r.Get(ctx, req.NamespacedName, router); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Only routers the revision controller compiles have a fabric status.
	if router.Status.Fabric == nil || router.Status.Fabric.LatestRevision == "" || !router.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	node := &metav1.PartialObjectMetadata{}
	node.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Node"))
	if err := r.Get(ctx, types.NamespacedName{Name: router.Spec.TargetRef.Name}, node); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	dep := &networkv1alpha1.FabricRouterDeployment{}
	err := r.Get(ctx, client.ObjectKeyFromObject(router), dep)
	if apierrors.IsNotFound(err) {
		return ctrl.Result{}, r.create(ctx, router, string(node.UID))
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	switch {
	case dep.Spec.RouterRef.UID != string(router.UID):
		r.warn(router, "deployment %s belongs to an earlier BGPRouter %s; delete it to deploy this one",
			dep.Name, dep.Spec.RouterRef.UID)
		return ctrl.Result{}, nil
	case dep.Spec.Target.NodeUID != string(node.UID) || dep.Spec.Target.NodeName != router.Spec.TargetRef.Name:
		// Moving needs the old node fenced, which only an operator can
		// confirm; the deployment keeps its target until then.
		r.warn(router, "deployment %s targets Node %s (%s), the router targets %s (%s); fence the old node to move it",
			dep.Name, dep.Spec.Target.NodeName, dep.Spec.Target.NodeUID, router.Spec.TargetRef.Name, node.UID)
		return ctrl.Result{}, nil
	}
	latest := router.Status.Fabric.LatestRevision
	if dep.Spec.CandidateRevisionRef != nil && dep.Spec.CandidateRevisionRef.Name == latest {
		return ctrl.Result{}, nil
	}
	before := dep.DeepCopy()
	dep.Spec.CandidateRevisionRef = &networkv1alpha1.LocalObjectRef{Name: latest}
	return ctrl.Result{}, r.Patch(ctx, dep, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
}

func (r *DeploymentReconciler) create(ctx context.Context, router *networkv1alpha1.BGPRouter, nodeUID string) error {
	dep := &networkv1alpha1.FabricRouterDeployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: router.Namespace, Name: router.Name},
		Spec: networkv1alpha1.FabricRouterDeploymentSpec{
			RouterRef: networkv1alpha1.FabricObjectIdentity{Name: router.Name, UID: string(router.UID)},
			Target: networkv1alpha1.FabricNodeIdentity{NodeName: router.Spec.TargetRef.Name,
				NodeUID: nodeUID},
			Source:               networkv1alpha1.FabricConfigSourceConfigMap,
			CandidateRevisionRef: &networkv1alpha1.LocalObjectRef{Name: router.Status.Fabric.LatestRevision},
		},
	}
	if err := controllerutil.SetControllerReference(router, dep, r.Scheme()); err != nil {
		return err
	}
	return client.IgnoreAlreadyExists(r.Create(ctx, dep))
}

func (r *DeploymentReconciler) warn(router *networkv1alpha1.BGPRouter, format string, args ...any) {
	if r.Recorder != nil {
		r.Recorder.Eventf(router, nil, corev1.EventTypeWarning, ReasonDeploymentMismatch, "Deploy", format, args...)
	}
}

// SetupWithManager reconciles routers on their own changes, their
// deployments' and their Nodes' appearing.
func (r *DeploymentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	nodeRouters := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		routers := &networkv1alpha1.BGPRouterList{}
		if err := r.List(ctx, routers); err != nil {
			return nil
		}
		var out []reconcile.Request
		for _, rt := range routers.Items {
			if rt.Spec.TargetRef.Name == o.GetName() {
				out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&rt)})
			}
		}
		return out
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("fabric-router-deployments").
		For(&networkv1alpha1.BGPRouter{}).
		Owns(&networkv1alpha1.FabricRouterDeployment{}).
		WatchesMetadata(&corev1.Node{}, nodeRouters).
		Complete(r)
}

// String names the reconciler in logs.
func (r *DeploymentReconciler) String() string { return fmt.Sprintf("%T", r) }
