// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
)

// DefaultProxyNodeResync is how often ProxyNodeReconciler checks an
// attachment's pod again. It reads the pod directly rather than through a pod
// informer, so a deleted or rescheduled pod is noticed within this interval.
const DefaultProxyNodeResync = 30 * time.Second

// PodCertifiedNode returns the node the pod an attachment names
// (status.podName) runs on, read uncached from the attachment's own
// namespace: its spec.nodeName, which the scheduler set. It returns "" when
// the attachment names no pod, or the pod is gone, not yet scheduled or
// terminating. A pod of the same name in another namespace never certifies.
func PodCertifiedNode(ctx context.Context, reader client.Reader, attachment *cloudv1alpha1.VPCAttachment) (
	string, error) {
	if reader == nil || attachment.Status.PodName == "" {
		return "", nil
	}
	var pod corev1.Pod
	key := client.ObjectKey{Namespace: attachment.Namespace, Name: attachment.Status.PodName}
	if err := reader.Get(ctx, key, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("read pod %s of VPC attachment %s: %w", key, attachment.Name, err)
	}
	if !pod.DeletionTimestamp.IsZero() || pod.Spec.NodeName == "" {
		return "", nil
	}
	return pod.Spec.NodeName, nil
}

// ProxyNodeReconciler certifies status.node of a VPC attachment that names
// its pod (status.podName) but has no tenant advertisement yet, such as the
// per-VPC attachment of an Envoy proxy, whose galactic-vrf sidecar Galactic
// Worker admits a socket claim for only on the attachment's node. The node is
// the pod's spec.nodeName, so only the scheduler decides it; a pod can claim
// no other node.
//
// Once an advertisement for the attachment exists, BGPAdvertisementReconciler
// projects the node from it, and this reconciler leaves the attachment alone;
// when that advertisement is withdrawn, the projection falls back to the same
// pod-certified node.
type ProxyNodeReconciler struct {
	client.Client
	// APIReader reads the attachment's pod uncached, so the controller keeps
	// no informer on every pod in the cluster.
	APIReader client.Reader
	// Resync is how often the pod is read again; DefaultProxyNodeResync when
	// zero.
	Resync time.Duration
}

// +kubebuilder:rbac:groups="",resources=pods,verbs=get
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=vpcattachments/status,verbs=get;update;patch

// Reconcile implements reconcile.Reconciler.
func (r *ProxyNodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	resync := r.Resync
	if resync == 0 {
		resync = DefaultProxyNodeResync
	}
	var attachment cloudv1alpha1.VPCAttachment
	if err := r.Get(ctx, req.NamespacedName, &attachment); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if attachment.Status.PodName == "" {
		return ctrl.Result{}, nil
	}
	identity := galactic.AdvertisementName(attachment.Status.VPC, attachment.Status.VPCAttachment)
	if identity == "" {
		return ctrl.Result{}, nil
	}
	var advertisements bgpv1alpha1.BGPAdvertisementList
	if err := r.List(ctx, &advertisements, client.InNamespace(galactic.SystemNamespace),
		client.MatchingFields{IndexBGPAdvertisementIdentity: identity}); err != nil {
		return ctrl.Result{}, fmt.Errorf("list advertisements of %s: %w", identity, err)
	}
	if len(advertisements.Items) > 0 {
		// The advertisement's projection owns the node.
		return ctrl.Result{}, nil
	}
	reader := r.APIReader
	if reader == nil {
		reader = r.Client
	}
	node, err := PodCertifiedNode(ctx, reader, &attachment)
	if err != nil {
		return ctrl.Result{}, err
	}
	if attachment.Status.Node != node {
		attachment.Status.Node = node
		if err := r.Status().Update(ctx, &attachment); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, fmt.Errorf("update VPC attachment %s status: %w", req.NamespacedName, err)
		}
	}
	return ctrl.Result{RequeueAfter: resync}, nil
}

// SetupWithManager registers the reconciler for attachments that name a pod.
func (r *ProxyNodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	namesPod := func(obj client.Object) bool {
		attachment, ok := obj.(*cloudv1alpha1.VPCAttachment)
		return ok && attachment.Status.PodName != ""
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&cloudv1alpha1.VPCAttachment{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc:  func(e event.CreateEvent) bool { return namesPod(e.Object) },
			DeleteFunc:  func(event.DeleteEvent) bool { return false },
			GenericFunc: func(e event.GenericEvent) bool { return namesPod(e.Object) },
			UpdateFunc: func(e event.UpdateEvent) bool {
				oldAttachment, oldOK := e.ObjectOld.(*cloudv1alpha1.VPCAttachment)
				newAttachment, newOK := e.ObjectNew.(*cloudv1alpha1.VPCAttachment)
				if !oldOK || !newOK || (oldAttachment.Status.PodName == "" && newAttachment.Status.PodName == "") {
					return false
				}
				return oldAttachment.Status.PodName != newAttachment.Status.PodName ||
					oldAttachment.Status.Node != newAttachment.Status.Node ||
					oldAttachment.Status.VPC != newAttachment.Status.VPC ||
					oldAttachment.Status.VPCAttachment != newAttachment.Status.VPCAttachment
			},
		})).
		Named("proxyattachmentnode").
		Complete(r)
}
