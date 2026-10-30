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
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cloud/galactic"
	networkingv1alpha "go.datum.net/network-services-operator/api/v1alpha"
)

// ReasonAdvertisementWithdrawn is the Programmed reason of an attachment that
// no tenant advertisement certifies any more.
const ReasonAdvertisementWithdrawn = "AdvertisementWithdrawn"

// IndexVPCAttachmentIdentity indexes a VPCAttachment by the "<vpc>-<attachment>"
// pair galactic names its BGPAdvertisement after.
const (
	IndexVPCAttachmentIdentity    = "status.identity"
	IndexBGPAdvertisementIdentity = "metadata.identity"
)

// BGPAdvertisementReconciler projects what the data plane published onto the
// Datum API. galactic-router sets Advertised from live GoBGP runtime state, so
// consuming its BGPAdvertisement keeps Datum types off the CNI ADD path and
// keeps galactic free of Datum APIs.
type BGPAdvertisementReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=bgpadvertisements;bgprouters,verbs=get;list;watch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=vpcattachments/status,verbs=get;update;patch

func (r *BGPAdvertisementReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var advertisement bgpv1alpha1.BGPAdvertisement
	if err := r.Get(ctx, req.NamespacedName, &advertisement); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, r.clearWithdrawnAdvertisement(ctx, req.NamespacedName)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	vpc, attachmentID, ok := galactic.SplitAdvertisementName(advertisement.Name)
	if !ok {
		return ctrl.Result{}, nil
	}

	// Ownership is checked before any status write: an advertisement on a
	// router naming a routerClassName (the fabric underlay) never certifies
	// a tenant attachment, interface or claim, whatever its name looks like.
	router, err := r.routerFor(ctx, advertisement.Namespace, advertisement.Spec.RouterRef.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	if router != nil && !bgpv1alpha1.IsLegacyOwned(router) {
		return ctrl.Result{}, nil
	}

	var attachments cloudv1alpha1.VPCAttachmentList
	if err := r.List(ctx, &attachments,
		client.MatchingFields{IndexVPCAttachmentIdentity: galactic.AdvertisementName(vpc, attachmentID)}); err != nil {
		return ctrl.Result{}, fmt.Errorf("list VPC attachments for advertisement %s: %w", advertisement.Name, err)
	}
	if len(attachments.Items) == 0 {
		return ctrl.Result{}, nil
	}

	var node string
	if router != nil {
		node = router.Spec.TargetRef.Name
	}
	programmed := programmedCondition(&advertisement)
	subnets := galactic.AllocatedSubnets(advertisement.Annotations)

	for i := range attachments.Items {
		attachment := &attachments.Items[i]
		attachment.Status.Node = node
		attachment.Status.HostInterface = galactic.HostInterfaceName(vpc, attachmentID)
		attachment.Status.VRFInterface = galactic.VRFInterfaceName(vpc)
		if len(subnets) == 1 {
			// One live pod per interface at a time, so a single recorded subnet
			// is this attachment's; several means a container is still being
			// collected and neither is unambiguously current.
			attachment.Status.PodSubnet = subnets[0]
		}
		meta.SetStatusCondition(&attachment.Status.Conditions, programmed)
		if err := r.Status().Update(ctx, attachment); err != nil {
			return ctrl.Result{}, fmt.Errorf("update VPC attachment %s status: %w",
				client.ObjectKeyFromObject(attachment), err)
		}
		if err := r.projectOntoInterface(ctx, attachment, programmed); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// clearWithdrawnAdvertisement removes delivery status only when no tenant
// advertisement can certify the attachment, including after a node move.
func (r *BGPAdvertisementReconciler) clearWithdrawnAdvertisement(ctx context.Context, key types.NamespacedName) error {
	vpc, attachmentID, ok := galactic.SplitAdvertisementName(key.Name)
	if !ok || key.Namespace != galactic.SystemNamespace {
		return nil
	}
	identity := galactic.AdvertisementName(vpc, attachmentID)
	var advertisements bgpv1alpha1.BGPAdvertisementList
	if err := r.List(ctx, &advertisements, client.InNamespace(key.Namespace),
		client.MatchingFields{IndexBGPAdvertisementIdentity: identity}); err != nil {
		return fmt.Errorf("list replacement advertisements: %w", err)
	}
	for i := range advertisements.Items {
		advertisement := &advertisements.Items[i]
		router, err := r.routerFor(ctx, advertisement.Namespace, advertisement.Spec.RouterRef.Name)
		if err != nil {
			return err
		}
		if router == nil || bgpv1alpha1.IsLegacyOwned(router) {
			return nil
		}
	}
	var attachments cloudv1alpha1.VPCAttachmentList
	if err := r.List(ctx, &attachments, client.MatchingFields{IndexVPCAttachmentIdentity: identity}); err != nil {
		return fmt.Errorf("list withdrawn attachments: %w", err)
	}
	for i := range attachments.Items {
		attachment := &attachments.Items[i]
		if attachment.Status.Node == "" || key.Name != identity+"-"+attachment.Status.Node {
			continue
		}
		attachment.Status.Node = ""
		attachment.Status.HostInterface = ""
		attachment.Status.VRFInterface = ""
		attachment.Status.PodSubnet = ""
		programmed := metav1.Condition{
			Type: cloudv1alpha1.ConditionTypeProgrammed, Status: metav1.ConditionFalse,
			Reason: ReasonAdvertisementWithdrawn, Message: "the attachment has no network advertisement",
			ObservedGeneration: attachment.Generation,
		}
		meta.SetStatusCondition(&attachment.Status.Conditions, programmed)
		if err := r.projectOntoInterface(ctx, attachment, programmed); err != nil {
			return err
		}
		if err := r.Status().Update(ctx, attachment); err != nil {
			return fmt.Errorf("clear withdrawn attachment %s: %w", client.ObjectKeyFromObject(attachment), err)
		}
	}
	return nil
}

func advertisementForAttachment(_ context.Context, obj client.Object) []reconcile.Request {
	attachment, ok := obj.(*cloudv1alpha1.VPCAttachment)
	if !ok || attachment.Status.Node == "" {
		return nil
	}
	identity := galactic.AdvertisementName(attachment.Status.VPC, attachment.Status.VPCAttachment)
	if identity == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{
		Namespace: galactic.SystemNamespace, Name: identity + "-" + attachment.Status.Node,
	}}}
}

// projectOntoInterface closes the Programmed condition NSO deliberately leaves
// for whoever realizes the interface.
func (r *BGPAdvertisementReconciler) projectOntoInterface(
	ctx context.Context, attachment *cloudv1alpha1.VPCAttachment, programmed metav1.Condition,
) error {
	if attachment.Spec.InterfaceRef == nil {
		return nil
	}
	var networkInterface networkingv1alpha.NetworkInterface
	key := types.NamespacedName{Namespace: attachment.Namespace, Name: attachment.Spec.InterfaceRef.Name}
	if err := r.Get(ctx, key, &networkInterface); err != nil {
		return client.IgnoreNotFound(err)
	}
	// An advertisement from the new group cannot certify an interface that
	// still points at the former attachment API.
	if networkInterface.Status.AttachmentRef == nil ||
		networkInterface.Status.AttachmentRef.APIGroup != cloudv1alpha1.GroupVersion.Group ||
		networkInterface.Status.AttachmentRef.Name != attachment.Name {
		return nil
	}

	interfaceProgrammed := programmed
	interfaceProgrammed.Type = networkingv1alpha.NetworkInterfaceProgrammed
	interfaceProgrammed.ObservedGeneration = networkInterface.Generation
	meta.SetStatusCondition(&networkInterface.Status.Conditions, interfaceProgrammed)
	if err := r.Status().Update(ctx, &networkInterface); err != nil {
		return fmt.Errorf("update network interface %s status: %w", key, err)
	}
	if networkInterface.Spec.ClaimRef == nil {
		return nil
	}
	claimKey := types.NamespacedName{Namespace: networkInterface.Namespace, Name: networkInterface.Spec.ClaimRef.Name}
	var claim networkingv1alpha.NetworkInterfaceClaim
	if err := r.Get(ctx, claimKey, &claim); err != nil {
		return client.IgnoreNotFound(err)
	}
	claimProgrammed := programmed
	claimProgrammed.Type = networkingv1alpha.NetworkInterfaceClaimProgrammed
	claimProgrammed.ObservedGeneration = claim.Generation
	meta.SetStatusCondition(&claim.Status.Conditions, claimProgrammed)
	if programmed.Status != metav1.ConditionTrue {
		meta.SetStatusCondition(&claim.Status.Conditions, metav1.Condition{
			Type: networkingv1alpha.NetworkInterfaceClaimReady, Status: programmed.Status,
			Reason: "NotProgrammed", Message: programmed.Message, ObservedGeneration: claim.Generation,
		})
	}
	if err := r.Status().Update(ctx, &claim); err != nil {
		return fmt.Errorf("update network interface claim %s status: %w", claimKey, err)
	}
	return nil
}

// advertisementForInterface replays an existing advertisement when an
// interface switches to the Galactic API group after the data plane reported.
func (r *BGPAdvertisementReconciler) advertisementForInterface(ctx context.Context, obj client.Object) []reconcile.Request {
	iface, ok := obj.(*networkingv1alpha.NetworkInterface)
	if !ok || iface.Status.AttachmentRef == nil ||
		iface.Status.AttachmentRef.APIGroup != cloudv1alpha1.GroupVersion.Group {
		return nil
	}
	var attachment cloudv1alpha1.VPCAttachment
	key := types.NamespacedName{Namespace: iface.Namespace, Name: iface.Status.AttachmentRef.Name}
	if err := r.Get(ctx, key, &attachment); err != nil ||
		attachment.Status.VPC == "" || attachment.Status.VPCAttachment == "" {
		return nil
	}
	identity := galactic.AdvertisementName(attachment.Status.VPC, attachment.Status.VPCAttachment)
	if identity == "" {
		return nil
	}
	var advertisements bgpv1alpha1.BGPAdvertisementList
	if err := r.List(ctx, &advertisements, client.MatchingFields{IndexBGPAdvertisementIdentity: identity}); err != nil {
		log.FromContext(ctx).Error(err, "list advertisements for migrated interface", "interface", key)
		return nil
	}
	requests := make([]reconcile.Request, 0, len(advertisements.Items))
	for i := range advertisements.Items {
		advertisement := &advertisements.Items[i]
		// A fabric advertisement named like this attachment never enters
		// the replay; Reconcile would ignore it anyway.
		router, err := r.routerFor(ctx, advertisement.Namespace, advertisement.Spec.RouterRef.Name)
		if err != nil {
			log.FromContext(ctx).Error(err, "get BGPRouter for replayed advertisement",
				"advertisement", client.ObjectKeyFromObject(advertisement))
			continue
		}
		if router != nil && !bgpv1alpha1.IsLegacyOwned(router) {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: advertisement.Namespace,
			Name:      advertisement.Name,
		}})
	}
	return requests
}

// BGPAdvertisementIdentity returns the attachment identity shared by every
// node-qualified advertisement for that attachment.
func BGPAdvertisementIdentity(obj client.Object) []string {
	advertisement, ok := obj.(*bgpv1alpha1.BGPAdvertisement)
	if !ok {
		return nil
	}
	vpc, attachment, ok := galactic.SplitAdvertisementName(advertisement.Name)
	if !ok {
		return nil
	}
	identity := galactic.AdvertisementName(vpc, attachment)
	if identity == "" || !strings.HasPrefix(advertisement.Name, identity+"-") {
		return nil
	}
	return []string{identity}
}

// routerFor returns the named BGPRouter, or nil when the name is empty or the
// router does not exist yet.
func (r *BGPAdvertisementReconciler) routerFor(ctx context.Context, namespace, name string) (*bgpv1alpha1.BGPRouter, error) {
	if name == "" {
		return nil, nil
	}
	var router bgpv1alpha1.BGPRouter
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &router); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get BGPRouter %s/%s: %w", namespace, name, err)
	}
	return &router, nil
}

// programmedCondition translates the data plane's Advertised condition.
func programmedCondition(advertisement *bgpv1alpha1.BGPAdvertisement) metav1.Condition {
	advertised := meta.FindStatusCondition(advertisement.Status.Conditions, galactic.ConditionAdvertised)
	condition := metav1.Condition{
		Type:    cloudv1alpha1.ConditionTypeProgrammed,
		Status:  metav1.ConditionUnknown,
		Reason:  "AwaitingDataPlane",
		Message: "the data plane has not reported on this attachment yet",
	}
	if advertised != nil {
		condition.Status = advertised.Status
		condition.Reason = advertised.Reason
		condition.Message = advertised.Message
	}
	if advertised != nil && advertised.Status == metav1.ConditionTrue &&
		advertisement.Annotations[galactic.AnnotationNoAddressing] == labelTrue {
		condition.Message = "attachment advertised; the guest manages its own addressing"
	}
	return condition
}

// SetupWithManager registers the reconciler with the manager.
func (r *BGPAdvertisementReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bgpv1alpha1.BGPAdvertisement{}).
		Watches(&cloudv1alpha1.VPCAttachment{}, handler.EnqueueRequestsFromMapFunc(advertisementForAttachment),
			builder.WithPredicates(predicate.Funcs{UpdateFunc: func(e event.UpdateEvent) bool {
				oldAttachment, oldOK := e.ObjectOld.(*cloudv1alpha1.VPCAttachment)
				newAttachment, newOK := e.ObjectNew.(*cloudv1alpha1.VPCAttachment)
				return oldOK && newOK && (oldAttachment.Status.Node != newAttachment.Status.Node ||
					oldAttachment.Status.VPC != newAttachment.Status.VPC ||
					oldAttachment.Status.VPCAttachment != newAttachment.Status.VPCAttachment)
			}})).
		Watches(&networkingv1alpha.NetworkInterface{},
			handler.EnqueueRequestsFromMapFunc(r.advertisementForInterface),
			builder.WithPredicates(predicate.Funcs{
				UpdateFunc: func(e event.UpdateEvent) bool {
					oldIface, oldOK := e.ObjectOld.(*networkingv1alpha.NetworkInterface)
					newIface, newOK := e.ObjectNew.(*networkingv1alpha.NetworkInterface)
					return oldOK && newOK && oldIface.Status.AttachmentRef != nil &&
						newIface.Status.AttachmentRef != nil &&
						oldIface.Status.AttachmentRef.APIGroup != newIface.Status.AttachmentRef.APIGroup &&
						newIface.Status.AttachmentRef.APIGroup == cloudv1alpha1.GroupVersion.Group
				},
			})).
		Named("bgpadvertisement").
		Complete(r)
}
