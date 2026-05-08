// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	nadv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	galacticv1alpha "go.datum.net/galactic/pkg/apis/v1alpha"

	"go.datum.net/galactic/internal/operator/bgpattrs"
	"go.datum.net/galactic/internal/operator/cniconfig"
	"go.datum.net/galactic/internal/operator/identifier"
	"go.datum.net/galactic/internal/operator/srv6sid"
)

const MaxIdentifierAttemptsVPCAttachment = 100

type VPCAttachmentReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	Identifier   *identifier.Identifier
	SIDEncoder   *srv6sid.Encoder
	BGPFormatter *bgpattrs.Formatter
}

// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=vpcattachments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=vpcattachments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=vpcattachments/finalizers,verbs=update
// +kubebuilder:rbac:groups=k8s.cni.cncf.io,resources=network-attachment-definitions,verbs=get;list;watch;create;update;patch;delete

func (r *VPCAttachmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var vpcAttachment galacticv1alpha.VPCAttachment
	if err := r.Get(ctx, req.NamespacedName, &vpcAttachment); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	vpcNamespacedName := types.NamespacedName{
		Namespace: vpcAttachment.Spec.VPC.Namespace,
		Name:      vpcAttachment.Spec.VPC.Name,
	}
	var vpc galacticv1alpha.VPC
	if err := r.Get(ctx, vpcNamespacedName, &vpc); err != nil {
		return ctrl.Result{}, err
	}
	if !vpc.Status.Ready {
		return ctrl.Result{RequeueAfter: 1 * time.Second}, nil
	}

	// Identifier assignment is one-shot. Once status.Identifier is set
	// it is never reassigned — the VRF and SRv6 SID derived from it are
	// part of the attachment's stable identity for its entire lifetime.
	statusDirty := false
	if vpcAttachment.Status.Identifier == "" {
		var existingVpcAttachments galacticv1alpha.VPCAttachmentList
		if err := r.List(ctx, &existingVpcAttachments, &client.ListOptions{}); err != nil {
			return ctrl.Result{}, err
		}
		existingIdentifiers := vpcAttachmentsToIdentifiers(vpc, existingVpcAttachments)

		for i := 0; i <= MaxIdentifierAttemptsVPCAttachment; i++ {
			if i == MaxIdentifierAttemptsVPCAttachment {
				return ctrl.Result{}, fmt.Errorf("could not find an unused identifier after %d attempts", MaxIdentifierAttemptsVPCAttachment)
			}
			if vpcAttachment.Status.Identifier != "" && !slices.Contains(existingIdentifiers, vpcAttachment.Status.Identifier) {
				break
			}
			vpcAttachment.Status.Identifier, _ = r.Identifier.ForVPCAttachment()
		}
		statusDirty = true
	}

	// Service SID, route target, and route distinguisher are computed
	// from the (vpc-id, attachment-id) pair plus the operator's
	// POP-locator + ASN. They are deterministic — set them whenever
	// they're missing, but never recompute if they're already present.
	// Recomputation would cause a silent mismatch with whatever the
	// agents have already advertised over BGP.
	if vpcAttachment.Status.ServiceSID == "" {
		sid, err := r.SIDEncoder.ForAttachment(vpc.Status.Identifier, vpcAttachment.Status.Identifier)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("compute service SID: %w", err)
		}
		vpcAttachment.Status.ServiceSID = sid
		statusDirty = true
	}
	if vpcAttachment.Status.RouteTarget == "" {
		rt, err := r.BGPFormatter.RT(vpc.Status.Identifier)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("compute route target: %w", err)
		}
		vpcAttachment.Status.RouteTarget = rt
		statusDirty = true
	}
	if vpcAttachment.Status.RouteDistinguisher == "" {
		rd, err := r.BGPFormatter.RD(vpc.Status.Identifier)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("compute route distinguisher: %w", err)
		}
		vpcAttachment.Status.RouteDistinguisher = rd
		statusDirty = true
	}

	if statusDirty {
		vpcAttachment.Status.Ready = true
		if err := r.Status().Update(ctx, &vpcAttachment); err != nil {
			return ctrl.Result{}, err
		}
	}

	nad := &nadv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:      vpcAttachment.Name,
			Namespace: vpcAttachment.Namespace,
		},
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, nad, func() error {
		cniPluginConfig, err := cniconfig.CNIConfigForVPCAttachment(vpc, vpcAttachment)
		if err != nil {
			return err
		}
		cniPluginConfigJson, _ := json.Marshal(cniPluginConfig)

		nad.Spec = nadv1.NetworkAttachmentDefinitionSpec{
			Config: string(cniPluginConfigJson),
		}

		if err := controllerutil.SetControllerReference(&vpcAttachment, nad, r.Scheme); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *VPCAttachmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&galacticv1alpha.VPCAttachment{}).
		Named("vpcattachment").
		Complete(r)
}

func vpcAttachmentsToIdentifiers(vpc galacticv1alpha.VPC, vpcAttachments galacticv1alpha.VPCAttachmentList) []string {
	identifiers := make([]string, 0, len(vpcAttachments.Items))
	for _, vpcAttachment := range vpcAttachments.Items {
		if vpcAttachment.Status.Identifier != "" &&
			vpcAttachment.Spec.VPC.Name == vpc.Name &&
			vpcAttachment.Spec.VPC.Namespace == vpc.Namespace {
			identifiers = append(identifiers, vpcAttachment.Status.Identifier)
		}
	}
	return identifiers
}
