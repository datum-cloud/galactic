package controller

import (
	"context"
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha "github.com/datum-cloud/galactic-operator/api/v1alpha"
	"github.com/datum-cloud/galactic-operator/internal/identifier"
)

const MaxIdentifierAttemptsVPC = 100

type VPCReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	Identifier *identifier.Identifier
}

// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=vpcs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=vpcs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=galactic.datumapis.com,resources=vpcs/finalizers,verbs=update

func (r *VPCReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var vpc galacticv1alpha.VPC
	if err := r.Get(ctx, req.NamespacedName, &vpc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// We only assign an identifier once
	if vpc.Status.Identifier == "" {
		var existingVpcs galacticv1alpha.VPCList
		if err := r.List(ctx, &existingVpcs, &client.ListOptions{}); err != nil {
			return ctrl.Result{}, err
		}
		existingIdentifiers := vpcsToIdentifiers(existingVpcs)

		for i := 0; i <= MaxIdentifierAttemptsVPC; i++ {
			if i == MaxIdentifierAttemptsVPC {
				return ctrl.Result{}, fmt.Errorf("could not find an unused identifier after %d attempts", MaxIdentifierAttemptsVPC)
			}
			if vpc.Status.Identifier != "" && !slices.Contains(existingIdentifiers, vpc.Status.Identifier) {
				break
			}
			vpc.Status.Identifier, _ = r.Identifier.ForVPC()
		}

		vpc.Status.Ready = true

		if err := r.Status().Update(ctx, &vpc); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *VPCReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&galacticv1alpha.VPC{}).
		Named("vpc").
		Complete(r)
}

func vpcsToIdentifiers(vpcs galacticv1alpha.VPCList) []string {
	identifiers := make([]string, 0, len(vpcs.Items))
	for _, vpc := range vpcs.Items {
		if vpc.Status.Identifier != "" {
			identifiers = append(identifiers, vpc.Status.Identifier)
		}
	}
	return identifiers
}
