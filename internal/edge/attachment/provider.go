// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

const (
	// ProviderPolicy is the ValidatingAdmissionPolicy, with paramKind
	// EdgeProvider, that checks a provider's writes against its parameter.
	ProviderPolicy = "galactic-edge-provider"
	// ProviderClusterRole is what each approved provider's ServiceAccounts
	// are bound to in their own namespaces.
	ProviderClusterRole = "galactic-edge-provider"
	// ProviderLabel marks the bindings made for a provider with its UID.
	ProviderLabel = "galactic.datumapis.com/edge-provider-uid"
)

// ProviderBindingFinalizer holds an EdgeProvider until its bindings are
// withdrawn: a policy binding whose parameter is gone denies every write it
// matches, and garbage collection removes dependents in no set order.
const ProviderBindingFinalizer = "galactic.datumapis.com/edge-provider-bindings"

// ProviderBindingReconciler keeps, for each approved EdgeProvider, one
// ValidatingAdmissionPolicyBinding of ProviderPolicy whose parameter is the
// provider, and in each namespace of its listed ServiceAccounts one
// RoleBinding of ProviderClusterRole to them. A provider that is not
// approved, or is being deleted, has neither, so RBAC refuses its writes
// before the policy runs. The bindings are named after the provider, so a
// provider recreated under the same name takes over its predecessor's.
type ProviderBindingReconciler struct {
	Client client.Client
}

// Reconcile implements reconcile.Reconciler.
func (r *ProviderBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var p galacticv1alpha1.EdgeProvider
	if err := r.Client.Get(ctx, req.NamespacedName, &p); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	deleting := !p.DeletionTimestamp.IsZero()
	approved := p.Status.Approved && !deleting
	if approved && controllerutil.AddFinalizer(&p, ProviderBindingFinalizer) {
		if err := r.Client.Update(ctx, &p); err != nil {
			return ctrl.Result{}, err
		}
	}
	namespaces := map[string][]rbacv1.Subject{}
	if approved {
		for _, sa := range p.Spec.ServiceAccounts {
			namespaces[sa.Namespace] = append(namespaces[sa.Namespace], rbacv1.Subject{
				Kind: rbacv1.ServiceAccountKind, Namespace: sa.Namespace, Name: sa.Name,
			})
		}
	}
	name := bindingName(p.Name)

	// Withdraw RoleBindings first, so a revoked provider loses write access
	// before its policy binding goes.
	var existing rbacv1.RoleBindingList
	if err := r.Client.List(ctx, &existing, client.HasLabels{ProviderLabel}); err != nil {
		return ctrl.Result{}, err
	}
	var errs []error
	for i := range existing.Items {
		rb := &existing.Items[i]
		if rb.Name != name {
			continue
		}
		if _, ok := namespaces[rb.Namespace]; !ok {
			if err := r.Client.Delete(ctx, rb); client.IgnoreNotFound(err) != nil {
				errs = append(errs, err)
			}
		}
	}
	vapb := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if !approved {
		if len(errs) == 0 {
			errs = append(errs, client.IgnoreNotFound(r.Client.Delete(ctx, vapb)))
		}
		if err := errors.Join(errs...); err != nil || !deleting {
			return ctrl.Result{}, err
		}
		if controllerutil.RemoveFinalizer(&p, ProviderBindingFinalizer) {
			return ctrl.Result{}, client.IgnoreNotFound(r.Client.Update(ctx, &p))
		}
		return ctrl.Result{}, nil
	}

	// The policy binding goes in before the RoleBindings, so no write is
	// ever allowed without the provider's checks.
	owner := []metav1.OwnerReference{*metav1.NewControllerRef(&p, galacticv1alpha1.GroupVersion.WithKind("EdgeProvider"))}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, vapb, func() error {
		vapb.Labels = map[string]string{ProviderLabel: string(p.UID)}
		vapb.OwnerReferences = owner
		deny := admissionregistrationv1.DenyAction
		vapb.Spec = admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        ProviderPolicy,
			ParamRef:          &admissionregistrationv1.ParamRef{Name: p.Name, ParameterNotFoundAction: &deny},
			ValidationActions: []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny},
		}
		return nil
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("apply policy binding %s: %w", name, err)
	}
	// A namespace that cannot take its binding, such as one not created yet,
	// does not hold up the others.
	for _, ns := range sortedKeys(namespaces) {
		rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
		if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, rb, func() error {
			if rb.RoleRef.Name != "" && rb.RoleRef.Name != ProviderClusterRole {
				return fmt.Errorf("RoleBinding %s/%s binds %s, not %s", ns, name, rb.RoleRef.Name, ProviderClusterRole)
			}
			rb.Labels = map[string]string{ProviderLabel: string(p.UID)}
			rb.OwnerReferences = owner
			rb.RoleRef = rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: ProviderClusterRole}
			rb.Subjects = namespaces[ns]
			return nil
		}); err != nil {
			errs = append(errs, fmt.Errorf("apply RoleBinding %s/%s: %w", ns, name, err))
		}
	}
	return ctrl.Result{}, errors.Join(errs...)
}

// bindingName names a provider's bindings, hashing a name too long to carry.
func bindingName(provider string) string {
	name := ProviderPolicy + "-" + provider
	if len(name) <= 253 {
		return name
	}
	sum := sha256.Sum256([]byte(provider))
	return ProviderPolicy + "-" + hex.EncodeToString(sum[:16])
}

func sortedKeys(m map[string][]rbacv1.Subject) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// SetupWithManager registers the reconciler. A nil Client is the manager's.
func (r *ProviderBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Client == nil {
		r.Client = mgr.GetClient()
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("edge-provider-bindings").
		For(&galacticv1alpha1.EdgeProvider{}).
		Owns(&admissionregistrationv1.ValidatingAdmissionPolicyBinding{}).
		Owns(&rbacv1.RoleBinding{}).
		Complete(r)
}
