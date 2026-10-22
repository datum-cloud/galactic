// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package admission

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
)

// ProviderFromAPI converts an EdgeProvider into the Provider admission
// checks. Approval comes from status, which no provider identity may write.
func ProviderFromAPI(p *galacticv1alpha1.EdgeProvider) Provider {
	out := Provider{
		Name:             p.Name,
		Approved:         p.Status.Approved,
		ContractVersions: append([]string(nil), p.Spec.ContractVersions...),
		ConfigGroup:      p.Spec.Configuration.Group,
		ConfigKind:       p.Spec.Configuration.Kind,
	}
	for _, c := range p.Spec.Capabilities {
		out.Capabilities = append(out.Capabilities, Capability{Name: c.Name, Version: c.Version})
	}
	for _, sa := range p.Spec.ServiceAccounts {
		out.ServiceAccounts = append(out.ServiceAccounts, ServiceAccount{Namespace: sa.Namespace, Name: sa.Name})
	}
	return out
}

// GrantFromAPI converts an EdgeService into the Grant admission checks. A
// service being deleted is a revoked grant. It fails on a prefix the API
// should have refused.
func GrantFromAPI(s *galacticv1alpha1.EdgeService) (Grant, error) {
	g := Grant{
		UID:          string(s.UID),
		Generation:   s.Generation,
		Provider:     s.Spec.ProviderRef.Name,
		VPC:          s.Spec.VPCRef.UID,
		Capabilities: append([]string(nil), s.Spec.Capabilities...),
		Revoked:      !s.DeletionTimestamp.IsZero(),
	}
	if s.Spec.ValidUntil != nil {
		g.ValidUntil = s.Spec.ValidUntil.Time
	}
	for _, raw := range s.Spec.Prefixes {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p != p.Masked() {
			return Grant{}, fmt.Errorf("EdgeService %s/%s: prefix %q is not a masked CIDR", s.Namespace, s.Name, raw)
		}
		g.Prefixes = append(g.Prefixes, p)
	}
	return g, nil
}

// ProviderSource keeps an Authority's providers in step with the cell's
// EdgeProviders.
type ProviderSource struct {
	Reader    client.Reader
	Authority *Authority
}

// Reconcile loads one EdgeProvider into the Authority, or removes it once
// it is gone or being deleted.
func (s *ProviderSource) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var p galacticv1alpha1.EdgeProvider
	err := s.Reader.Get(ctx, req.NamespacedName, &p)
	switch {
	case apierrors.IsNotFound(err):
		s.Authority.DeleteProvider(req.Name)
	case err != nil:
		return reconcile.Result{}, err
	case !p.DeletionTimestamp.IsZero():
		s.Authority.DeleteProvider(p.Name)
	default:
		s.Authority.SetProvider(ProviderFromAPI(&p))
	}
	return reconcile.Result{}, nil
}

// SetupWithManager registers the source with mgr.
func (s *ProviderSource) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).Named("edge-admission-provider").
		For(&galacticv1alpha1.EdgeProvider{}).Complete(s)
}

// GrantSource keeps an Authority's grants in step with the cell's
// EdgeServices.
type GrantSource struct {
	Reader    client.Reader
	Authority *Authority

	mu sync.Mutex
	// uids maps each loaded service to its UID, so a service that is gone,
	// or was recreated under the same name, removes the grant it replaced.
	uids map[types.NamespacedName]string
}

// Reconcile loads one EdgeService into the Authority. A service that is gone,
// recreated or carries an invalid prefix revokes its previous grant.
func (s *GrantSource) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var svc galacticv1alpha1.EdgeService
	err := s.Reader.Get(ctx, req.NamespacedName, &svc)
	if err != nil && !apierrors.IsNotFound(err) {
		return reconcile.Result{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uids == nil {
		s.uids = map[types.NamespacedName]string{}
	}
	if old, ok := s.uids[req.NamespacedName]; ok && (err != nil || old != string(svc.UID)) {
		s.Authority.DeleteGrant(old)
		delete(s.uids, req.NamespacedName)
	}
	if err != nil {
		return reconcile.Result{}, nil
	}
	g, convErr := GrantFromAPI(&svc)
	if convErr != nil {
		s.Authority.DeleteGrant(string(svc.UID))
		delete(s.uids, req.NamespacedName)
		return reconcile.Result{}, reconcile.TerminalError(convErr)
	}
	s.Authority.SetGrant(g)
	s.uids[req.NamespacedName] = g.UID
	return reconcile.Result{}, nil
}

// SetupWithManager registers the source with mgr.
func (s *GrantSource) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).Named("edge-admission-grant").
		For(&galacticv1alpha1.EdgeService{}).Complete(s)
}
