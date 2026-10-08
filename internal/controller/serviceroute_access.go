// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"k8s.io/apimachinery/pkg/types"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/serviceroute"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const maxServiceAuthorizationDuration = 2 * time.Minute

func (r *ServiceRoutePolicyReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *ServiceRoutePolicyReconciler) validateAuthorization(policy *networkv1alpha1.ServiceRoutePolicy) error {
	if policy.Spec.Frontend == nil {
		return nil
	}
	if policy.Spec.Authorization == nil {
		return errors.New("frontend translation requires authorization.validUntil")
	}
	deadline := policy.Spec.Authorization.ValidUntil.Time
	now := r.now()
	if !deadline.After(now) || deadline.After(now.Add(maxServiceAuthorizationDuration)) {
		return errors.New("network authorization deadline must be within the next two minutes")
	}
	return nil
}

func (r *ServiceRoutePolicyReconciler) conflictingPolicies(
	ctx context.Context, attachments []*cloudv1alpha1.VPCAttachment,
) (map[types.NamespacedName]bool, error) {
	policies := &networkv1alpha1.ServiceRoutePolicyList{}
	if err := r.List(ctx, policies); err != nil {
		return nil, fmt.Errorf("list service policy conflicts: %w", err)
	}
	desired := map[types.NamespacedName][]serviceroute.RouteIntent{}
	translated := map[types.NamespacedName]bool{}
	nodes := map[string]bool{}
	for _, a := range attachments {
		nodes[a.Status.Node] = true
	}
	for i := range policies.Items {
		p := &policies.Items[i]
		if p.DeletionTimestamp != nil || r.validateAuthorization(p) != nil || (p.Spec.Frontend != nil && !r.FrontendEnabled) {
			continue
		}
		endpoint := &networkv1alpha1.ServiceEndpoint{}
		if err := r.Get(ctx, types.NamespacedName{
			Namespace: p.Namespace,
			Name:      p.Spec.ServiceRef.Name,
		}, endpoint); err != nil {
			continue
		}
		identity, err := r.consumerVPCIdentity(ctx, p)
		if err != nil {
			continue
		}
		key := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}
		translated[key] = p.Spec.Frontend != nil
		for node := range nodes {
			intents, err := serviceroute.CompileForConsumerVPC(p, endpoint, attachments, node,
				func(*cloudv1alpha1.VPCAttachment) (net.IP, error) { return net.ParseIP("fd00::1"), nil }, identity)
			if err == nil {
				desired[key] = append(desired[key], intents...)
			}
		}
	}
	return serviceroute.ConflictingPolicies(desired, translated), nil
}
