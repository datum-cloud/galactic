// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"context"
	"errors"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/serviceroute"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

const serviceProgrammingAckDuration = 60 * time.Second

func (r *ServiceRoutePolicyReconciler) setNodeProgramming(
	ctx context.Context, policy *networkv1alpha1.ServiceRoutePolicy, digest string, ready bool,
) error {
	deadline := r.now().Add(serviceProgrammingAckDuration)
	if policy.Spec.Authorization != nil && policy.Spec.Authorization.ValidUntil.Before(&metav1.Time{Time: deadline}) {
		deadline = policy.Spec.Authorization.ValidUntil.Time
	}
	report := networkv1alpha1.ServiceRouteNodeStatus{
		NodeName:           r.NodeName,
		PolicyUID:          string(policy.UID),
		ObservedGeneration: policy.Generation,
		InputDigest:        digest,
		Ready:              ready,
		ValidUntil:         metav1.NewTime(deadline),
	}
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		current := &networkv1alpha1.ServiceRoutePolicy{}
		key := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}
		if err := r.Get(ctx, key, current); err != nil {
			return err
		}
		if current.UID != policy.UID || current.Generation != policy.Generation {
			return errors.New("policy changed before programming acknowledgment")
		}
		found := false
		for i := range current.Status.Nodes {
			if current.Status.Nodes[i].NodeName == r.NodeName {
				current.Status.Nodes[i] = report
				found = true
			}
		}
		if !found && !ready {
			return nil
		}
		if !found {
			current.Status.Nodes = append(current.Status.Nodes, report)
		}
		sort.Slice(current.Status.Nodes, func(i, j int) bool {
			return current.Status.Nodes[i].NodeName < current.Status.Nodes[j].NodeName
		})
		return r.Status().Update(ctx, current)
	})
}

func serviceProgrammingDigest(policy *networkv1alpha1.ServiceRoutePolicy, endpoint *networkv1alpha1.ServiceEndpoint,
	attachments []*cloudv1alpha1.VPCAttachment, vpcIdentity string,
) string {
	plan, err := serviceroute.ProgrammingPlan(policy, endpoint, attachments, vpcIdentity)
	if err != nil {
		return ""
	}
	return plan.InputDigest
}
