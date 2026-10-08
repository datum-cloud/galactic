// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// ProgrammingRequirements fences acknowledgments to a complete topology snapshot.
type ProgrammingRequirements struct {
	InputDigest string
	Nodes       []string
}

// ProgrammingPlan identifies every consumer and selected producer node required
// to serve a policy. Attachment health establishes network eligibility only.
func ProgrammingPlan(policy *networkv1alpha1.ServiceRoutePolicy, endpoint *networkv1alpha1.ServiceEndpoint,
	attachments []*cloudv1alpha1.VPCAttachment, consumerVPCIdentity string,
) (ProgrammingRequirements, error) {
	plan := ProgrammingRequirements{}
	if policy == nil || endpoint == nil {
		return plan, errors.New("policy and endpoint are required")
	}
	if policy.Spec.Frontend != nil && (policy.UID == "" || endpoint.UID == "" || consumerVPCIdentity == "") {
		return plan, errors.New("translated programming requires current policy, endpoint, and VPC identities")
	}
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.AttachmentSelector)
	if err != nil {
		return plan, err
	}
	producers, err := producerCandidates(endpoint, attachments)
	if err != nil {
		return plan, err
	}
	if err := validateProducerTopology(endpoint, producers); err != nil {
		return plan, err
	}
	ready := map[types.NamespacedName]bool{}
	for _, a := range readyAttachments(attachments) {
		ready[types.NamespacedName{Namespace: a.Namespace, Name: a.Name}] = a.Status.HostInterface != ""
	}
	relevant := map[types.NamespacedName]bool{}
	for _, p := range producers {
		relevant[types.NamespacedName{Namespace: p.Namespace, Name: p.Name}] = true
	}
	nodes := map[string]bool{}
	selected := 0
	sorted := make([]*cloudv1alpha1.VPCAttachment, 0, len(attachments))
	for _, a := range attachments {
		if a != nil {
			sorted = append(sorted, a)
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Namespace+"/"+sorted[i].Name < sorted[j].Namespace+"/"+sorted[j].Name
	})
	for _, a := range sorted {
		if !selector.Matches(labels.Set(a.Labels)) {
			continue
		}
		if !consumerMatchesVPC(policy, a, consumerVPCIdentity) {
			continue
		}
		relevant[types.NamespacedName{Namespace: a.Namespace, Name: a.Name}] = true
		selected++
		if a.DeletionTimestamp != nil || !ready[types.NamespacedName{Namespace: a.Namespace, Name: a.Name}] {
			return plan, fmt.Errorf("consumer attachment %s/%s is not ready", a.Namespace, a.Name)
		}
		p := chooseProducer(endpoint.Spec.DeliveryMode, a.Status.Node, producers)
		if p == nil {
			return plan, fmt.Errorf("consumer attachment %s/%s has no eligible producer", a.Namespace, a.Name)
		}
		if policy.Spec.Frontend != nil && (a.UID == "" || p.UID == "") {
			return plan, errors.New("translated programming requires current attachment UIDs")
		}
		nodes[a.Status.Node], nodes[p.Status.Node] = true, true
	}
	if selected == 0 {
		return plan, errors.New("no eligible consumer attachments")
	}
	// Resource versions and node reports are excluded: heartbeat writes do not
	// invalidate the desired topology. UIDs, generations, specs, and statuses do.
	snapshot := struct {
		PolicyUID          types.UID
		PolicyGeneration   int64
		PolicySpec         networkv1alpha1.ServiceRoutePolicySpec
		EndpointUID        types.UID
		EndpointGeneration int64
		EndpointSpec       networkv1alpha1.ServiceEndpointSpec
		VPCIdentity        string
		Attachments        []any
	}{PolicyUID: policy.UID, PolicyGeneration: policy.Generation, PolicySpec: policy.Spec,
		EndpointUID: endpoint.UID, EndpointGeneration: endpoint.Generation, EndpointSpec: endpoint.Spec,
		VPCIdentity: consumerVPCIdentity}
	for _, a := range sorted {
		if !relevant[types.NamespacedName{Namespace: a.Namespace, Name: a.Name}] {
			continue
		}
		snapshot.Attachments = append(snapshot.Attachments, struct {
			Namespace, Name string
			UID             types.UID
			Generation      int64
			Labels          map[string]string
			Deleted         bool
			Spec            cloudv1alpha1.VPCAttachmentSpec
			Status          cloudv1alpha1.VPCAttachmentStatus
		}{a.Namespace, a.Name, a.UID, a.Generation, a.Labels, a.DeletionTimestamp != nil, a.Spec, a.Status})
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return plan, fmt.Errorf("encode service programming snapshot: %w", err)
	}
	sum := sha256.Sum256(encoded)
	plan.InputDigest = hex.EncodeToString(sum[:])
	for node := range nodes {
		plan.Nodes = append(plan.Nodes, node)
	}
	sort.Strings(plan.Nodes)
	return plan, nil
}
