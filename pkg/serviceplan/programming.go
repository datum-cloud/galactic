// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// ErrNoEligibleConsumers is returned by ProgrammingPlan when no consumer
// attachment the policy selects is placed on a node, so there is no path to
// program yet. A placed consumer that is not ready yet returns
// ErrConsumersNotReady instead.
var ErrNoEligibleConsumers = errors.New("no eligible consumer attachments")

// ErrConsumersNotReady is returned by ProgrammingPlan when consumer
// attachments the policy selects are placed on a node but none of them is
// ready yet.
var ErrConsumersNotReady = errors.New("no consumer attachment is ready")

// ProgrammingRequirements fences acknowledgments to a complete topology snapshot.
type ProgrammingRequirements struct {
	// InputDigest identifies the policy, endpoint and attachment inputs the
	// plan was computed from. A node's report in ServiceRoutePolicy
	// status.nodes counts only when it carries the same digest.
	InputDigest string
	// Nodes lists, sorted, every node that must report the path programmed:
	// each selected consumer's node and each node holding a producer that
	// serves one of them.
	Nodes []string
}

// servingProducers returns the producers whose node installs part of
// consumer's path: its node-local producer, or every remote producer that
// accepts it under any Spread pairing, whichever pairing the consumer's node
// uses.
func servingProducers(endpoint *networkv1alpha1.ServiceEndpoint, consumer *cloudv1alpha1.VPCAttachment,
	producers []*cloudv1alpha1.VPCAttachment, health map[types.UID]producerHealth,
) ([]*cloudv1alpha1.VPCAttachment, error) {
	local, remote := selectProducers(endpoint, consumer, producers, health, SpreadPairingFirst)
	if len(local) != 0 {
		return local[:1], nil
	}
	if remote == nil {
		return nil, fmt.Errorf("consumer attachment %s/%s has no eligible producer", consumer.Namespace, consumer.Name)
	}
	return acceptedProducers(endpoint, consumer, producers, health, remote), nil
}

// ProgrammingPlan identifies every consumer and selected producer node required
// to serve a policy. Attachment health establishes network eligibility only.
// It selects producers exactly as Compile does on every node, Spread endpoints
// included, so a caller that waits for every node in Nodes to report
// InputDigest waits for the nodes the routers program. For a Spread endpoint,
// pass the endpoint through WithProducerReports first. consumerVPCIdentity,
// when set, selects only consumers whose status carries that VPC identity; a
// policy with a frontend requires it.
//
// For a Spread endpoint the plan depends on which producer reports are
// current, so it can change when a report expires without any object
// changing. A caller should recompute it when a ServiceEndpointProducerReport
// changes and at the time NextProducerReportExpiry returns.
func ProgrammingPlan(policy *networkv1alpha1.ServiceRoutePolicy, endpoint *networkv1alpha1.ServiceEndpoint,
	attachments []*cloudv1alpha1.VPCAttachment, consumerVPCIdentity string,
) (ProgrammingRequirements, error) {
	return ProgrammingPlanAt(policy, endpoint, attachments, consumerVPCIdentity, time.Now())
}

// ProgrammingPlanAt is ProgrammingPlan with producer reports judged current
// or expired as of now.
func ProgrammingPlanAt(policy *networkv1alpha1.ServiceRoutePolicy, endpoint *networkv1alpha1.ServiceEndpoint,
	attachments []*cloudv1alpha1.VPCAttachment, consumerVPCIdentity string, now time.Time,
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
	health := producersHealth(endpoint, producers, now)
	ready := map[types.NamespacedName]bool{}
	for _, a := range readyAttachments(attachments) {
		ready[types.NamespacedName{Namespace: a.Namespace, Name: a.Name}] = a.Status.HostInterface != ""
	}
	relevant := map[types.NamespacedName]bool{}
	for _, p := range producers {
		relevant[types.NamespacedName{Namespace: p.Namespace, Name: p.Name}] = true
	}
	nodes := map[string]bool{}
	selected, placed := 0, 0
	sorted := sortedAttachments(attachments)
	for _, a := range sorted {
		if !selector.Matches(labels.Set(a.Labels)) {
			continue
		}
		if !consumerMatchesVPC(policy, a, consumerVPCIdentity) {
			continue
		}
		relevant[types.NamespacedName{Namespace: a.Namespace, Name: a.Name}] = true
		if a.DeletionTimestamp == nil && a.Status.Node != "" {
			placed++
		}
		if a.DeletionTimestamp != nil || !ready[types.NamespacedName{Namespace: a.Namespace, Name: a.Name}] {
			continue
		}
		selected++
		serving, err := servingProducers(endpoint, a, producers, health)
		if err != nil {
			return plan, err
		}
		nodes[a.Status.Node] = true
		for _, p := range serving {
			if policy.Spec.Frontend != nil && (a.UID == "" || p.UID == "") {
				return plan, errors.New("translated programming requires current attachment UIDs")
			}
			nodes[p.Status.Node] = true
		}
	}
	if selected == 0 && placed == 0 {
		return plan, ErrNoEligibleConsumers
	}
	if selected == 0 {
		return plan, ErrConsumersNotReady
	}
	plan.InputDigest, err = programmingDigest(policy, endpoint, consumerVPCIdentity, sorted, relevant)
	if err != nil {
		return plan, err
	}
	for node := range nodes {
		plan.Nodes = append(plan.Nodes, node)
	}
	sort.Strings(plan.Nodes)
	return plan, nil
}

// sortedAttachments returns the attachments that are not nil, ordered by
// namespace and name.
func sortedAttachments(attachments []*cloudv1alpha1.VPCAttachment) []*cloudv1alpha1.VPCAttachment {
	sorted := make([]*cloudv1alpha1.VPCAttachment, 0, len(attachments))
	for _, a := range attachments {
		if a != nil {
			sorted = append(sorted, a)
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Namespace+"/"+sorted[i].Name < sorted[j].Namespace+"/"+sorted[j].Name
	})
	return sorted
}

// programmingDigest hashes the inputs of a plan: policy, endpoint, the
// consumer VPC identity and the relevant attachments of sorted.
func programmingDigest(policy *networkv1alpha1.ServiceRoutePolicy, endpoint *networkv1alpha1.ServiceEndpoint,
	consumerVPCIdentity string, sorted []*cloudv1alpha1.VPCAttachment, relevant map[types.NamespacedName]bool,
) (string, error) {
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
		return "", fmt.Errorf("encode service programming snapshot: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
