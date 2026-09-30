// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package serviceroute compiles internal service-routing policy into the
// node-local route intents consumed by Galactic's dataplane programmer.
package serviceroute

import (
	"fmt"
	"net"
	"sort"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

// RouteIntent describes one local bidirectional service route. The consumer
// prefix is taken from VPCAttachment.status.podSubnet; the service prefix is
// the endpoint address as a host route.
type RouteIntent struct {
	Attachment     types.NamespacedName
	Consumer       *net.IPNet
	Service        *net.IPNet
	ConsumerVPC    string
	ConsumerDevice string
	ServiceVPC     string
	ServiceDevice  string
	Ports          []networkv1alpha1.ServiceRouteProtocolPort
}

// Compile evaluates policy against attachments assigned to localNode and
// returns deterministic route intents. The caller can pass the result to a
// dataplane programmer without creating per-attachment API objects.
func Compile(
	policy *networkv1alpha1.ServiceRoutePolicy,
	endpoint *networkv1alpha1.ServiceEndpoint,
	attachments []*cloudv1alpha1.VPCAttachment,
	localNode string,
) ([]RouteIntent, error) {
	if policy == nil || endpoint == nil {
		return nil, fmt.Errorf("service route policy and endpoint are required")
	}
	if policy.Spec.Region != "" && endpoint.Spec.Region != "" && policy.Spec.Region != endpoint.Spec.Region {
		return nil, fmt.Errorf("policy region %q does not match endpoint region %q", policy.Spec.Region, endpoint.Spec.Region)
	}
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.AttachmentSelector)
	if err != nil {
		return nil, fmt.Errorf("compile attachment selector: %w", err)
	}
	service, err := hostPrefix(endpoint.Spec.Address)
	if err != nil {
		return nil, fmt.Errorf("parse service endpoint address: %w", err)
	}
	if endpoint.Spec.AttachmentRef == nil {
		return nil, fmt.Errorf("service endpoint %s requires attachmentRef for local service routing", endpoint.Name)
	}
	serviceKey := types.NamespacedName{Namespace: endpoint.Spec.AttachmentRef.Namespace, Name: endpoint.Spec.AttachmentRef.Name}
	var serviceAttachment *cloudv1alpha1.VPCAttachment
	for _, attachment := range attachments {
		if attachment == nil {
			continue
		}
		attachmentKey := types.NamespacedName{Namespace: attachment.Namespace, Name: attachment.Name}
		if attachmentKey == serviceKey {
			serviceAttachment = attachment
			break
		}
	}
	if serviceAttachment == nil || serviceAttachment.Status.Node != localNode {
		return nil, nil
	}
	if serviceAttachment.Status.VPC == "" || serviceAttachment.Status.HostInterface == "" {
		return nil, fmt.Errorf("service attachment %s/%s is missing VPC or host interface status", serviceKey.Namespace, serviceKey.Name)
	}

	ports := append([]networkv1alpha1.ServiceRouteProtocolPort(nil), policy.Spec.ProtocolPorts...)
	if len(ports) == 0 {
		ports = []networkv1alpha1.ServiceRouteProtocolPort{{Protocol: endpoint.Spec.Protocol, Port: endpoint.Spec.Port}}
	}

	intents := make([]RouteIntent, 0, len(attachments))
	for _, attachment := range attachments {
		if attachment == nil || attachment.Status.Node != localNode || !selector.Matches(labels.Set(attachment.Labels)) {
			continue
		}
		_, consumer, err := net.ParseCIDR(attachment.Status.PodSubnet)
		if err != nil {
			return nil, fmt.Errorf("attachment %s/%s has invalid podSubnet %q: %w", attachment.Namespace, attachment.Name, attachment.Status.PodSubnet, err)
		}
		intents = append(intents, RouteIntent{
			Attachment:     types.NamespacedName{Namespace: attachment.Namespace, Name: attachment.Name},
			Consumer:       consumer,
			Service:        cloneIPNet(service),
			ConsumerVPC:    attachment.Status.VPC,
			ConsumerDevice: attachment.Status.HostInterface,
			ServiceVPC:     serviceAttachment.Status.VPC,
			ServiceDevice:  serviceAttachment.Status.HostInterface,
			Ports:          append([]networkv1alpha1.ServiceRouteProtocolPort(nil), ports...),
		})
	}
	sort.Slice(intents, func(i, j int) bool { return intents[i].Attachment.String() < intents[j].Attachment.String() })
	return intents, nil
}

func hostPrefix(address string) (*net.IPNet, error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, fmt.Errorf("%q is not an IP address", address)
	}
	if ip.To4() != nil {
		return &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}, nil
}

func cloneIPNet(in *net.IPNet) *net.IPNet {
	return &net.IPNet{IP: append(net.IP(nil), in.IP...), Mask: append(net.IPMask(nil), in.Mask...)}
}
