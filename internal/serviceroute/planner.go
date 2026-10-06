// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package serviceroute compiles internal service-routing policy into the
// node-local route intents consumed by Galactic's dataplane programmer.
package serviceroute

import (
	"errors"
	"fmt"
	"net"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// RouteIntent describes one local, attachment-scoped service path. Consumer
// addresses are learned from authorized packets, so guest-managed attachments
// do not need to publish a podSubnet.
type RouteIntent struct {
	Attachment     types.NamespacedName
	Service        *net.IPNet
	ConsumerDevice string
	ServiceDevice  string
	Ports          []networkv1alpha1.ServiceRouteProtocolPort
}

// RouteProgrammer applies a local service path. Implementations must make
// repeated Apply and Remove calls safe so reconciliation can resume after a
// partial failure.
type RouteProgrammer interface {
	Apply(RouteIntent) error
	Remove(RouteIntent) error
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
		return nil, errors.New("service route policy and endpoint are required")
	}
	if policy.Spec.Region != "" && endpoint.Spec.Region != "" && policy.Spec.Region != endpoint.Spec.Region {
		return nil, fmt.Errorf("policy region %q does not match endpoint region %q", policy.Spec.Region, endpoint.Spec.Region)
	}
	if endpoint.Spec.DeliveryMode != networkv1alpha1.ServiceEndpointDeliveryModeNodeLocal {
		return nil, fmt.Errorf("service endpoint %s has unsupported deliveryMode %q",
			endpoint.Name, endpoint.Spec.DeliveryMode)
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
	serviceKey := types.NamespacedName{
		Namespace: endpoint.Spec.AttachmentRef.Namespace,
		Name:      endpoint.Spec.AttachmentRef.Name,
	}
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
	if serviceAttachment.Status.HostInterface == "" {
		return nil, fmt.Errorf("service attachment %s/%s is missing host interface status",
			serviceKey.Namespace, serviceKey.Name)
	}

	ports := append([]networkv1alpha1.ServiceRouteProtocolPort(nil), policy.Spec.ProtocolPorts...)
	if len(ports) == 0 {
		ports = []networkv1alpha1.ServiceRouteProtocolPort{{Protocol: endpoint.Spec.Protocol, Port: endpoint.Spec.Port}}
	} else {
		for _, port := range ports {
			if port.Protocol != endpoint.Spec.Protocol || port.Port != endpoint.Spec.Port {
				return nil, fmt.Errorf("policy protocolPorts must be a subset of endpoint %s/%d",
					endpoint.Spec.Protocol, endpoint.Spec.Port)
			}
		}
	}

	intents := make([]RouteIntent, 0, len(attachments))
	for _, attachment := range attachments {
		if attachment == nil || attachment.Status.Node != localNode || !selector.Matches(labels.Set(attachment.Labels)) {
			continue
		}
		if attachment.Status.HostInterface == "" {
			continue
		}
		intents = append(intents, RouteIntent{
			Attachment:     types.NamespacedName{Namespace: attachment.Namespace, Name: attachment.Name},
			Service:        cloneIPNet(service),
			ConsumerDevice: attachment.Status.HostInterface,
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
