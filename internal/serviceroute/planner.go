// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package serviceroute compiles service policy into node-local dataplane intents.
package serviceroute

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	networkv1alpha1 "go.datum.net/network/api/v1alpha1"
)

type RouteIntentKind string

const (
	RouteIntentLocal          RouteIntentKind = "Local"
	RouteIntentRemoteConsumer RouteIntentKind = "RemoteConsumer"
	RouteIntentRemoteProducer RouteIntentKind = "RemoteProducer"
)

type ServiceGrantID [16]byte

// RouteIntent is one node's half of an attachment-scoped service path.
type RouteIntent struct {
	Attachment         types.NamespacedName
	ProducerAttachment types.NamespacedName
	Kind               RouteIntentKind
	Service            *net.IPNet
	ConsumerDevice     string
	ServiceDevice      string
	ServiceSID         net.IP
	ConsumerSID        net.IP
	GrantID            ServiceGrantID
	Ports              []networkv1alpha1.ServiceRouteProtocolPort
}

type RouteProgrammer interface {
	Initialize() error
	Apply(RouteIntent) error
	Remove(RouteIntent) error
}

type SIDResolver func(*cloudv1alpha1.VPCAttachment) (net.IP, error)

// DependencyNotReadyError reports a valid policy whose node-local routing
// dependencies are not ready yet. It is distinct from a policy validation
// failure because every Galactic node reconciles the same status object while
// only participating nodes need to resolve a given attachment SID.
type DependencyNotReadyError struct{ Err error }

func (e *DependencyNotReadyError) Error() string { return e.Err.Error() }
func (e *DependencyNotReadyError) Unwrap() error { return e.Err }

// Compile deterministically picks one ready producer for every selected
// consumer and emits only intent halves owned by localNode.
func Compile(policy *networkv1alpha1.ServiceRoutePolicy, endpoint *networkv1alpha1.ServiceEndpoint,
	attachments []*cloudv1alpha1.VPCAttachment, localNode string, resolveSID SIDResolver,
) ([]RouteIntent, error) {
	if policy == nil || endpoint == nil {
		return nil, errors.New("service route policy and endpoint are required")
	}
	if policy.Spec.Region != "" && endpoint.Spec.Region != "" && policy.Spec.Region != endpoint.Spec.Region {
		return nil, fmt.Errorf("policy region %q does not match endpoint region %q", policy.Spec.Region, endpoint.Spec.Region)
	}
	consumerSelector, err := metav1.LabelSelectorAsSelector(&policy.Spec.AttachmentSelector)
	if err != nil {
		return nil, fmt.Errorf("compile consumer attachment selector: %w", err)
	}
	service, err := hostPrefix(endpoint.Spec.Address)
	if err != nil {
		return nil, fmt.Errorf("parse service endpoint address: %w", err)
	}
	ports, err := servicePorts(policy, endpoint)
	if err != nil {
		return nil, err
	}
	producers, err := producerCandidates(endpoint, attachments)
	if err != nil {
		return nil, err
	}

	consumers := readyAttachments(attachments)
	intents := make([]RouteIntent, 0, len(consumers))
	for _, consumer := range consumers {
		if consumer.Status.HostInterface == "" || !consumerSelector.Matches(labels.Set(consumer.Labels)) {
			continue
		}
		producer := chooseProducer(endpoint.Spec.DeliveryMode, consumer.Status.Node, producers)
		if producer == nil {
			continue
		}
		consumerKey := types.NamespacedName{Namespace: consumer.Namespace, Name: consumer.Name}
		producerKey := types.NamespacedName{Namespace: producer.Namespace, Name: producer.Name}
		if producer.Status.Node == consumer.Status.Node {
			if consumer.Status.Node == localNode {
				intents = append(intents, RouteIntent{
					Attachment: consumerKey, ProducerAttachment: producerKey, Kind: RouteIntentLocal,
					Service: cloneIPNet(service), ConsumerDevice: consumer.Status.HostInterface,
					ServiceDevice: producer.Status.HostInterface, Ports: clonePorts(ports),
				})
			}
			continue
		}
		if resolveSID == nil {
			return nil, errors.New("remote service routing requires a SID resolver")
		}
		grantID, err := serviceGrantID(policy, endpoint, consumer, producer, ports)
		if err != nil {
			return nil, err
		}
		if consumer.Status.Node == localNode {
			serviceSID, err := resolveSID(producer)
			if err != nil {
				return nil, &DependencyNotReadyError{Err: fmt.Errorf(
					"resolve producer attachment %s SID: %w", producerKey, err)}
			}
			intents = append(intents, RouteIntent{
				Attachment: consumerKey, ProducerAttachment: producerKey, Kind: RouteIntentRemoteConsumer,
				Service: cloneIPNet(service), ConsumerDevice: consumer.Status.HostInterface,
				ServiceSID: cloneIP(serviceSID), GrantID: grantID, Ports: clonePorts(ports),
			})
		}
		if producer.Status.Node == localNode {
			consumerSID, err := resolveSID(consumer)
			if err != nil {
				return nil, &DependencyNotReadyError{Err: fmt.Errorf(
					"resolve consumer attachment %s SID: %w", consumerKey, err)}
			}
			intents = append(intents, RouteIntent{
				Attachment: consumerKey, ProducerAttachment: producerKey, Kind: RouteIntentRemoteProducer,
				Service: cloneIPNet(service), ServiceDevice: producer.Status.HostInterface,
				ConsumerSID: cloneIP(consumerSID), GrantID: grantID, Ports: clonePorts(ports),
			})
		}
	}
	sort.Slice(intents, func(i, j int) bool {
		if intents[i].Attachment != intents[j].Attachment {
			return intents[i].Attachment.String() < intents[j].Attachment.String()
		}
		return intents[i].Kind < intents[j].Kind
	})
	return intents, nil
}

func producerCandidates(endpoint *networkv1alpha1.ServiceEndpoint,
	attachments []*cloudv1alpha1.VPCAttachment,
) ([]*cloudv1alpha1.VPCAttachment, error) {
	if (endpoint.Spec.AttachmentRef == nil) == (endpoint.Spec.AttachmentSelector == nil) {
		return nil, fmt.Errorf(
			"service endpoint %s must set exactly one of attachmentRef or attachmentSelector", endpoint.Name,
		)
	}
	ready := readyAttachments(attachments)
	if endpoint.Spec.AttachmentRef != nil {
		key := types.NamespacedName{Namespace: endpoint.Spec.AttachmentRef.Namespace, Name: endpoint.Spec.AttachmentRef.Name}
		for _, attachment := range ready {
			if (types.NamespacedName{Namespace: attachment.Namespace, Name: attachment.Name}) == key &&
				attachment.Status.HostInterface != "" {
				return []*cloudv1alpha1.VPCAttachment{attachment}, nil
			}
		}
		return nil, nil
	}
	selector, err := metav1.LabelSelectorAsSelector(endpoint.Spec.AttachmentSelector)
	if err != nil {
		return nil, fmt.Errorf("compile service attachment selector: %w", err)
	}
	producers := make([]*cloudv1alpha1.VPCAttachment, 0, len(ready))
	for _, attachment := range ready {
		if attachment.Status.HostInterface != "" && selector.Matches(labels.Set(attachment.Labels)) {
			producers = append(producers, attachment)
		}
	}
	return producers, nil
}

func readyAttachments(attachments []*cloudv1alpha1.VPCAttachment) []*cloudv1alpha1.VPCAttachment {
	ready := make([]*cloudv1alpha1.VPCAttachment, 0, len(attachments))
	for _, attachment := range attachments {
		if attachment == nil || attachment.Status.ObservedGeneration != attachment.Generation ||
			attachment.Status.Node == "" || attachment.Status.VPC == "" || attachment.Status.VPCAttachment == "" ||
			!apimeta.IsStatusConditionTrue(attachment.Status.Conditions, cloudv1alpha1.ConditionTypeReady) ||
			!apimeta.IsStatusConditionTrue(attachment.Status.Conditions, cloudv1alpha1.ConditionTypeProgrammed) {
			continue
		}
		ready = append(ready, attachment)
	}
	sort.Slice(ready, func(i, j int) bool {
		return types.NamespacedName{Namespace: ready[i].Namespace, Name: ready[i].Name}.String() <
			types.NamespacedName{Namespace: ready[j].Namespace, Name: ready[j].Name}.String()
	})
	return ready
}

func chooseProducer(mode networkv1alpha1.ServiceEndpointDeliveryMode, consumerNode string,
	producers []*cloudv1alpha1.VPCAttachment,
) *cloudv1alpha1.VPCAttachment {
	for _, producer := range producers {
		if producer.Status.Node == consumerNode {
			return producer
		}
	}
	if mode == networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal && len(producers) != 0 {
		return producers[0]
	}
	return nil
}

func servicePorts(policy *networkv1alpha1.ServiceRoutePolicy,
	endpoint *networkv1alpha1.ServiceEndpoint,
) ([]networkv1alpha1.ServiceRouteProtocolPort, error) {
	ports := clonePorts(policy.Spec.ProtocolPorts)
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
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Protocol != ports[j].Protocol {
			return ports[i].Protocol < ports[j].Protocol
		}
		return ports[i].Port < ports[j].Port
	})
	return ports, nil
}

func serviceGrantID(policy *networkv1alpha1.ServiceRoutePolicy, endpoint *networkv1alpha1.ServiceEndpoint,
	consumer, producer *cloudv1alpha1.VPCAttachment, ports []networkv1alpha1.ServiceRouteProtocolPort,
) (ServiceGrantID, error) {
	if policy.UID == "" || endpoint.UID == "" || consumer.UID == "" || producer.UID == "" {
		return ServiceGrantID{}, errors.New("remote service grant requires policy, endpoint, consumer, and producer UIDs")
	}
	h := sha256.New()
	for _, uid := range []types.UID{policy.UID, consumer.UID, endpoint.UID, producer.UID} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(uid)))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(uid))
	}
	for _, port := range ports {
		_, _ = h.Write([]byte(port.Protocol))
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], uint32(port.Port))
		_, _ = h.Write(encoded[:])
	}
	var id ServiceGrantID
	copy(id[:], h.Sum(nil))
	return id, nil
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
	return &net.IPNet{IP: cloneIP(in.IP), Mask: append(net.IPMask(nil), in.Mask...)}
}

func cloneIP(in net.IP) net.IP { return append(net.IP(nil), in...) }

func clonePorts(in []networkv1alpha1.ServiceRouteProtocolPort) []networkv1alpha1.ServiceRouteProtocolPort {
	return append([]networkv1alpha1.ServiceRouteProtocolPort(nil), in...)
}
