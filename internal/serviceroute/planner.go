// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package serviceroute compiles service policy into node-local dataplane intents.
package serviceroute

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"time"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

type RouteIntentKind string

const (
	RouteIntentLocal          RouteIntentKind = "Local"
	RouteIntentLocalSet       RouteIntentKind = "LocalSet"
	RouteIntentRemoteConsumer RouteIntentKind = "RemoteConsumer"
	RouteIntentRemoteProducer RouteIntentKind = "RemoteProducer"
)

type ServiceGrantID [16]byte

// RouteIntent is one node's half of an attachment-scoped service path.
type RouteIntent struct {
	Attachment              types.NamespacedName
	ProducerAttachment      types.NamespacedName
	Kind                    RouteIntentKind
	Service                 *net.IPNet
	Frontend                *net.IPNet
	ConsumerDevice          string
	ServiceDevice           string
	ConsumerNextHop         net.IP
	ServiceNextHop          net.IP
	ServiceSID              net.IP
	ConsumerSID             net.IP
	GrantID                 ServiceGrantID
	AuthorizationValidUntil time.Time
	Ports                   []networkv1alpha1.ServiceRouteProtocolPort
	// Producers holds every producer on the consumer's node for a
	// RouteIntentLocalSet intent, ordered by attachment name. It is empty for
	// every other kind.
	Producers []ProducerTarget
}

// ProducerTarget is one member of a LocalSet intent's producer set.
type ProducerTarget struct {
	Attachment types.NamespacedName
	Device     string
	NextHop    net.IP
	// Draining keeps the producer's existing flows and replies but gives it
	// no new flow.
	Draining bool
}

// ErrProducerSetsUnavailable is returned for a LocalSet intent while the
// node's datapath predates LocalSet routes. Every other intent still applies.
var ErrProducerSetsUnavailable = errors.New(
	"node's eBPF datapath has no producer set map; LocalSet routes need a newer galactic-cni")

type RouteProgrammer interface {
	Initialize() error
	Apply(RouteIntent) error
	Cleanup(RouteIntent) error
	Remove(RouteIntent) error
	Finalize() error
}

type SIDResolver func(*cloudv1alpha1.VPCAttachment) (net.IP, error)

// DependencyNotReadyError reports a valid policy whose node-local routing
// dependencies are not ready yet. It is distinct from a policy validation
// failure because every Galactic node reconciles the same status object while
// only participating nodes need to resolve a given attachment SID.
type DependencyNotReadyError struct{ Err error }

func (e *DependencyNotReadyError) Error() string { return e.Err.Error() }
func (e *DependencyNotReadyError) Unwrap() error { return e.Err }

// Compile deterministically picks the ready producers for every selected
// consumer and emits only intent halves owned by localNode. A Single endpoint
// gets one producer per consumer; a Spread endpoint gets every producer on the
// consumer's node as one LocalSet intent, or one remote producer when its node
// has none and DeliveryMode allows it.
func Compile(policy *networkv1alpha1.ServiceRoutePolicy, endpoint *networkv1alpha1.ServiceEndpoint,
	attachments []*cloudv1alpha1.VPCAttachment, localNode string, resolveSID SIDResolver,
) ([]RouteIntent, error) {
	return compile(policy, endpoint, attachments, localNode, resolveSID, "")
}

// CompileForConsumerVPC compiles a policy while requiring selected consumer
// attachments to carry the live provider VPC's allocated status identity.
func CompileForConsumerVPC(policy *networkv1alpha1.ServiceRoutePolicy, endpoint *networkv1alpha1.ServiceEndpoint,
	attachments []*cloudv1alpha1.VPCAttachment, localNode string, resolveSID SIDResolver, consumerVPCIdentity string,
) ([]RouteIntent, error) {
	return compile(policy, endpoint, attachments, localNode, resolveSID, consumerVPCIdentity)
}

func compile(policy *networkv1alpha1.ServiceRoutePolicy, endpoint *networkv1alpha1.ServiceEndpoint,
	attachments []*cloudv1alpha1.VPCAttachment, localNode string, resolveSID SIDResolver, consumerVPCIdentity string,
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
	frontend := cloneIPNet(service)
	if policy.Spec.Frontend != nil {
		frontend, err = hostPrefix(policy.Spec.Frontend.Address)
		if err != nil {
			return nil, fmt.Errorf("parse service frontend address: %w", err)
		}
		if (frontend.IP.To4() == nil) != (service.IP.To4() == nil) {
			return nil, errors.New("service frontend and endpoint address families must match")
		}
	}
	ports, err := servicePorts(policy, endpoint)
	if err != nil {
		return nil, err
	}
	producers, err := producerCandidates(endpoint, attachments)
	if err != nil {
		return nil, err
	}
	if err := validateProducerTopology(endpoint, producers); err != nil {
		return nil, err
	}
	health := producersHealth(endpoint, producers, time.Now())

	consumers := readyAttachments(attachments)
	intents := make([]RouteIntent, 0, len(consumers))
	for _, consumer := range consumers {
		if consumer.Status.HostInterface == "" || !consumerSelector.Matches(labels.Set(consumer.Labels)) {
			continue
		}
		if !consumerMatchesVPC(policy, consumer, consumerVPCIdentity) {
			continue
		}
		local, producer := selectProducers(endpoint, consumer, producers, health)
		consumerKey := types.NamespacedName{Namespace: consumer.Namespace, Name: consumer.Name}
		if len(local) != 0 {
			if consumer.Status.Node == localNode {
				intents = append(intents, RouteIntent{
					Attachment: consumerKey, Kind: RouteIntentLocalSet,
					Service: cloneIPNet(service), Frontend: cloneIPNet(frontend), ConsumerDevice: consumer.Status.HostInterface,
					Ports: clonePorts(ports), ConsumerNextHop: attachmentNextHop(consumer, service.IP),
					Producers: producerTargets(local, health, service.IP),
				})
			}
			continue
		}
		if producer == nil {
			continue
		}
		producerKey := types.NamespacedName{Namespace: producer.Namespace, Name: producer.Name}
		if producer.Status.Node == consumer.Status.Node {
			if consumer.Status.Node == localNode {
				intents = append(intents, RouteIntent{
					Attachment: consumerKey, ProducerAttachment: producerKey, Kind: RouteIntentLocal,
					Service: cloneIPNet(service), Frontend: cloneIPNet(frontend), ConsumerDevice: consumer.Status.HostInterface,
					ServiceDevice: producer.Status.HostInterface, Ports: clonePorts(ports),
					ConsumerNextHop: attachmentNextHop(consumer, service.IP), ServiceNextHop: attachmentNextHop(producer, service.IP),
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
				Service: cloneIPNet(service), Frontend: cloneIPNet(frontend), ConsumerDevice: consumer.Status.HostInterface,
				ServiceSID: cloneIP(serviceSID), GrantID: grantID, Ports: clonePorts(ports),
				ConsumerNextHop: attachmentNextHop(consumer, service.IP),
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
				Service: cloneIPNet(service), Frontend: cloneIPNet(frontend), ServiceDevice: producer.Status.HostInterface,
				ConsumerSID: cloneIP(consumerSID), GrantID: grantID, Ports: clonePorts(ports),
				ServiceNextHop: attachmentNextHop(producer, service.IP),
			})
		}
	}
	setIntentAuthorization(policy, intents)
	sort.Slice(intents, func(i, j int) bool {
		if intents[i].Attachment != intents[j].Attachment {
			return intents[i].Attachment.String() < intents[j].Attachment.String()
		}
		return intents[i].Kind < intents[j].Kind
	})
	return intents, nil
}

// attachmentNextHop returns the guest address for a routed attachment subnet.
func attachmentNextHop(attachment *cloudv1alpha1.VPCAttachment, service net.IP) net.IP {
	ip, _, err := net.ParseCIDR(attachment.Status.PodSubnet)
	if err != nil || (ip.To4() == nil) != (service.To4() == nil) {
		return nil
	}
	return ip
}

// validateProducerTopology refuses a Single endpoint with two ready producers
// in one node and VPC, which its one-target route cannot tell apart, and a
// Spread endpoint with more producers on one node than a producer set holds.
func validateProducerTopology(endpoint *networkv1alpha1.ServiceEndpoint,
	producers []*cloudv1alpha1.VPCAttachment,
) error {
	if spread(endpoint) {
		perNode := make(map[string]int, len(producers))
		for _, producer := range producers {
			perNode[producer.Status.Node]++
			if perNode[producer.Status.Node] > networkv1alpha1.ServiceEndpointMaxProducersPerNode {
				return fmt.Errorf("service endpoint %s/%s selects more than %d ready producer attachments on node %q",
					endpoint.Namespace, endpoint.Name, networkv1alpha1.ServiceEndpointMaxProducersPerNode,
					producer.Status.Node)
			}
		}
		return nil
	}
	type producerLocation struct {
		node string
		vpc  string
	}
	seen := make(map[producerLocation]*cloudv1alpha1.VPCAttachment, len(producers))
	for _, producer := range producers {
		location := producerLocation{node: producer.Status.Node, vpc: producer.Status.VPC}
		if first, ok := seen[location]; ok {
			firstKey := types.NamespacedName{Namespace: first.Namespace, Name: first.Name}
			producerKey := types.NamespacedName{Namespace: producer.Namespace, Name: producer.Name}
			endpointKey := types.NamespacedName{Namespace: endpoint.Namespace, Name: endpoint.Name}
			return fmt.Errorf(
				"service endpoint %s selects multiple ready producer attachments %s and %s on node %q in VPC %q; "+
					"the direct endpoint dataplane cannot distinguish them",
				endpointKey, firstKey, producerKey, location.node, location.vpc,
			)
		}
		seen[location] = producer
	}
	return nil
}

// Producers returns the endpoint's ready producer attachments, ordered by
// namespace and name.
func Producers(endpoint *networkv1alpha1.ServiceEndpoint,
	attachments []*cloudv1alpha1.VPCAttachment,
) ([]*cloudv1alpha1.VPCAttachment, error) {
	return producerCandidates(endpoint, attachments)
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
		if attachment == nil || attachment.DeletionTimestamp != nil ||
			attachment.Status.ObservedGeneration != attachment.Generation ||
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

func spread(endpoint *networkv1alpha1.ServiceEndpoint) bool {
	return endpoint.Spec.Distribution == networkv1alpha1.ServiceEndpointDistributionSpread
}

// selectProducers returns, for a Spread endpoint, every producer on
// consumer's node as local. Otherwise, or when that node has none, it returns
// the one producer the consumer is sent to, or nil. A Spread endpoint's remote
// producer is chosen by rendezvous hashing of the consumer's UID with each
// candidate's UID (see rendezvousKey), among the producers whose node currently reports them
// Healthy or Unknown, or has never reported them; failing that, among those
// whose report expired, since their node may be down; failing that, among all
// of them. A producer joining or leaving a candidate set then moves only the
// consumers it gains or loses.
func selectProducers(endpoint *networkv1alpha1.ServiceEndpoint, consumer *cloudv1alpha1.VPCAttachment,
	producers []*cloudv1alpha1.VPCAttachment, health map[types.UID]producerHealth,
) (local []*cloudv1alpha1.VPCAttachment, remote *cloudv1alpha1.VPCAttachment) {
	if spread(endpoint) {
		for _, producer := range producers {
			if producer.Status.Node == consumer.Status.Node {
				local = append(local, producer)
			}
		}
		if len(local) != 0 {
			return local, nil
		}
		if endpoint.Spec.DeliveryMode != networkv1alpha1.ServiceEndpointDeliveryModePreferNodeLocal ||
			len(producers) == 0 {
			return nil, nil
		}
		for _, want := range []producerHealth{producerEligible, producerReportExpired} {
			if producer := rendezvousProducer(consumer, producers, func(p *cloudv1alpha1.VPCAttachment) bool {
				return health[p.UID] == want
			}); producer != nil {
				return nil, producer
			}
		}
		return nil, rendezvousProducer(consumer, producers, func(*cloudv1alpha1.VPCAttachment) bool { return true })
	}
	return nil, chooseProducer(endpoint.Spec.DeliveryMode, consumer.Status.Node, producers)
}

// rendezvousProducer returns the producer accepted by include with the highest
// score for consumer, or nil when include accepts none. Producers are sorted
// by name, so equal scores resolve the same way on every node.
func rendezvousProducer(consumer *cloudv1alpha1.VPCAttachment, producers []*cloudv1alpha1.VPCAttachment,
	include func(*cloudv1alpha1.VPCAttachment) bool,
) *cloudv1alpha1.VPCAttachment {
	var best *cloudv1alpha1.VPCAttachment
	var bestScore uint64
	for _, producer := range producers {
		if !include(producer) {
			continue
		}
		hash := fnv.New64a()
		_, _ = hash.Write([]byte(rendezvousKey(consumer)))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(rendezvousKey(producer)))
		if score := mix64(hash.Sum64()); best == nil || score > bestScore {
			best, bestScore = producer, score
		}
	}
	return best
}

// rendezvousKey identifies attachment for rendezvous hashing: its UID, or its
// namespace and name when it has none.
func rendezvousKey(attachment *cloudv1alpha1.VPCAttachment) string {
	if attachment.UID != "" {
		return string(attachment.UID)
	}
	return attachment.Namespace + "/" + attachment.Name
}

// mix64 is the SplitMix64 finalizer. FNV-1a alone leaves inputs that differ
// only in their last bytes with correlated high bits, which would bias the
// rendezvous comparison.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	return x ^ x>>31
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

// producerHealth is what a Spread endpoint's status.producers says of one
// producer.
type producerHealth int

const (
	// producerEligible: its node currently reports it Healthy or Unknown, or
	// has no entry for it.
	producerEligible producerHealth = iota
	// producerReportExpired: its node stopped renewing its entry.
	producerReportExpired
	// producerUnhealthy: its node currently reports it Unhealthy.
	producerUnhealthy
)

// producersHealth classifies a Spread endpoint's producers by the status entry
// their own node wrote for that same attachment, as of now. A producer with
// no such entry is eligible.
func producersHealth(endpoint *networkv1alpha1.ServiceEndpoint,
	producers []*cloudv1alpha1.VPCAttachment, now time.Time,
) map[types.UID]producerHealth {
	if !spread(endpoint) {
		return nil
	}
	reported := make(map[types.NamespacedName]networkv1alpha1.ServiceEndpointProducerStatus,
		len(endpoint.Status.Producers))
	for _, entry := range endpoint.Status.Producers {
		reported[types.NamespacedName{Namespace: entry.Namespace, Name: entry.Name}] = entry
	}
	health := make(map[types.UID]producerHealth, len(producers))
	for _, producer := range producers {
		entry, ok := reported[types.NamespacedName{Namespace: producer.Namespace, Name: producer.Name}]
		switch {
		case !ok || entry.AttachmentUID != producer.UID || entry.Node != producer.Status.Node:
		case !ProducerReportCurrent(entry, now):
			health[producer.UID] = producerReportExpired
		case entry.State == networkv1alpha1.BackendHealthUnhealthy:
			health[producer.UID] = producerUnhealthy
		}
	}
	return health
}

// ProducerReportCurrent reports whether entry was renewed within
// ServiceEndpointProducerReportLifetime before now.
func ProducerReportCurrent(entry networkv1alpha1.ServiceEndpointProducerStatus, now time.Time) bool {
	return entry.RenewTime != nil &&
		now.Before(entry.RenewTime.Add(networkv1alpha1.ServiceEndpointProducerReportLifetime))
}

// NextProducerReportExpiry returns how long until the first current entry of
// endpoint's status.producers expires, and false when none is current.
func NextProducerReportExpiry(endpoint *networkv1alpha1.ServiceEndpoint, now time.Time) (time.Duration, bool) {
	var next time.Duration
	found := false
	for _, entry := range endpoint.Status.Producers {
		if !ProducerReportCurrent(entry, now) {
			continue
		}
		left := entry.RenewTime.Add(networkv1alpha1.ServiceEndpointProducerReportLifetime).Sub(now)
		if !found || left < next {
			next, found = left, true
		}
	}
	return next, found
}

// producerTargets builds a LocalSet intent's members. Producers currently
// reported Unhealthy drain, unless every one of them is: then all stay
// eligible, since an empty set would drop every new flow. An expired report
// drains nothing.
func producerTargets(local []*cloudv1alpha1.VPCAttachment, health map[types.UID]producerHealth,
	service net.IP,
) []ProducerTarget {
	allUnhealthy := true
	for _, producer := range local {
		if health[producer.UID] != producerUnhealthy {
			allUnhealthy = false
			break
		}
	}
	targets := make([]ProducerTarget, 0, len(local))
	for _, producer := range local {
		targets = append(targets, ProducerTarget{
			Attachment: types.NamespacedName{Namespace: producer.Namespace, Name: producer.Name},
			Device:     producer.Status.HostInterface,
			NextHop:    attachmentNextHop(producer, service),
			Draining:   health[producer.UID] == producerUnhealthy && !allUnhealthy,
		})
	}
	return targets
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
	// Preserve direct-policy grant identifiers across mixed-version router fleets.
	if policy.Spec.Frontend != nil || policy.Spec.ConsumerVPCRef != nil || policy.Spec.Authorization != nil {
		_, _ = fmt.Fprintf(h, "|%d|%d|%d|%d|",
			policy.Generation, endpoint.Generation, consumer.Generation, producer.Generation)
		_, _ = h.Write([]byte(endpoint.Spec.Address))
		if policy.Spec.Frontend != nil {
			_, _ = h.Write([]byte(policy.Spec.Frontend.Address))
		}
		if policy.Spec.ConsumerVPCRef != nil {
			_, _ = h.Write([]byte(policy.Spec.ConsumerVPCRef.Name))
			_, _ = h.Write([]byte(policy.Spec.ConsumerVPCRef.UID))
		}
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

func consumerMatchesVPC(policy *networkv1alpha1.ServiceRoutePolicy,
	consumer *cloudv1alpha1.VPCAttachment, identity string,
) bool {
	if ref := policy.Spec.ConsumerVPCRef; ref != nil &&
		(consumer.Namespace != policy.Namespace || consumer.Spec.VPC.Name != ref.Name) {
		return false
	}
	return identity == "" || consumer.Status.VPC == identity
}

func setIntentAuthorization(policy *networkv1alpha1.ServiceRoutePolicy, intents []RouteIntent) {
	if policy.Spec.Frontend == nil || policy.Spec.Authorization == nil || policy.Spec.Authorization.Persistent {
		return
	}
	for i := range intents {
		intents[i].AuthorizationValidUntil = policy.Spec.Authorization.ValidUntil.Time
	}
}
