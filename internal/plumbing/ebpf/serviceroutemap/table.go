// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package serviceroutemap manages the pinned maps that drive node-local
// private-service forwarding in usid_egress.
package serviceroutemap

import (
	"errors"
	"fmt"
	"math/bits"
	"net"
	"path/filepath"

	"github.com/cilium/ebpf"

	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

const (
	serviceRouteMapName       = "service_route_table"
	serviceAccessMapName      = "service_access_table"
	serviceReverseMapName     = "service_reverse_table"
	serviceRemoteGrantMapName = "service_remote_grant_table"
	attachmentIdentityMapName = "attachment_identity_table"
	servicePolicyStateMapName = "service_policy_state_table"
	serviceDenyMapName        = "service_deny_table"

	familyIPv6 = uint8(0)
	familyIPv4 = uint8(1)
)

// Protocol numbers used by ServiceRoutePolicy.
const (
	ProtocolTCP = uint8(6)
	ProtocolUDP = uint8(17)
)

type serviceRouteValue struct {
	TargetIfindex uint32
	Mode          uint8
	Pad           [3]uint8
	ConsumerToken uint64
	ProducerToken uint64
	GrantID       [16]uint8
	TargetSID     [16]uint8
}

const (
	routeModeLocal  = uint8(1)
	routeModeRemote = uint8(2)
)

type serviceRouteKey struct {
	IngressIfindex uint32
	Family         uint8
	Protocol       uint8
	Port           uint16
	Address        [16]uint8
}

type serviceAccessKey struct {
	IngressIfindex uint32
	Family         uint8
	Protocol       uint8
	Port           uint16
	Address        [16]uint8
}

type serviceAccessValue struct {
	AttachmentToken  uint64
	MarkerDirections uint8
	Pad              [7]uint8
}

type serviceDenyKey struct {
	IngressIfindex uint32
	Family         uint8
	Pad            [3]uint8
	Address        [16]uint8
}

type serviceDenyValue struct {
	AttachmentToken uint64
	Directions      uint8
	Pad             [7]uint8
}

const (
	MarkerRequest = uint8(1)
	MarkerReply   = uint8(2)
)

type serviceReverseKey struct {
	IngressIfindex uint32
	Family         uint8
	Protocol       uint8
	SourcePort     uint16
	DestPort       uint16
	Pad            [2]uint8
	SourceAddress  [16]uint8
	DestAddress    [16]uint8
}

type serviceReverseValue struct {
	ConsumerIfindex uint32
	Mode            uint8
	Pad             [3]uint8
	ConsumerToken   uint64
	ProducerToken   uint64
	GrantID         [16]uint8
	ReturnSID       [16]uint8
	LastSeenNS      uint64
}

type serviceRemoteGrantKey struct {
	ProducerIfindex uint32
	Family          uint8
	Protocol        uint8
	Port            uint16
	GrantID         [16]uint8
	Address         [16]uint8
}

type serviceRemoteGrantValue struct {
	ConsumerSID   [16]uint8
	ProducerToken uint64
}

type servicePolicyStateValue struct{ Enabled uint8 }

// RouteIdentity describes a forwarding key that must survive a complete
// desired-state sweep.
type RouteIdentity struct {
	IngressIfindex uint32
	Address        net.IP
	Protocol       uint8
	Port           uint16
}

// AccessIdentity describes an access key that must survive a complete
// desired-state sweep.
type AccessIdentity struct {
	IngressIfindex uint32
	Address        net.IP
	Protocol       uint8
	Port           uint16
}

type DenyIdentity struct {
	IngressIfindex uint32
	Address        net.IP
}

// RemoteGrantIdentity describes a producer grant key that must survive a
// complete desired-state sweep.
type RemoteGrantIdentity struct {
	ProducerIfindex uint32
	Address         net.IP
	Protocol        uint8
	Port            uint16
	GrantID         [16]byte
}

// PolicySnapshot contains the policy-map identities in a complete desired
// controller snapshot. Values are rewritten before the sweep.
type PolicySnapshot struct {
	Routes       []RouteIdentity
	Access       []AccessIdentity
	RemoteGrants []RemoteGrantIdentity
	Deny         []DenyIdentity
}

// Tables owns the route and access maps used by the service datapath.
type Tables struct {
	routes       usidmap.Table
	access       usidmap.Table
	reverse      usidmap.Table
	remoteGrants usidmap.Table
	identities   usidmap.Table
	policyState  usidmap.Table
	deny         usidmap.Table
}

// OpenPinned opens both service maps under pinDir. The caller owns the
// returned kernel maps and must close them.
func OpenPinned(pinDir string) (*Tables, []*ebpf.Map, error) {
	routes, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, serviceRouteMapName), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("serviceroutemap: open %s: %w", serviceRouteMapName, err)
	}
	access, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, serviceAccessMapName), nil)
	if err != nil {
		_ = routes.Close()
		return nil, nil, fmt.Errorf("serviceroutemap: open %s: %w", serviceAccessMapName, err)
	}
	reverse, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, serviceReverseMapName), nil)
	if err != nil {
		_ = routes.Close()
		_ = access.Close()
		return nil, nil, fmt.Errorf("serviceroutemap: open %s: %w", serviceReverseMapName, err)
	}
	remoteGrants, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, serviceRemoteGrantMapName), nil)
	if err != nil {
		_ = routes.Close()
		_ = access.Close()
		_ = reverse.Close()
		return nil, nil, fmt.Errorf("serviceroutemap: open %s: %w", serviceRemoteGrantMapName, err)
	}
	identities, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, attachmentIdentityMapName), nil)
	if err != nil {
		_ = routes.Close()
		_ = access.Close()
		_ = reverse.Close()
		_ = remoteGrants.Close()
		return nil, nil, fmt.Errorf("serviceroutemap: open %s: %w", attachmentIdentityMapName, err)
	}
	policyState, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, servicePolicyStateMapName), nil)
	if err != nil {
		_ = routes.Close()
		_ = access.Close()
		_ = reverse.Close()
		_ = remoteGrants.Close()
		_ = identities.Close()
		return nil, nil, fmt.Errorf("serviceroutemap: open %s: %w", servicePolicyStateMapName, err)
	}
	deny, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, serviceDenyMapName), nil)
	if err != nil {
		for _, opened := range []*ebpf.Map{routes, access, reverse, remoteGrants, identities, policyState} {
			_ = opened.Close()
		}
		return nil, nil, fmt.Errorf("serviceroutemap: open %s: %w", serviceDenyMapName, err)
	}
	return New(
			usidmap.KernelTable{Map: routes}, usidmap.KernelTable{Map: access},
			usidmap.KernelTable{Map: reverse}, usidmap.KernelTable{Map: remoteGrants}, usidmap.KernelTable{Map: identities},
			usidmap.KernelTable{Map: policyState}, usidmap.KernelTable{Map: deny},
		),
		[]*ebpf.Map{routes, access, reverse, remoteGrants, identities, policyState, deny}, nil
}

// New wraps map implementations. Production uses OpenPinned; tests use fakes.
func New(routes, access, reverse usidmap.Table, remoteGrants ...usidmap.Table) *Tables {
	t := &Tables{routes: routes, access: access, reverse: reverse}
	if len(remoteGrants) != 0 {
		t.remoteGrants = remoteGrants[0]
	}
	if len(remoteGrants) > 1 {
		t.identities = remoteGrants[1]
	}
	if len(remoteGrants) > 2 {
		t.policyState = remoteGrants[2]
	}
	if len(remoteGrants) > 3 {
		t.deny = remoteGrants[3]
	}
	return t
}

// SetPolicyEnabled gates all service authorization while the controller is
// rebuilding a complete cache-synchronized generation.
func (t *Tables) SetPolicyEnabled(enabled bool) error {
	if t.policyState == nil {
		return errors.New("serviceroutemap: service policy state table unavailable")
	}
	value := servicePolicyStateValue{}
	if enabled {
		value.Enabled = 1
	}
	if err := t.policyState.Put(uint32(0), value); err != nil {
		return fmt.Errorf("serviceroutemap: set service policy enabled=%t: %w", enabled, err)
	}
	return nil
}

// IdentityToken returns the current nonzero incarnation token for ifindex.
func (t *Tables) IdentityToken(ifindex uint32) (uint64, error) {
	if t.identities == nil {
		return 0, errors.New("serviceroutemap: attachment identity table unavailable")
	}
	var token uint64
	if err := t.identities.Lookup(ifindex, &token); err != nil {
		return 0, fmt.Errorf("serviceroutemap: lookup attachment identity ifindex=%d: %w", ifindex, err)
	}
	if token == 0 {
		return 0, fmt.Errorf("serviceroutemap: attachment identity ifindex=%d has zero token", ifindex)
	}
	return token, nil
}

// Clear removes all service-owned state, including reverse flows. Normal
// controller restart reconciliation uses SweepPolicy instead so live desired
// entries and compatible reverse state remain available.
func (t *Tables) Clear() error {
	var routeKeys []serviceRouteKey
	routeIterator := t.routes.Iterate()
	var routeKey serviceRouteKey
	var routeValue serviceRouteValue
	for routeIterator.Next(&routeKey, &routeValue) {
		routeKeys = append(routeKeys, routeKey)
	}
	if err := routeIterator.Err(); err != nil {
		return fmt.Errorf("serviceroutemap: iterate routes: %w", err)
	}

	var accessKeys []serviceAccessKey
	accessIterator := t.access.Iterate()
	var grantKey serviceAccessKey
	var grantValue serviceAccessValue
	for accessIterator.Next(&grantKey, &grantValue) {
		accessKeys = append(accessKeys, grantKey)
	}
	if err := accessIterator.Err(); err != nil {
		return fmt.Errorf("serviceroutemap: iterate access grants: %w", err)
	}

	var reverseKeys []serviceReverseKey
	reverseIterator := t.reverse.Iterate()
	var reverseKey serviceReverseKey
	var reverseValue serviceReverseValue
	for reverseIterator.Next(&reverseKey, &reverseValue) {
		reverseKeys = append(reverseKeys, reverseKey)
	}
	if err := reverseIterator.Err(); err != nil {
		return fmt.Errorf("serviceroutemap: iterate reverse flows: %w", err)
	}

	var remoteGrantKeys []serviceRemoteGrantKey
	if t.remoteGrants != nil {
		iterator := t.remoteGrants.Iterate()
		var key serviceRemoteGrantKey
		var value serviceRemoteGrantValue
		for iterator.Next(&key, &value) {
			remoteGrantKeys = append(remoteGrantKeys, key)
		}
		if err := iterator.Err(); err != nil {
			return fmt.Errorf("serviceroutemap: iterate remote grants: %w", err)
		}
	}
	var denyKeys []serviceDenyKey
	if t.deny != nil {
		iterator := t.deny.Iterate()
		var key serviceDenyKey
		var value serviceDenyValue
		for iterator.Next(&key, &value) {
			denyKeys = append(denyKeys, key)
		}
		if err := iterator.Err(); err != nil {
			return fmt.Errorf("serviceroutemap: iterate deny catalog: %w", err)
		}
	}

	for _, key := range routeKeys {
		if err := t.routes.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("serviceroutemap: clear route: %w", err)
		}
	}
	for _, key := range accessKeys {
		if err := t.access.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("serviceroutemap: clear access grant: %w", err)
		}
	}
	for _, key := range reverseKeys {
		if err := t.reverse.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("serviceroutemap: clear reverse flow: %w", err)
		}
	}
	for _, key := range remoteGrantKeys {
		if err := t.remoteGrants.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("serviceroutemap: clear remote grant: %w", err)
		}
	}
	for _, key := range denyKeys {
		if err := t.deny.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("serviceroutemap: clear deny catalog: %w", err)
		}
	}
	return nil
}

// SweepPolicy removes route, access, and remote-grant entries absent from a
// complete cache-synchronized desired snapshot. Reverse-flow entries are
// deliberately preserved: reply processing revalidates the current route,
// access, and grant maps before delivery.
//
// All three maps are fully iterated before the first deletion. An iteration or
// desired-key error therefore leaves the live maps unchanged. Deletion is
// idempotent, so a partial deletion failure is safe to retry with the same
// complete snapshot.
//
//nolint:gocyclo // Atomic multi-map sweep is intentionally linear.
func (t *Tables) SweepPolicy(snapshot PolicySnapshot) error {
	desiredRoutes := make(map[serviceRouteKey]struct{}, len(snapshot.Routes))
	for _, route := range snapshot.Routes {
		key, err := routeKey(route.IngressIfindex, route.Address, route.Protocol, route.Port)
		if err != nil {
			return err
		}
		desiredRoutes[key] = struct{}{}
	}
	desiredAccess := make(map[serviceAccessKey]struct{}, len(snapshot.Access))
	for _, access := range snapshot.Access {
		key, err := accessKey(access.IngressIfindex, access.Address, access.Protocol, access.Port)
		if err != nil {
			return err
		}
		desiredAccess[key] = struct{}{}
	}
	desiredGrants := make(map[serviceRemoteGrantKey]struct{}, len(snapshot.RemoteGrants))
	for _, grant := range snapshot.RemoteGrants {
		key, err := remoteGrantKey(grant.ProducerIfindex, grant.Address, grant.Protocol, grant.Port, grant.GrantID)
		if err != nil {
			return err
		}
		desiredGrants[key] = struct{}{}
	}
	desiredDeny := make(map[serviceDenyKey]struct{}, len(snapshot.Deny))
	for _, deny := range snapshot.Deny {
		key, err := denyKey(deny.IngressIfindex, deny.Address)
		if err != nil {
			return err
		}
		desiredDeny[key] = struct{}{}
	}

	var staleRoutes []serviceRouteKey
	routeIterator := t.routes.Iterate()
	var route serviceRouteKey
	var routeValue serviceRouteValue
	for routeIterator.Next(&route, &routeValue) {
		if _, desired := desiredRoutes[route]; !desired {
			staleRoutes = append(staleRoutes, route)
		}
	}
	if err := routeIterator.Err(); err != nil {
		return fmt.Errorf("serviceroutemap: iterate routes for sweep: %w", err)
	}

	var staleAccess []serviceAccessKey
	accessIterator := t.access.Iterate()
	var access serviceAccessKey
	var accessValue serviceAccessValue
	for accessIterator.Next(&access, &accessValue) {
		if _, desired := desiredAccess[access]; !desired {
			staleAccess = append(staleAccess, access)
		}
	}
	if err := accessIterator.Err(); err != nil {
		return fmt.Errorf("serviceroutemap: iterate access grants for sweep: %w", err)
	}

	var staleGrants []serviceRemoteGrantKey
	if t.remoteGrants != nil {
		grantIterator := t.remoteGrants.Iterate()
		var grant serviceRemoteGrantKey
		var grantValue serviceRemoteGrantValue
		for grantIterator.Next(&grant, &grantValue) {
			if _, desired := desiredGrants[grant]; !desired {
				staleGrants = append(staleGrants, grant)
			}
		}
		if err := grantIterator.Err(); err != nil {
			return fmt.Errorf("serviceroutemap: iterate remote grants for sweep: %w", err)
		}
	}
	var staleDeny []serviceDenyKey
	if t.deny != nil {
		iterator := t.deny.Iterate()
		var deny serviceDenyKey
		var value serviceDenyValue
		for iterator.Next(&deny, &value) {
			if _, desired := desiredDeny[deny]; !desired {
				staleDeny = append(staleDeny, deny)
			}
		}
		if err := iterator.Err(); err != nil {
			return fmt.Errorf("serviceroutemap: iterate deny catalog for sweep: %w", err)
		}
	}

	// Revoke authorization before forwarding. Continue independent deletions
	// after an error so one broken key cannot leave unrelated stale grants live;
	// every operation is idempotent and the joined error triggers a retry.
	var deleteErrs []error
	for _, key := range staleGrants {
		if err := t.remoteGrants.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			deleteErrs = append(deleteErrs, fmt.Errorf("serviceroutemap: sweep remote grant: %w", err))
		}
	}
	for _, key := range staleAccess {
		if err := t.access.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			deleteErrs = append(deleteErrs, fmt.Errorf("serviceroutemap: sweep access grant: %w", err))
		}
	}
	for _, key := range staleRoutes {
		if err := t.routes.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			deleteErrs = append(deleteErrs, fmt.Errorf("serviceroutemap: sweep route: %w", err))
		}
	}
	for _, key := range staleDeny {
		if err := t.deny.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			deleteErrs = append(deleteErrs, fmt.Errorf("serviceroutemap: sweep deny catalog: %w", err))
		}
	}
	return errors.Join(deleteErrs...)
}

// RegisterRoute installs or replaces a service forwarding entry.
func (t *Tables) RegisterRoute(
	ingressIfindex uint32,
	address net.IP,
	protocol uint8,
	port uint16,
	targetIfindex uint32,
	consumerToken, producerToken uint64,
) error {
	key, err := routeKey(ingressIfindex, address, protocol, port)
	if err != nil {
		return err
	}
	value := serviceRouteValue{
		TargetIfindex: targetIfindex,
		Mode:          routeModeLocal,
		ConsumerToken: consumerToken,
		ProducerToken: producerToken,
	}
	if err := t.routes.Put(key, value); err != nil {
		return fmt.Errorf("serviceroutemap: register route ifindex=%d address=%s: %w", ingressIfindex, address, err)
	}
	return nil
}

// RegisterRemoteRoute installs an authenticated service tunnel target while
// keeping the original inner source address intact.
func (t *Tables) RegisterRemoteRoute(ingressIfindex uint32, address net.IP, grantID [16]byte,
	protocol uint8, port uint16, targetSID net.IP, consumerToken uint64) error {
	key, err := routeKey(ingressIfindex, address, protocol, port)
	if err != nil {
		return err
	}
	sid := targetSID.To16()
	if sid == nil || targetSID.To4() != nil {
		return fmt.Errorf("serviceroutemap: target SID %q is not IPv6", targetSID)
	}
	value := serviceRouteValue{Mode: routeModeRemote, GrantID: grantID, ConsumerToken: consumerToken}
	copy(value.TargetSID[:], sid)
	if err := t.routes.Put(key, value); err != nil {
		return fmt.Errorf("serviceroutemap: register remote route: %w", err)
	}
	return nil
}

func (t *Tables) RegisterRemoteGrant(producerIfindex uint32, address net.IP, protocol uint8, port uint16,
	grantID [16]byte, consumerSID net.IP, producerToken uint64) error {
	if t.remoteGrants == nil {
		return errors.New("serviceroutemap: remote grant table unavailable")
	}
	key, err := remoteGrantKey(producerIfindex, address, protocol, port, grantID)
	if err != nil {
		return err
	}
	sid := consumerSID.To16()
	if sid == nil || consumerSID.To4() != nil {
		return fmt.Errorf("serviceroutemap: consumer SID %q is not IPv6", consumerSID)
	}
	value := serviceRemoteGrantValue{ProducerToken: producerToken}
	copy(value.ConsumerSID[:], sid)
	if err := t.remoteGrants.Put(key, value); err != nil {
		return fmt.Errorf("serviceroutemap: register remote grant: %w", err)
	}
	return nil
}

func (t *Tables) UnregisterRemoteGrant(
	producerIfindex uint32, address net.IP, protocol uint8, port uint16, grantID [16]byte,
) error {
	key, err := remoteGrantKey(producerIfindex, address, protocol, port, grantID)
	if err != nil {
		return err
	}
	if err := t.remoteGrants.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("serviceroutemap: unregister remote grant: %w", err)
	}
	return nil
}

// UnregisterRoute removes a service forwarding entry if it exists.
func (t *Tables) UnregisterRoute(ingressIfindex uint32, address net.IP, protocol uint8, port uint16) error {
	key, err := routeKey(ingressIfindex, address, protocol, port)
	if err != nil {
		return err
	}
	if err := t.routes.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("serviceroutemap: unregister route ifindex=%d address=%s: %w", ingressIfindex, address, err)
	}
	return nil
}

// RegisterAccess allows protocol and port traffic to one service address.
func (t *Tables) RegisterAccess(ingressIfindex uint32, address net.IP, protocol uint8, port uint16,
	attachmentToken uint64, markerDirections uint8) error {
	key, err := accessKey(ingressIfindex, address, protocol, port)
	if err != nil {
		return err
	}
	value := serviceAccessValue{AttachmentToken: attachmentToken, MarkerDirections: markerDirections}
	if err := t.access.Put(key, value); err != nil {
		return fmt.Errorf("serviceroutemap: register access ifindex=%d address=%s protocol=%d port=%d: %w",
			ingressIfindex, address, protocol, port, err)
	}
	return nil
}

func (t *Tables) RegisterDeny(ingressIfindex uint32, address net.IP, attachmentToken uint64, directions uint8) error {
	if t.deny == nil {
		return errors.New("serviceroutemap: service deny table unavailable")
	}
	key, err := denyKey(ingressIfindex, address)
	if err != nil {
		return err
	}
	if err := t.deny.Put(key, serviceDenyValue{AttachmentToken: attachmentToken, Directions: directions}); err != nil {
		return fmt.Errorf("serviceroutemap: register deny ifindex=%d address=%s: %w", ingressIfindex, address, err)
	}
	return nil
}

func (t *Tables) UnregisterDeny(ingressIfindex uint32, address net.IP) error {
	key, err := denyKey(ingressIfindex, address)
	if err != nil {
		return err
	}
	if err := t.deny.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("serviceroutemap: unregister deny ifindex=%d address=%s: %w", ingressIfindex, address, err)
	}
	return nil
}

// UnregisterAccess removes a service access grant if it exists.
func (t *Tables) UnregisterAccess(ingressIfindex uint32, address net.IP, protocol uint8, port uint16) error {
	key, err := accessKey(ingressIfindex, address, protocol, port)
	if err != nil {
		return err
	}
	if err := t.access.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("serviceroutemap: unregister access ifindex=%d address=%s protocol=%d port=%d: %w",
			ingressIfindex, address, protocol, port, err)
	}
	return nil
}

func routeKey(ingressIfindex uint32, address net.IP, protocol uint8, port uint16) (serviceRouteKey, error) {
	key := serviceRouteKey{IngressIfindex: ingressIfindex, Protocol: protocol, Port: bits.ReverseBytes16(port)}
	if ipv4 := address.To4(); ipv4 != nil {
		key.Family = familyIPv4
		copy(key.Address[:4], ipv4)
		return key, nil
	}
	ipv6 := address.To16()
	if ipv6 == nil {
		return serviceRouteKey{}, fmt.Errorf("serviceroutemap: address %q is not an IP address", address)
	}
	key.Family = familyIPv6
	copy(key.Address[:], ipv6)
	return key, nil
}

func accessKey(ingressIfindex uint32, address net.IP, protocol uint8, port uint16) (serviceAccessKey, error) {
	key := serviceAccessKey{IngressIfindex: ingressIfindex, Protocol: protocol, Port: bits.ReverseBytes16(port)}
	if ipv4 := address.To4(); ipv4 != nil {
		key.Family = familyIPv4
		copy(key.Address[:4], ipv4)
		return key, nil
	}
	ipv6 := address.To16()
	if ipv6 == nil {
		return serviceAccessKey{}, fmt.Errorf("serviceroutemap: address %q is not an IP address", address)
	}
	key.Family = familyIPv6
	copy(key.Address[:], ipv6)
	return key, nil
}

func denyKey(ingressIfindex uint32, address net.IP) (serviceDenyKey, error) {
	key := serviceDenyKey{IngressIfindex: ingressIfindex}
	if ipv4 := address.To4(); ipv4 != nil {
		key.Family = familyIPv4
		copy(key.Address[:4], ipv4)
		return key, nil
	}
	ipv6 := address.To16()
	if ipv6 == nil {
		return serviceDenyKey{}, fmt.Errorf("serviceroutemap: address %q is not an IP address", address)
	}
	key.Family = familyIPv6
	copy(key.Address[:], ipv6)
	return key, nil
}

func remoteGrantKey(
	producerIfindex uint32, address net.IP, protocol uint8, port uint16, grantID [16]byte,
) (serviceRemoteGrantKey, error) {
	key := serviceRemoteGrantKey{
		ProducerIfindex: producerIfindex, Protocol: protocol,
		Port: bits.ReverseBytes16(port), GrantID: grantID,
	}
	if ipv4 := address.To4(); ipv4 != nil {
		key.Family = familyIPv4
		copy(key.Address[:4], ipv4)
		return key, nil
	}
	ipv6 := address.To16()
	if ipv6 == nil {
		return serviceRemoteGrantKey{}, fmt.Errorf("serviceroutemap: address %q is not an IP address", address)
	}
	key.Family = familyIPv6
	copy(key.Address[:], ipv6)
	return key, nil
}
