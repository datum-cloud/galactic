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
	ConsumerSID [16]uint8
}

// Tables owns the route and access maps used by the service datapath.
type Tables struct {
	routes       usidmap.Table
	access       usidmap.Table
	reverse      usidmap.Table
	remoteGrants usidmap.Table
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
	return New(usidmap.KernelTable{Map: routes}, usidmap.KernelTable{Map: access}, usidmap.KernelTable{Map: reverse}, usidmap.KernelTable{Map: remoteGrants}),
		[]*ebpf.Map{routes, access, reverse, remoteGrants}, nil
}

// New wraps map implementations. Production uses OpenPinned; tests use fakes.
func New(routes, access, reverse usidmap.Table, remoteGrants ...usidmap.Table) *Tables {
	t := &Tables{routes: routes, access: access, reverse: reverse}
	if len(remoteGrants) != 0 {
		t.remoteGrants = remoteGrants[0]
	}
	return t
}

// Clear removes all service-owned state. Galactic calls this once when it
// first opens the maps after process start, then rebuilds the complete desired
// set from informer events. Clearing fails closed and prevents an object that
// was deleted while the controller was down from leaving permanent access.
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
	var grantValue uint8
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
	return nil
}

// RegisterRoute installs or replaces a service forwarding entry.
func (t *Tables) RegisterRoute(
	ingressIfindex uint32,
	address net.IP,
	protocol uint8,
	port uint16,
	targetIfindex uint32,
) error {
	key, err := routeKey(ingressIfindex, address, protocol, port)
	if err != nil {
		return err
	}
	value := serviceRouteValue{
		TargetIfindex: targetIfindex,
		Mode:          routeModeLocal,
	}
	if err := t.routes.Put(key, value); err != nil {
		return fmt.Errorf("serviceroutemap: register route ifindex=%d address=%s: %w", ingressIfindex, address, err)
	}
	return nil
}

// RegisterRemoteRoute installs an authenticated service tunnel target while
// keeping the original inner source address intact.
func (t *Tables) RegisterRemoteRoute(ingressIfindex uint32, address net.IP, grantID [16]byte,
	protocol uint8, port uint16, targetSID net.IP) error {
	key, err := routeKey(ingressIfindex, address, protocol, port)
	if err != nil {
		return err
	}
	sid := targetSID.To16()
	if sid == nil || targetSID.To4() != nil {
		return fmt.Errorf("serviceroutemap: target SID %q is not IPv6", targetSID)
	}
	value := serviceRouteValue{Mode: routeModeRemote, GrantID: grantID}
	copy(value.TargetSID[:], sid)
	if err := t.routes.Put(key, value); err != nil {
		return fmt.Errorf("serviceroutemap: register remote route: %w", err)
	}
	return nil
}

func (t *Tables) RegisterRemoteGrant(producerIfindex uint32, address net.IP, protocol uint8, port uint16,
	grantID [16]byte, consumerSID net.IP) error {
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
	value := serviceRemoteGrantValue{}
	copy(value.ConsumerSID[:], sid)
	if err := t.remoteGrants.Put(key, value); err != nil {
		return fmt.Errorf("serviceroutemap: register remote grant: %w", err)
	}
	return nil
}

func (t *Tables) UnregisterRemoteGrant(producerIfindex uint32, address net.IP, protocol uint8, port uint16, grantID [16]byte) error {
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
func (t *Tables) RegisterAccess(ingressIfindex uint32, address net.IP, protocol uint8, port uint16) error {
	key, err := accessKey(ingressIfindex, address, protocol, port)
	if err != nil {
		return err
	}
	if err := t.access.Put(key, uint8(1)); err != nil {
		return fmt.Errorf("serviceroutemap: register access ifindex=%d address=%s protocol=%d port=%d: %w",
			ingressIfindex, address, protocol, port, err)
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

func remoteGrantKey(producerIfindex uint32, address net.IP, protocol uint8, port uint16, grantID [16]byte) (serviceRemoteGrantKey, error) {
	key := serviceRemoteGrantKey{ProducerIfindex: producerIfindex, Protocol: protocol, Port: bits.ReverseBytes16(port), GrantID: grantID}
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
