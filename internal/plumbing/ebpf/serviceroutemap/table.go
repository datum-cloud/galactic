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
	serviceRouteMapName   = "service_route_table"
	serviceAccessMapName  = "service_access_table"
	serviceReverseMapName = "service_reverse_table"

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
}

type serviceRouteKey struct {
	IngressIfindex uint32
	Family         uint8
	Pad            [3]uint8
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
	Pad             uint32
	LastSeenNS      uint64
}

// Tables owns the route and access maps used by the service datapath.
type Tables struct {
	routes  usidmap.Table
	access  usidmap.Table
	reverse usidmap.Table
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
	return New(usidmap.KernelTable{Map: routes}, usidmap.KernelTable{Map: access}, usidmap.KernelTable{Map: reverse}),
		[]*ebpf.Map{routes, access, reverse}, nil
}

// New wraps map implementations. Production uses OpenPinned; tests use fakes.
func New(routes, access, reverse usidmap.Table) *Tables {
	return &Tables{routes: routes, access: access, reverse: reverse}
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
	return nil
}

// RegisterRoute installs or replaces a service forwarding entry.
func (t *Tables) RegisterRoute(
	ingressIfindex uint32,
	address net.IP,
	targetIfindex uint32,
) error {
	key, err := routeKey(ingressIfindex, address)
	if err != nil {
		return err
	}
	value := serviceRouteValue{
		TargetIfindex: targetIfindex,
	}
	if err := t.routes.Put(key, value); err != nil {
		return fmt.Errorf("serviceroutemap: register route ifindex=%d address=%s: %w", ingressIfindex, address, err)
	}
	return nil
}

// UnregisterRoute removes a service forwarding entry if it exists.
func (t *Tables) UnregisterRoute(ingressIfindex uint32, address net.IP) error {
	key, err := routeKey(ingressIfindex, address)
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

func routeKey(ingressIfindex uint32, address net.IP) (serviceRouteKey, error) {
	key := serviceRouteKey{IngressIfindex: ingressIfindex}
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
