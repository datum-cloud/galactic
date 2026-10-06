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

	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
)

const (
	serviceRouteMapName  = "service_route_table"
	serviceAccessMapName = "service_access_table"

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
	TargetKind    uint32
	RequirePolicy uint8
	Pad           [3]uint8
}

type serviceAccessKey struct {
	TableID  uint32
	Family   uint8
	Protocol uint8
	Port     uint16
	Address  [16]uint8
}

// Tables owns the route and access maps used by the service datapath.
type Tables struct {
	routes usidmap.Table
	access usidmap.Table
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
	return New(usidmap.KernelTable{Map: routes}, usidmap.KernelTable{Map: access}),
		[]*ebpf.Map{routes, access}, nil
}

// New wraps map implementations. Production uses OpenPinned; tests use fakes.
func New(routes, access usidmap.Table) *Tables {
	return &Tables{routes: routes, access: access}
}

// Clear removes all service-owned state. Galactic calls this once when it
// first opens the maps after process start, then rebuilds the complete desired
// set from informer events. Clearing fails closed and prevents an object that
// was deleted while the controller was down from leaving permanent access.
func (t *Tables) Clear() error {
	var routeKeys []prog.UsidEgressRouteKey
	routeIterator := t.routes.Iterate()
	var routeKey prog.UsidEgressRouteKey
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
	return nil
}

// RegisterRoute installs or replaces a service forwarding entry.
func (t *Tables) RegisterRoute(
	tableID uint32,
	prefix *net.IPNet,
	targetIfindex uint32,
	targetKind uint32,
	requirePolicy bool,
) error {
	key, err := routeKey(tableID, prefix)
	if err != nil {
		return err
	}
	value := serviceRouteValue{TargetIfindex: targetIfindex, TargetKind: targetKind}
	if requirePolicy {
		value.RequirePolicy = 1
	}
	if err := t.routes.Put(key, value); err != nil {
		return fmt.Errorf("serviceroutemap: register route table=%d prefix=%s: %w", tableID, prefix, err)
	}
	return nil
}

// UnregisterRoute removes a service forwarding entry if it exists.
func (t *Tables) UnregisterRoute(tableID uint32, prefix *net.IPNet) error {
	key, err := routeKey(tableID, prefix)
	if err != nil {
		return err
	}
	if err := t.routes.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("serviceroutemap: unregister route table=%d prefix=%s: %w", tableID, prefix, err)
	}
	return nil
}

// RegisterAccess allows protocol and port traffic to one service address.
func (t *Tables) RegisterAccess(tableID uint32, address net.IP, protocol uint8, port uint16) error {
	key, err := accessKey(tableID, address, protocol, port)
	if err != nil {
		return err
	}
	if err := t.access.Put(key, uint8(1)); err != nil {
		return fmt.Errorf("serviceroutemap: register access table=%d address=%s protocol=%d port=%d: %w",
			tableID, address, protocol, port, err)
	}
	return nil
}

// UnregisterAccess removes a service access grant if it exists.
func (t *Tables) UnregisterAccess(tableID uint32, address net.IP, protocol uint8, port uint16) error {
	key, err := accessKey(tableID, address, protocol, port)
	if err != nil {
		return err
	}
	if err := t.access.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("serviceroutemap: unregister access table=%d address=%s protocol=%d port=%d: %w",
			tableID, address, protocol, port, err)
	}
	return nil
}

func routeKey(tableID uint32, prefix *net.IPNet) (prog.UsidEgressRouteKey, error) {
	if prefix == nil {
		return prog.UsidEgressRouteKey{}, errors.New("serviceroutemap: prefix is nil")
	}
	ones, width := prefix.Mask.Size()
	if width == 0 {
		return prog.UsidEgressRouteKey{}, fmt.Errorf("serviceroutemap: prefix %s has an invalid mask", prefix)
	}
	key := prog.UsidEgressRouteKey{TableId: tableID, Prefixlen: uint32(40 + ones)}
	if address := prefix.IP.To4(); address != nil {
		key.Family = familyIPv4
		copy(key.Addr[:4], address)
		return key, nil
	}
	address := prefix.IP.To16()
	if address == nil {
		return prog.UsidEgressRouteKey{}, fmt.Errorf("serviceroutemap: prefix %s is not an IP prefix", prefix)
	}
	key.Family = familyIPv6
	copy(key.Addr[:], address)
	return key, nil
}

func accessKey(tableID uint32, address net.IP, protocol uint8, port uint16) (serviceAccessKey, error) {
	key := serviceAccessKey{TableID: tableID, Protocol: protocol, Port: bits.ReverseBytes16(port)}
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
