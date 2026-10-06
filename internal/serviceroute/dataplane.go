//go:build linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/serviceroutemap"
	"go.datum.net/galactic/internal/plumbing/vrf"
	api "go.datum.net/network/api/v1alpha1"
)

// RouteProgrammer applies the local bidirectional service path for a route
// intent. Implementations must make repeated Apply calls safe.
type RouteProgrammer interface {
	Apply(RouteIntent) error
	Remove(RouteIntent) error
}

type routeRef struct {
	tableID       uint32
	prefix        string
	targetIfindex uint32
	targetTableID uint32
	targetKind    uint32
	requirePolicy bool
}

type accessRef struct {
	tableID  uint32
	address  string
	protocol uint8
	port     uint16
}

type appliedEntry struct {
	route  *routeRef
	access *accessRef
}

type routeState struct {
	count int
	ref   routeRef
}

// EBPFRouteProgrammer writes the complete private-service path into pinned
// TC-eBPF maps. It creates no Linux route: consumers continue to use only their
// ordinary default gateway, and usid_egress redirects authorized packets.
type EBPFRouteProgrammer struct {
	PinDir string

	mu          sync.Mutex
	tables      *serviceroutemap.Tables
	kinds       *ifindexvrfmap.EgressKindTable
	mapHandles  []*ebpf.Map
	routeRefs   map[string]routeState
	accessRefs  map[accessRef]int
	appliedRefs map[string][][]appliedEntry
}

// Initialize opens the pinned maps and removes service state left by an older
// controller process. Apply also initializes lazily so startup ordering with
// the datapath loader remains tolerant.
func (p *EBPFRouteProgrammer) Initialize() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.ensureOpen()
}

func (p *EBPFRouteProgrammer) Apply(intent RouteIntent) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.ensureOpen(); err != nil {
		return err
	}
	entries, err := p.entries(intent)
	if err != nil {
		return err
	}

	applied := make([]appliedEntry, 0, len(entries))
	for _, entry := range entries {
		if err := p.acquire(entry); err != nil {
			for index := len(applied) - 1; index >= 0; index-- {
				_ = p.release(applied[index])
			}
			return err
		}
		applied = append(applied, entry)
	}
	key := intentKey(intent)
	p.appliedRefs[key] = append(p.appliedRefs[key], applied)
	return nil
}

func (p *EBPFRouteProgrammer) Remove(intent RouteIntent) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.ensureOpen(); err != nil {
		return err
	}
	key := intentKey(intent)
	sets := p.appliedRefs[key]
	if len(sets) == 0 {
		return nil
	}
	entries := sets[len(sets)-1]
	var errs []error
	for index := len(entries) - 1; index >= 0; index-- {
		if err := p.release(entries[index]); err != nil {
			errs = append(errs, err)
		}
	}
	if len(sets) == 1 {
		delete(p.appliedRefs, key)
	} else {
		p.appliedRefs[key] = sets[:len(sets)-1]
	}
	return errors.Join(errs...)
}

func (p *EBPFRouteProgrammer) ensureOpen() error {
	if p.tables != nil {
		return nil
	}
	tables, handles, err := serviceroutemap.OpenPinned(p.pinDir())
	if err != nil {
		return err
	}
	kinds, kindHandle, err := ifindexvrfmap.OpenPinnedEgressKind(p.pinDir())
	if err != nil {
		for _, handle := range handles {
			_ = handle.Close()
		}
		return err
	}
	if err := tables.Clear(); err != nil {
		for _, handle := range handles {
			_ = handle.Close()
		}
		_ = kindHandle.Close()
		return err
	}
	p.tables = tables
	p.kinds = kinds
	p.mapHandles = append(handles, kindHandle)
	p.routeRefs = make(map[string]routeState)
	p.accessRefs = make(map[accessRef]int)
	p.appliedRefs = make(map[string][][]appliedEntry)
	return nil
}

func (p *EBPFRouteProgrammer) entries(intent RouteIntent) ([]appliedEntry, error) {
	consumerTable, err := vrf.TableID(intent.ConsumerVPC)
	if err != nil {
		return nil, fmt.Errorf("resolve consumer VRF %q: %w", intent.ConsumerVPC, err)
	}
	serviceTable, err := vrf.TableID(intent.ServiceVPC)
	if err != nil {
		return nil, fmt.Errorf("resolve service VRF %q: %w", intent.ServiceVPC, err)
	}
	consumerIfindex, consumerKind, err := p.target(intent.ConsumerDevice)
	if err != nil {
		return nil, fmt.Errorf("resolve consumer interface %q: %w", intent.ConsumerDevice, err)
	}
	serviceIfindex, serviceKind, err := p.target(intent.ServiceDevice)
	if err != nil {
		return nil, fmt.Errorf("resolve service interface %q: %w", intent.ServiceDevice, err)
	}

	serviceIP := intent.Service.IP
	entries := make([]appliedEntry, 0, len(intent.Ports)+2)
	for _, port := range intent.Ports {
		protocol, err := protocolNumber(port.Protocol)
		if err != nil {
			return nil, err
		}
		entries = append(entries, appliedEntry{access: &accessRef{
			tableID: consumerTable, address: serviceIP.String(), protocol: protocol, port: uint16(port.Port),
		}})
	}
	entries = append(entries,
		appliedEntry{route: &routeRef{
			tableID: serviceTable, prefix: intent.Consumer.String(), targetIfindex: consumerIfindex,
			targetTableID: consumerTable, targetKind: consumerKind,
		}},
		appliedEntry{route: &routeRef{
			tableID: consumerTable, prefix: intent.Service.String(), targetIfindex: serviceIfindex,
			targetTableID: serviceTable, targetKind: serviceKind, requirePolicy: true,
		}},
	)
	return entries, nil
}

func (p *EBPFRouteProgrammer) target(name string) (uint32, uint32, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, 0, err
	}
	ifindex := uint32(link.Attrs().Index)
	kind, ok, err := p.kinds.Get(ifindex)
	if err != nil {
		return 0, 0, err
	}
	if !ok {
		return 0, 0, fmt.Errorf("interface %d has no registered egress kind", ifindex)
	}
	return ifindex, kind, nil
}

func (p *EBPFRouteProgrammer) acquire(entry appliedEntry) error {
	if entry.access != nil {
		if p.accessRefs[*entry.access] == 0 {
			address := net.ParseIP(entry.access.address)
			if err := p.tables.RegisterAccess(
				entry.access.tableID, address, entry.access.protocol, entry.access.port,
			); err != nil {
				return err
			}
		}
		p.accessRefs[*entry.access]++
		return nil
	}

	key := routeRefKey(*entry.route)
	state, ok := p.routeRefs[key]
	if ok {
		if state.ref != *entry.route {
			return fmt.Errorf("service route %s has conflicting redirect targets", key)
		}
		state.count++
		p.routeRefs[key] = state
		return nil
	}
	prefix, err := parsePrefix(entry.route.prefix)
	if err != nil {
		return err
	}
	if err := p.tables.RegisterRoute(
		entry.route.tableID,
		prefix,
		entry.route.targetIfindex,
		entry.route.targetTableID,
		entry.route.targetKind,
		entry.route.requirePolicy,
	); err != nil {
		return err
	}
	p.routeRefs[key] = routeState{count: 1, ref: *entry.route}
	return nil
}

func (p *EBPFRouteProgrammer) release(entry appliedEntry) error {
	if entry.access != nil {
		count := p.accessRefs[*entry.access]
		if count > 1 {
			p.accessRefs[*entry.access] = count - 1
			return nil
		}
		delete(p.accessRefs, *entry.access)
		return p.tables.UnregisterAccess(
			entry.access.tableID,
			net.ParseIP(entry.access.address),
			entry.access.protocol,
			entry.access.port,
		)
	}

	key := routeRefKey(*entry.route)
	state, ok := p.routeRefs[key]
	if !ok {
		return nil
	}
	if state.count > 1 {
		state.count--
		p.routeRefs[key] = state
		return nil
	}
	delete(p.routeRefs, key)
	prefix, err := parsePrefix(entry.route.prefix)
	if err != nil {
		return err
	}
	return p.tables.UnregisterRoute(entry.route.tableID, prefix)
}

func protocolNumber(protocol api.NetworkRuleProtocol) (uint8, error) {
	switch protocol {
	case api.NetworkRuleProtocolTCP:
		return serviceroutemap.ProtocolTCP, nil
	case api.NetworkRuleProtocolUDP:
		return serviceroutemap.ProtocolUDP, nil
	default:
		return 0, fmt.Errorf("unsupported service route protocol %q", protocol)
	}
}

func parsePrefix(value string) (*net.IPNet, error) {
	_, prefix, err := net.ParseCIDR(value)
	if err != nil {
		return nil, fmt.Errorf("parse service route prefix %q: %w", value, err)
	}
	return prefix, nil
}

func routeRefKey(ref routeRef) string {
	return fmt.Sprintf("%d|%s", ref.tableID, ref.prefix)
}

func intentKey(intent RouteIntent) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s|%s|%s|%s|%s|%s|%s",
		intent.Attachment, intent.Consumer, intent.Service, intent.ConsumerVPC,
		intent.ConsumerDevice, intent.ServiceVPC, intent.ServiceDevice)
	for _, port := range intent.Ports {
		fmt.Fprintf(&builder, "|%s:%d", port.Protocol, port.Port)
	}
	return builder.String()
}

func (p *EBPFRouteProgrammer) pinDir() string {
	if p.PinDir != "" {
		return p.PinDir
	}
	return attach.PinDir
}
