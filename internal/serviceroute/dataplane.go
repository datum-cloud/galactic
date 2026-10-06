//go:build linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/serviceroutemap"
	api "go.datum.net/network/api/v1alpha1"
)

type routeRef struct {
	ingressIfindex uint32
	address        string
	targetIfindex  uint32
	mode           RouteIntentKind
	protocol       uint8
	port           uint16
	grantID        ServiceGrantID
	targetSID      [16]byte
}

type accessRef struct {
	ingressIfindex uint32
	address        string
	protocol       uint8
	port           uint16
}

type appliedEntry struct {
	route  *routeRef
	access *accessRef
	grant  *grantRef
}

type grantRef struct {
	producerIfindex uint32
	address         string
	protocol        uint8
	port            uint16
	grantID         ServiceGrantID
	consumerSID     [16]byte
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

	mu               sync.Mutex
	tables           *serviceroutemap.Tables
	mapHandles       []*ebpf.Map
	routeMapID       ebpf.MapID
	routeRefs        map[string]routeState
	accessRefs       map[accessRef]int
	grantRefs        map[grantRef]int
	appliedRefs      map[string][][]appliedEntry
	desiredRefs      map[string][][]appliedEntry
	pendingRollbacks map[string][]appliedEntry
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

	key := intentKey(intent)
	if err := p.retryRollback(key); err != nil {
		return fmt.Errorf("retry prior service route rollback: %w", err)
	}
	applied := make([]appliedEntry, 0, len(entries))
	for _, entry := range entries {
		if err := p.acquire(entry); err != nil {
			var rollbackErrs []error
			for index := len(applied) - 1; index >= 0; index-- {
				if rollbackErr := p.release(applied[index]); rollbackErr != nil {
					p.pendingRollbacks[key] = append(p.pendingRollbacks[key], applied[index])
					rollbackErrs = append(rollbackErrs, rollbackErr)
				}
			}
			return errors.Join(err, errors.Join(rollbackErrs...))
		}
		applied = append(applied, entry)
	}
	p.appliedRefs[key] = append(p.appliedRefs[key], applied)
	p.desiredRefs[key] = append(p.desiredRefs[key], applied)
	return nil
}

func (p *EBPFRouteProgrammer) Remove(intent RouteIntent) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.ensureOpen(); err != nil {
		return err
	}
	key := intentKey(intent)
	if err := p.retryRollback(key); err != nil {
		return fmt.Errorf("retry prior service route rollback: %w", err)
	}
	sets := p.appliedRefs[key]
	if len(sets) == 0 {
		return nil
	}
	entries := sets[len(sets)-1]
	remaining := make([]appliedEntry, 0, len(entries))
	var errs []error
	for index := len(entries) - 1; index >= 0; index-- {
		if err := p.release(entries[index]); err != nil {
			errs = append(errs, err)
			remaining = append(remaining, entries[index])
		}
	}
	if len(remaining) != 0 {
		sets[len(sets)-1] = remaining
		p.appliedRefs[key] = sets
		return errors.Join(errs...)
	}
	if len(sets) == 1 {
		delete(p.appliedRefs, key)
		delete(p.desiredRefs, key)
	} else {
		p.appliedRefs[key] = sets[:len(sets)-1]
		desired := p.desiredRefs[key]
		p.desiredRefs[key] = desired[:len(desired)-1]
	}
	return errors.Join(errs...)
}

func (p *EBPFRouteProgrammer) ensureOpen() error {
	if p.tables != nil {
		changed, err := p.routeMapChanged()
		if err != nil {
			return err
		}
		if !changed {
			return nil
		}
		p.closeHandles()
	}
	desired := p.desiredRefs
	tables, handles, err := serviceroutemap.OpenPinned(p.pinDir())
	if err != nil {
		return err
	}
	if err := tables.Clear(); err != nil {
		for _, handle := range handles {
			_ = handle.Close()
		}
		return err
	}
	p.tables = tables
	p.mapHandles = handles
	p.routeMapID, err = kernelMapID(handles[0])
	if err != nil {
		p.closeHandles()
		return err
	}
	p.routeRefs = make(map[string]routeState)
	p.accessRefs = make(map[accessRef]int)
	p.grantRefs = make(map[grantRef]int)
	p.appliedRefs = make(map[string][][]appliedEntry)
	p.pendingRollbacks = make(map[string][]appliedEntry)
	if desired == nil {
		p.desiredRefs = make(map[string][][]appliedEntry)
		return nil
	}
	p.desiredRefs = desired
	for key, sets := range desired {
		for _, entries := range sets {
			applied := make([]appliedEntry, 0, len(entries))
			for _, entry := range entries {
				if err := p.acquire(entry); err != nil {
					p.closeHandles()
					return fmt.Errorf("rebuild service route state %s: %w", key, err)
				}
				applied = append(applied, entry)
			}
			p.appliedRefs[key] = append(p.appliedRefs[key], applied)
		}
	}
	return nil
}

func (p *EBPFRouteProgrammer) routeMapChanged() (bool, error) {
	current, err := ebpf.LoadPinnedMap(filepath.Join(p.pinDir(), "service_route_table"), nil)
	if err != nil {
		return false, fmt.Errorf("open current service route map: %w", err)
	}
	defer current.Close() //nolint:errcheck // read-only identity check
	id, err := kernelMapID(current)
	if err != nil {
		return false, err
	}
	return id != p.routeMapID, nil
}

func kernelMapID(m *ebpf.Map) (ebpf.MapID, error) {
	info, err := m.Info()
	if err != nil {
		return 0, fmt.Errorf("read service route map info: %w", err)
	}
	id, ok := info.ID()
	if !ok {
		return 0, errors.New("kernel did not report service route map ID")
	}
	return id, nil
}

func (p *EBPFRouteProgrammer) closeHandles() {
	for _, handle := range p.mapHandles {
		_ = handle.Close()
	}
	p.mapHandles = nil
	p.tables = nil
	p.routeMapID = 0
}

func (p *EBPFRouteProgrammer) retryRollback(key string) error {
	entries := p.pendingRollbacks[key]
	if len(entries) == 0 {
		return nil
	}
	remaining := make([]appliedEntry, 0, len(entries))
	var errs []error
	for _, entry := range entries {
		if err := p.release(entry); err != nil {
			remaining = append(remaining, entry)
			errs = append(errs, err)
		}
	}
	if len(remaining) == 0 {
		delete(p.pendingRollbacks, key)
	} else {
		p.pendingRollbacks[key] = remaining
	}
	return errors.Join(errs...)
}

func (p *EBPFRouteProgrammer) entries(intent RouteIntent) ([]appliedEntry, error) {
	serviceIP := intent.Service.IP
	entries := make([]appliedEntry, 0, len(intent.Ports)+2)
	if intent.Kind == RouteIntentRemoteProducer {
		serviceIfindex, err := p.target(intent.ServiceDevice)
		if err != nil {
			return nil, fmt.Errorf("resolve service interface %q: %w", intent.ServiceDevice, err)
		}
		consumerSID, err := ipv6Bytes(intent.ConsumerSID)
		if err != nil {
			return nil, err
		}
		for _, port := range intent.Ports {
			protocol, err := protocolNumber(port.Protocol)
			if err != nil {
				return nil, err
			}
			ref := grantRef{producerIfindex: serviceIfindex, address: serviceIP.String(), protocol: protocol,
				port: uint16(port.Port), grantID: intent.GrantID, consumerSID: consumerSID}
			entries = append(entries, appliedEntry{grant: &ref})
		}
		return entries, nil
	}
	consumerIfindex, err := p.target(intent.ConsumerDevice)
	if err != nil {
		return nil, fmt.Errorf("resolve consumer interface %q: %w", intent.ConsumerDevice, err)
	}
	// A protocol/port-zero marker makes malformed or non-TCP/UDP traffic to a
	// configured service fail closed without conflating distinct real tuples.
	entries = append(entries, appliedEntry{access: &accessRef{
		ingressIfindex: consumerIfindex, address: serviceIP.String(),
	}})
	var targetIfindex uint32
	var targetSID [16]byte
	if intent.Kind == RouteIntentRemoteConsumer {
		targetSID, err = ipv6Bytes(intent.ServiceSID)
		if err != nil {
			return nil, err
		}
	} else {
		targetIfindex, err = p.target(intent.ServiceDevice)
		if err != nil {
			return nil, fmt.Errorf("resolve service interface %q: %w", intent.ServiceDevice, err)
		}
	}
	for _, port := range intent.Ports {
		protocol, err := protocolNumber(port.Protocol)
		if err != nil {
			return nil, err
		}
		entries = append(entries, appliedEntry{access: &accessRef{
			ingressIfindex: consumerIfindex, address: serviceIP.String(), protocol: protocol, port: uint16(port.Port),
		}})
		ref := routeRef{ingressIfindex: consumerIfindex, address: serviceIP.String(), mode: intent.Kind,
			protocol: protocol, port: uint16(port.Port), grantID: intent.GrantID,
			targetIfindex: targetIfindex, targetSID: targetSID}
		entries = append(entries, appliedEntry{route: &ref})
	}
	return entries, nil
}

func ipv6Bytes(ip net.IP) ([16]byte, error) {
	var out [16]byte
	if ip == nil || ip.To4() != nil || ip.To16() == nil {
		return out, fmt.Errorf("service route SID %q is not IPv6", ip)
	}
	copy(out[:], ip.To16())
	return out, nil
}

func (p *EBPFRouteProgrammer) target(name string) (uint32, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return 0, err
	}
	return uint32(link.Attrs().Index), nil
}

func (p *EBPFRouteProgrammer) acquire(entry appliedEntry) error {
	if entry.grant != nil {
		if p.grantRefs[*entry.grant] == 0 {
			g := entry.grant
			if err := p.tables.RegisterRemoteGrant(g.producerIfindex, net.ParseIP(g.address), g.protocol, g.port,
				[16]byte(g.grantID), net.IP(g.consumerSID[:])); err != nil {
				return err
			}
		}
		p.grantRefs[*entry.grant]++
		return nil
	}
	if entry.access != nil {
		if p.accessRefs[*entry.access] == 0 {
			address := net.ParseIP(entry.access.address)
			if err := p.tables.RegisterAccess(
				entry.access.ingressIfindex, address, entry.access.protocol, entry.access.port,
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
	var err error
	if entry.route.mode == RouteIntentRemoteConsumer {
		err = p.tables.RegisterRemoteRoute(entry.route.ingressIfindex, net.ParseIP(entry.route.address),
			[16]byte(entry.route.grantID), entry.route.protocol, entry.route.port, net.IP(entry.route.targetSID[:]))
	} else {
		err = p.tables.RegisterRoute(entry.route.ingressIfindex, net.ParseIP(entry.route.address),
			entry.route.protocol, entry.route.port, entry.route.targetIfindex)
	}
	if err != nil {
		return err
	}
	p.routeRefs[key] = routeState{count: 1, ref: *entry.route}
	return nil
}

func (p *EBPFRouteProgrammer) release(entry appliedEntry) error {
	if entry.grant != nil {
		count := p.grantRefs[*entry.grant]
		if count > 1 {
			p.grantRefs[*entry.grant] = count - 1
			return nil
		}
		g := entry.grant
		if err := p.tables.UnregisterRemoteGrant(g.producerIfindex, net.ParseIP(g.address), g.protocol, g.port, [16]byte(g.grantID)); err != nil {
			return err
		}
		delete(p.grantRefs, *entry.grant)
		return nil
	}
	if entry.access != nil {
		count := p.accessRefs[*entry.access]
		if count > 1 {
			p.accessRefs[*entry.access] = count - 1
			return nil
		}
		if err := p.tables.UnregisterAccess(
			entry.access.ingressIfindex,
			net.ParseIP(entry.access.address),
			entry.access.protocol,
			entry.access.port,
		); err != nil {
			return err
		}
		delete(p.accessRefs, *entry.access)
		return nil
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
	if err := p.tables.UnregisterRoute(entry.route.ingressIfindex, net.ParseIP(entry.route.address),
		entry.route.protocol, entry.route.port); err != nil {
		return err
	}
	delete(p.routeRefs, key)
	return nil
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

func routeRefKey(ref routeRef) string {
	return fmt.Sprintf("%d|%s|%d|%d", ref.ingressIfindex, ref.address, ref.protocol, ref.port)
}

func intentKey(intent RouteIntent) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s|%s|%s|%s|%s|%s|%s|%x",
		intent.Attachment, intent.ProducerAttachment, intent.Kind, intent.Service, intent.ConsumerDevice,
		intent.ServiceDevice, intent.ServiceSID, intent.GrantID)
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
