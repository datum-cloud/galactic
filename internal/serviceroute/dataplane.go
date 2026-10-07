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
	"reflect"
	"sort"
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
	consumerToken  uint64
	producerToken  uint64
}

type accessRef struct {
	ingressIfindex   uint32
	address          string
	protocol         uint8
	port             uint16
	attachmentToken  uint64
	markerDirections uint8
}

type accessKey struct {
	ingressIfindex uint32
	address        string
	protocol       uint8
	port           uint16
}

type accessState struct {
	token                   uint64
	regular, request, reply int
}

type denyRef struct {
	ingressIfindex   uint32
	address          string
	attachmentToken  uint64
	markerDirections uint8
}

type denyKey struct {
	ingressIfindex uint32
	address        string
}

type denyState struct {
	token          uint64
	request, reply int
}

type appliedEntry struct {
	route  *routeRef
	access *accessRef
	grant  *grantRef
	deny   *denyRef
}

type grantRef struct {
	producerIfindex uint32
	address         string
	protocol        uint8
	port            uint16
	grantID         ServiceGrantID
	consumerSID     [16]byte
	producerToken   uint64
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

	mu                   sync.Mutex
	tables               *serviceroutemap.Tables
	mapHandles           []*ebpf.Map
	mapIDs               [7]ebpf.MapID
	mapIDsValid          bool
	routeRefs            map[string]routeState
	accessRefs           map[accessKey]accessState
	denyRefs             map[denyKey]denyState
	grantRefs            map[grantRef]int
	appliedRefs          map[string][][]appliedEntry
	desiredIntents       map[string][]RouteIntent
	pendingRollbacks     map[string][]appliedEntry
	policyFinalized      bool
	syncFailures         int
	failedMutations      map[string]struct{}
	generationIncomplete bool

	// These hooks keep map replacement and interface recreation tests
	// deterministic without requiring a privileged kernel eBPF setup.
	openMapSetFn  func(string) (*serviceroutemap.Tables, []*ebpf.Map, [7]ebpf.MapID, error)
	readMapIDsFn  func(string) ([7]ebpf.MapID, error)
	targetIndexFn func(string) (uint32, error)
}

// Initialize opens the pinned maps without deleting state left by the running
// datapath. It also repairs entries whose interface names now resolve to new
// ifindexes. Apply initializes lazily so startup ordering remains tolerant.
func (p *EBPFRouteProgrammer) Initialize() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.ensureOpen(); err != nil {
		return err
	}
	if p.policyFinalized {
		return nil
	}
	if err := p.tables.SetPolicyEnabled(false); err != nil {
		return err
	}
	p.syncFailures = 0
	p.failedMutations = make(map[string]struct{})
	return nil
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
	p.clearSyncFailure(key)
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
			if len(rollbackErrs) != 0 {
				p.markSyncFailure(key)
			}
			return errors.Join(err, errors.Join(rollbackErrs...))
		}
		applied = append(applied, entry)
	}
	p.appliedRefs[key] = append(p.appliedRefs[key], applied)
	p.desiredIntents[key] = append(p.desiredIntents[key], cloneRouteIntent(intent))
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
		p.markSyncFailure(key)
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
		p.markSyncFailure(key)
		sets[len(sets)-1] = remaining
		p.appliedRefs[key] = sets
		return errors.Join(errs...)
	}
	if len(sets) == 1 {
		delete(p.appliedRefs, key)
		delete(p.desiredIntents, key)
	} else {
		p.appliedRefs[key] = sets[:len(sets)-1]
		desired := p.desiredIntents[key]
		p.desiredIntents[key] = desired[:len(desired)-1]
	}
	p.clearSyncFailure(key)
	return errors.Join(errs...)
}

func (p *EBPFRouteProgrammer) Cleanup(intent RouteIntent) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureOpen(); err != nil {
		return err
	}
	if err := p.retryRollback(intentKey(intent)); err != nil {
		return fmt.Errorf("retry prior service route rollback: %w", err)
	}
	p.clearSyncFailure(intentKey(intent))
	return nil
}

// Finalize removes policy entries that were not adopted from a complete
// cache-synchronized desired snapshot. It never removes reverse-flow state.
func (p *EBPFRouteProgrammer) Finalize() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.ensureOpen(); err != nil {
		return err
	}
	return p.finalizeLocked()
}

func (p *EBPFRouteProgrammer) finalizeLocked() error {
	if p.syncFailures != 0 || len(p.pendingRollbacks) != 0 {
		return fmt.Errorf("service route generation has %d failed mutations and %d pending rollbacks",
			p.syncFailures, len(p.pendingRollbacks))
	}
	snapshot := serviceroutemap.PolicySnapshot{
		Routes:       make([]serviceroutemap.RouteIdentity, 0, len(p.routeRefs)),
		Access:       make([]serviceroutemap.AccessIdentity, 0, len(p.accessRefs)),
		RemoteGrants: make([]serviceroutemap.RemoteGrantIdentity, 0, len(p.grantRefs)),
		Deny:         make([]serviceroutemap.DenyIdentity, 0, len(p.denyRefs)),
	}
	for _, state := range p.routeRefs {
		if state.count == 0 {
			continue
		}
		snapshot.Routes = append(snapshot.Routes, serviceroutemap.RouteIdentity{
			IngressIfindex: state.ref.ingressIfindex,
			Address:        net.ParseIP(state.ref.address),
			Protocol:       state.ref.protocol,
			Port:           state.ref.port,
		})
	}
	for access, state := range p.accessRefs {
		if accessStateCount(state) == 0 {
			continue
		}
		snapshot.Access = append(snapshot.Access, serviceroutemap.AccessIdentity{
			IngressIfindex: access.ingressIfindex,
			Address:        net.ParseIP(access.address),
			Protocol:       access.protocol,
			Port:           access.port,
		})
	}
	for deny, state := range p.denyRefs {
		if denyStateCount(state) == 0 {
			continue
		}
		snapshot.Deny = append(snapshot.Deny, serviceroutemap.DenyIdentity{
			IngressIfindex: deny.ingressIfindex, Address: net.ParseIP(deny.address),
		})
	}
	for grant, count := range p.grantRefs {
		if count == 0 {
			continue
		}
		snapshot.RemoteGrants = append(snapshot.RemoteGrants, serviceroutemap.RemoteGrantIdentity{
			ProducerIfindex: grant.producerIfindex,
			Address:         net.ParseIP(grant.address),
			Protocol:        grant.protocol,
			Port:            grant.port,
			GrantID:         [16]byte(grant.grantID),
		})
	}
	if err := p.tables.SweepPolicy(snapshot); err != nil {
		return err
	}
	if err := p.tables.SetPolicyEnabled(true); err != nil {
		return err
	}
	p.policyFinalized = true
	return nil
}

func (p *EBPFRouteProgrammer) ensureOpen() error {
	if p.tables != nil {
		changed, err := p.mapSetChanged()
		if err != nil {
			return err
		}
		if !changed {
			return p.repairDesired()
		}
		p.closeHandles()
	}
	tables, handles, ids, err := p.openMapSet(p.pinDir())
	if err != nil {
		return err
	}
	p.tables = tables
	p.mapHandles = handles
	p.mapIDs = ids
	p.mapIDsValid = true
	p.routeRefs = make(map[string]routeState)
	p.accessRefs = make(map[accessKey]accessState)
	p.denyRefs = make(map[denyKey]denyState)
	p.grantRefs = make(map[grantRef]int)
	p.appliedRefs = make(map[string][][]appliedEntry)
	p.pendingRollbacks = make(map[string][]appliedEntry)
	p.failedMutations = make(map[string]struct{})
	p.syncFailures = 0
	if p.desiredIntents == nil {
		p.desiredIntents = make(map[string][]RouteIntent)
		return nil
	}
	if err := p.rebuildDesired(); err != nil {
		p.closeHandles()
		return err
	}
	if p.policyFinalized {
		return p.finalizeLocked()
	}
	return nil
}

var serviceRouteMapNames = [...]string{
	"service_route_table",
	"service_access_table",
	"service_reverse_table",
	"service_remote_grant_table",
	"attachment_identity_table",
	"service_policy_state_table",
	"service_deny_table",
}

func (p *EBPFRouteProgrammer) mapSetChanged() (bool, error) {
	if !p.mapIDsValid {
		return true, nil
	}
	ids, err := p.readMapIDs(p.pinDir())
	if err != nil {
		return false, err
	}
	return ids != p.mapIDs, nil
}

func (p *EBPFRouteProgrammer) openMapSet(pinDir string) (*serviceroutemap.Tables, []*ebpf.Map, [7]ebpf.MapID, error) {
	if p.openMapSetFn != nil {
		return p.openMapSetFn(pinDir)
	}
	tables, handles, err := serviceroutemap.OpenPinned(pinDir)
	if err != nil {
		return nil, nil, [7]ebpf.MapID{}, err
	}
	var ids [7]ebpf.MapID
	for index, handle := range handles {
		ids[index], err = kernelMapID(handle)
		if err != nil {
			for _, opened := range handles {
				_ = opened.Close()
			}
			return nil, nil, [7]ebpf.MapID{}, err
		}
	}
	return tables, handles, ids, nil
}

func (p *EBPFRouteProgrammer) readMapIDs(pinDir string) ([7]ebpf.MapID, error) {
	if p.readMapIDsFn != nil {
		return p.readMapIDsFn(pinDir)
	}
	var ids [7]ebpf.MapID
	for index, name := range serviceRouteMapNames {
		current, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
		if err != nil {
			return ids, fmt.Errorf("open current %s map: %w", name, err)
		}
		ids[index], err = kernelMapID(current)
		_ = current.Close()
		if err != nil {
			return ids, err
		}
	}
	return ids, nil
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
	p.mapIDs = [7]ebpf.MapID{}
	p.mapIDsValid = false
}

func (p *EBPFRouteProgrammer) rebuildDesired() error {
	for _, key := range sortedIntentKeys(p.desiredIntents) {
		for _, intent := range p.desiredIntents[key] {
			entries, err := p.entries(intent)
			if err != nil {
				return fmt.Errorf("re-derive service route state %s: %w", key, err)
			}
			applied, err := p.acquireSet(entries)
			if err != nil {
				return fmt.Errorf("rebuild service route state %s: %w", key, err)
			}
			p.appliedRefs[key] = append(p.appliedRefs[key], applied)
		}
	}
	return nil
}

func (p *EBPFRouteProgrammer) repairDesired() error {
	needsRepair := p.generationIncomplete
	for _, key := range sortedIntentKeys(p.desiredIntents) {
		intents := p.desiredIntents[key]
		sets := p.appliedRefs[key]
		if len(sets) != len(intents) {
			needsRepair = true
			continue
		}
		for index, intent := range intents {
			fresh, err := p.entries(intent)
			if err != nil {
				return fmt.Errorf("re-derive service route state %s: %w", key, err)
			}
			if reflect.DeepEqual(sets[index], fresh) {
				continue
			}
			needsRepair = true
		}
	}
	if !needsRepair {
		return nil
	}
	// Value-bearing refs can share a kernel key. Transitioning them one intent
	// at a time lets a late release delete a value already rewritten with the
	// new interface token. Rebuild one complete generation behind the closed
	// gate instead.
	if err := p.tables.SetPolicyEnabled(false); err != nil {
		return err
	}
	p.policyFinalized = false
	p.generationIncomplete = true
	if err := p.tables.SweepPolicy(serviceroutemap.PolicySnapshot{}); err != nil {
		return fmt.Errorf("clear stale service policy generation: %w", err)
	}
	p.routeRefs = make(map[string]routeState)
	p.accessRefs = make(map[accessKey]accessState)
	p.denyRefs = make(map[denyKey]denyState)
	p.grantRefs = make(map[grantRef]int)
	p.appliedRefs = make(map[string][][]appliedEntry)
	p.pendingRollbacks = make(map[string][]appliedEntry)
	p.failedMutations = make(map[string]struct{})
	p.syncFailures = 0
	if err := p.rebuildDesired(); err != nil {
		p.markSyncFailure("__generation__")
		return err
	}
	if err := p.finalizeLocked(); err != nil {
		p.markSyncFailure("__generation__")
		return err
	}
	p.generationIncomplete = false
	return nil
}

func (p *EBPFRouteProgrammer) markSyncFailure(key string) {
	if p.failedMutations == nil {
		p.failedMutations = make(map[string]struct{})
	}
	if _, exists := p.failedMutations[key]; exists {
		return
	}
	p.failedMutations[key] = struct{}{}
	p.syncFailures++
}

func (p *EBPFRouteProgrammer) clearSyncFailure(key string) {
	if _, exists := p.failedMutations[key]; !exists {
		return
	}
	delete(p.failedMutations, key)
	if p.syncFailures > 0 {
		p.syncFailures--
	}
}

func (p *EBPFRouteProgrammer) acquireSet(entries []appliedEntry) ([]appliedEntry, error) {
	applied := make([]appliedEntry, 0, len(entries))
	for _, entry := range entries {
		if err := p.acquire(entry); err != nil {
			var rollbackErrs []error
			for index := len(applied) - 1; index >= 0; index-- {
				rollbackErrs = append(rollbackErrs, p.release(applied[index]))
			}
			return nil, errors.Join(err, errors.Join(rollbackErrs...))
		}
		applied = append(applied, entry)
	}
	return applied, nil
}

func (p *EBPFRouteProgrammer) releaseSet(entries []appliedEntry) error {
	released := make([]appliedEntry, 0, len(entries))
	for index := len(entries) - 1; index >= 0; index-- {
		if err := p.release(entries[index]); err != nil {
			var restoreErrs []error
			for restoreIndex := len(released) - 1; restoreIndex >= 0; restoreIndex-- {
				if restoreErr := p.acquire(released[restoreIndex]); restoreErr != nil {
					restoreErrs = append(restoreErrs, restoreErr)
				}
			}
			return errors.Join(err, errors.Join(restoreErrs...))
		}
		released = append(released, entries[index])
	}
	return nil
}

func sortedIntentKeys(intents map[string][]RouteIntent) []string {
	keys := make([]string, 0, len(intents))
	for key := range intents {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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
	entries := make([]appliedEntry, 0, 2*len(intent.Ports)+2)
	if intent.Kind == RouteIntentRemoteProducer {
		serviceIfindex, err := p.target(intent.ServiceDevice)
		if err != nil {
			return nil, fmt.Errorf("resolve service interface %q: %w", intent.ServiceDevice, err)
		}
		consumerSID, err := ipv6Bytes(intent.ConsumerSID)
		if err != nil {
			return nil, err
		}
		producerToken, err := p.tables.IdentityToken(serviceIfindex)
		if err != nil {
			return nil, err
		}
		// Producer-side source marker for fragments, whose missing transport
		// tuple cannot be matched against an individual grant.
		entries = append(entries, appliedEntry{access: &accessRef{
			ingressIfindex: serviceIfindex, address: serviceIP.String(), attachmentToken: producerToken,
			markerDirections: serviceroutemap.MarkerReply,
		}})
		entries = append(entries, appliedEntry{deny: &denyRef{
			ingressIfindex: serviceIfindex, address: serviceIP.String(), attachmentToken: producerToken,
			markerDirections: serviceroutemap.MarkerReply,
		}})
		for _, port := range intent.Ports {
			protocol, err := protocolNumber(port.Protocol)
			if err != nil {
				return nil, err
			}
			ref := grantRef{producerIfindex: serviceIfindex, address: serviceIP.String(), protocol: protocol,
				port: uint16(port.Port), grantID: intent.GrantID, consumerSID: consumerSID,
				producerToken: producerToken}
			entries = append(entries, appliedEntry{grant: &ref})
		}
		return entries, nil
	}
	consumerIfindex, err := p.target(intent.ConsumerDevice)
	if err != nil {
		return nil, fmt.Errorf("resolve consumer interface %q: %w", intent.ConsumerDevice, err)
	}
	consumerToken, err := p.tables.IdentityToken(consumerIfindex)
	if err != nil {
		return nil, err
	}
	// A protocol/port-zero marker makes malformed or non-TCP/UDP traffic to a
	// configured service fail closed without conflating distinct real tuples.
	entries = append(entries, appliedEntry{access: &accessRef{
		ingressIfindex: consumerIfindex, address: serviceIP.String(), attachmentToken: consumerToken,
		markerDirections: serviceroutemap.MarkerRequest,
	}})
	entries = append(entries, appliedEntry{deny: &denyRef{
		ingressIfindex: consumerIfindex, address: serviceIP.String(), attachmentToken: consumerToken,
		markerDirections: serviceroutemap.MarkerRequest,
	}})
	var targetIfindex uint32
	var producerToken uint64
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
		producerToken, err = p.tables.IdentityToken(targetIfindex)
		if err != nil {
			return nil, err
		}
		// Local replies need the same address-only producer marker. Its
		// refcount is independent from the consumer marker because ifindex is
		// part of the key.
		entries = append(entries, appliedEntry{access: &accessRef{
			ingressIfindex: targetIfindex, address: serviceIP.String(), attachmentToken: producerToken,
			markerDirections: serviceroutemap.MarkerReply,
		}})
		entries = append(entries, appliedEntry{deny: &denyRef{
			ingressIfindex: targetIfindex, address: serviceIP.String(), attachmentToken: producerToken,
			markerDirections: serviceroutemap.MarkerReply,
		}})
	}
	for _, port := range intent.Ports {
		protocol, err := protocolNumber(port.Protocol)
		if err != nil {
			return nil, err
		}
		entries = append(entries, appliedEntry{access: &accessRef{
			ingressIfindex: consumerIfindex, address: serviceIP.String(), protocol: protocol, port: uint16(port.Port),
			attachmentToken: consumerToken,
		}})
		ref := routeRef{ingressIfindex: consumerIfindex, address: serviceIP.String(), mode: intent.Kind,
			protocol: protocol, port: uint16(port.Port), grantID: intent.GrantID,
			targetIfindex: targetIfindex, targetSID: targetSID, consumerToken: consumerToken,
			producerToken: producerToken}
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
	if p.targetIndexFn != nil {
		return p.targetIndexFn(name)
	}
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
				[16]byte(g.grantID), net.IP(g.consumerSID[:]), g.producerToken); err != nil {
				return err
			}
		}
		p.grantRefs[*entry.grant]++
		return nil
	}
	if entry.access != nil {
		key := accessRefKey(*entry.access)
		state := p.accessRefs[key]
		if accessStateCount(state) != 0 && state.token != entry.access.attachmentToken {
			return fmt.Errorf("service access %v has conflicting attachment tokens", key)
		}
		state.token = entry.access.attachmentToken
		incrementAccessState(&state, entry.access.markerDirections)
		if err := p.tables.RegisterAccess(key.ingressIfindex, net.ParseIP(key.address), key.protocol, key.port,
			state.token, accessStateDirections(state)); err != nil {
			return err
		}
		p.accessRefs[key] = state
		return nil
	}
	if entry.deny != nil {
		key := denyRefKey(*entry.deny)
		state := p.denyRefs[key]
		if denyStateCount(state) != 0 && state.token != entry.deny.attachmentToken {
			return fmt.Errorf("service deny %v has conflicting attachment tokens", key)
		}
		state.token = entry.deny.attachmentToken
		incrementDenyState(&state, entry.deny.markerDirections)
		if err := p.tables.RegisterDeny(key.ingressIfindex, net.ParseIP(key.address), state.token,
			denyStateDirections(state)); err != nil {
			return err
		}
		p.denyRefs[key] = state
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
			[16]byte(entry.route.grantID), entry.route.protocol, entry.route.port, net.IP(entry.route.targetSID[:]),
			entry.route.consumerToken)
	} else {
		err = p.tables.RegisterRoute(entry.route.ingressIfindex, net.ParseIP(entry.route.address),
			entry.route.protocol, entry.route.port, entry.route.targetIfindex,
			entry.route.consumerToken, entry.route.producerToken)
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
		if err := p.tables.UnregisterRemoteGrant(
			g.producerIfindex, net.ParseIP(g.address), g.protocol, g.port, [16]byte(g.grantID),
		); err != nil {
			return err
		}
		delete(p.grantRefs, *entry.grant)
		return nil
	}
	if entry.access != nil {
		key := accessRefKey(*entry.access)
		state, ok := p.accessRefs[key]
		if !ok {
			return nil
		}
		decrementAccessState(&state, entry.access.markerDirections)
		if accessStateCount(state) == 0 {
			if err := p.tables.UnregisterAccess(key.ingressIfindex, net.ParseIP(key.address), key.protocol, key.port); err != nil {
				return err
			}
			delete(p.accessRefs, key)
			return nil
		}
		if err := p.tables.RegisterAccess(key.ingressIfindex, net.ParseIP(key.address), key.protocol, key.port,
			state.token, accessStateDirections(state)); err != nil {
			return err
		}
		p.accessRefs[key] = state
		return nil
	}
	if entry.deny != nil {
		key := denyRefKey(*entry.deny)
		state, ok := p.denyRefs[key]
		if !ok {
			return nil
		}
		decrementDenyState(&state, entry.deny.markerDirections)
		if denyStateCount(state) == 0 {
			if err := p.tables.UnregisterDeny(key.ingressIfindex, net.ParseIP(key.address)); err != nil {
				return err
			}
			delete(p.denyRefs, key)
			return nil
		}
		if err := p.tables.RegisterDeny(key.ingressIfindex, net.ParseIP(key.address), state.token,
			denyStateDirections(state)); err != nil {
			return err
		}
		p.denyRefs[key] = state
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

func accessRefKey(ref accessRef) accessKey {
	return accessKey{ingressIfindex: ref.ingressIfindex, address: ref.address, protocol: ref.protocol, port: ref.port}
}

func accessStateCount(state accessState) int { return state.regular + state.request + state.reply }

func accessStateDirections(state accessState) uint8 {
	var directions uint8
	if state.request != 0 {
		directions |= serviceroutemap.MarkerRequest
	}
	if state.reply != 0 {
		directions |= serviceroutemap.MarkerReply
	}
	return directions
}

func incrementAccessState(state *accessState, directions uint8) {
	if directions == 0 {
		state.regular++
	}
	if directions&serviceroutemap.MarkerRequest != 0 {
		state.request++
	}
	if directions&serviceroutemap.MarkerReply != 0 {
		state.reply++
	}
}

func decrementAccessState(state *accessState, directions uint8) {
	if directions == 0 && state.regular > 0 {
		state.regular--
	}
	if directions&serviceroutemap.MarkerRequest != 0 && state.request > 0 {
		state.request--
	}
	if directions&serviceroutemap.MarkerReply != 0 && state.reply > 0 {
		state.reply--
	}
}

func denyRefKey(ref denyRef) denyKey {
	return denyKey{ingressIfindex: ref.ingressIfindex, address: ref.address}
}

func denyStateCount(state denyState) int { return state.request + state.reply }

func denyStateDirections(state denyState) uint8 {
	var directions uint8
	if state.request != 0 {
		directions |= serviceroutemap.MarkerRequest
	}
	if state.reply != 0 {
		directions |= serviceroutemap.MarkerReply
	}
	return directions
}

func incrementDenyState(state *denyState, directions uint8) {
	if directions&serviceroutemap.MarkerRequest != 0 {
		state.request++
	}
	if directions&serviceroutemap.MarkerReply != 0 {
		state.reply++
	}
}

func decrementDenyState(state *denyState, directions uint8) {
	if directions&serviceroutemap.MarkerRequest != 0 && state.request > 0 {
		state.request--
	}
	if directions&serviceroutemap.MarkerReply != 0 && state.reply > 0 {
		state.reply--
	}
}

func routeRefKey(ref routeRef) string {
	return fmt.Sprintf("%d|%s|%d|%d", ref.ingressIfindex, ref.address, ref.protocol, ref.port)
}

func intentKey(intent RouteIntent) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s|%s|%s|%s|%s|%s|%s|%s|%x",
		intent.Attachment, intent.ProducerAttachment, intent.Kind, intent.Service, intent.ConsumerDevice,
		intent.ServiceDevice, intent.ServiceSID, intent.ConsumerSID, intent.GrantID)
	for _, port := range intent.Ports {
		fmt.Fprintf(&builder, "|%s:%d", port.Protocol, port.Port)
	}
	return builder.String()
}

func cloneRouteIntent(intent RouteIntent) RouteIntent {
	cloned := intent
	if intent.Service != nil {
		cloned.Service = &net.IPNet{
			IP:   append(net.IP(nil), intent.Service.IP...),
			Mask: append(net.IPMask(nil), intent.Service.Mask...),
		}
	}
	cloned.ServiceSID = append(net.IP(nil), intent.ServiceSID...)
	cloned.ConsumerSID = append(net.IP(nil), intent.ConsumerSID...)
	cloned.Ports = append([]api.ServiceRouteProtocolPort(nil), intent.Ports...)
	return cloned
}

func (p *EBPFRouteProgrammer) pinDir() string {
	if p.PinDir != "" {
		return p.PinDir
	}
	return attach.PinDir
}
