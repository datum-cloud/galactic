// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package worker

import (
	"context"
	"math"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/srv6"
	"go.datum.net/galactic/internal/worker/module"
	"go.datum.net/galactic/internal/worker/module/fake"
	"go.datum.net/galactic/internal/worker/sources"
)

const (
	backendLocalUID  = "backend-a"
	backendRemoteUID = "backend-remote"
	backendTap       = "tapBackendA"
	backendPort      = 8080
)

var (
	// The local and remote backends use the same address on different
	// nodes, as backends of one VPC may.
	backendAddr       = netip.MustParseAddr("2001:db8:10::5")
	backendRemoteAddr = netip.MustParseAddr("2001:db8:10::6")
	slotLocal         = srv6.BackendSlot(backendAddr, backendPort)
	slotRemote        = srv6.BackendSlot(backendRemoteAddr, backendPort)
)

// withBackends adds a backend VPCAttachment of vpcA on this node and one on
// the other node, each with a Bound ServiceVIPBinding.
func withBackends(e *env) {
	e.src.SetAttachment(sources.Attachment{UID: backendLocalUID, Kind: sources.KindVPCAttachment, VPC: vpcA,
		Node: node, Admitted: true, Addresses: []netip.Addr{backendAddr}, HostInterface: backendTap})
	e.src.SetAttachment(sources.Attachment{UID: backendRemoteUID, Kind: sources.KindVPCAttachment, VPC: vpcA,
		Node: otherNode, Admitted: true, Addresses: []netip.Addr{backendRemoteAddr}, HostInterface: "tapRemote"})
	e.src.SetBackendBinding(bindingOf("bind-local", node, vpcA, backendAddr, backendPort, true))
	e.src.SetBackendBinding(bindingOf("bind-remote", otherNode, vpcA, backendRemoteAddr, backendPort, true))
}

func bindingOf(name, n, vpc string, addr netip.Addr, port uint16, bound bool) sources.BackendBinding {
	return sources.BackendBinding{Name: name, Node: n, VPCRef: vpc, BackendAddress: addr, BackendPort: port,
		Bound: bound}
}

func backendDest(n string, slot uint32) *workerv1alpha1.Destination {
	return &workerv1alpha1.Destination{Target: &workerv1alpha1.Destination_Backend{
		Backend: &workerv1alpha1.BackendRef{Node: n, Slot: slot}}}
}

// gatewaySpec is the gateway's claim: a TAP toward backend slots on this
// node, Local only.
func gatewaySpec(slots ...uint16) *workerv1alpha1.ClaimSpec {
	s := &workerv1alpha1.ClaimSpec{Handoff: workerv1alpha1.Handoff_HANDOFF_TAP, Mode: workerv1alpha1.Mode_MODE_LOCAL}
	for _, slot := range slots {
		s.Destinations = append(s.Destinations, backendDest(node, uint32(slot)))
	}
	return s
}

// resolvedReason waits for claim k at gen to report Resolved=False and
// returns its reason.
func (e *env) resolvedReason(k module.ClaimKey, gen uint64, want string) {
	e.t.Helper()
	e.eventually("Resolved=False/"+want, func() bool {
		st := e.status(k)
		c := condOf(st, workerv1alpha1.ConditionResolved)
		return st.GetObservedGeneration() == gen && c.GetStatus() == condFalse && c.GetReason() == want
	})
}

// TestBackendRefValidation refuses a backend with no node, slot 0, or a
// slot wider than 16 bits.
func TestBackendRefValidation(t *testing.T) {
	e := newEnv(t)
	withBackends(e)
	e.start()
	for name, ref := range map[string]*workerv1alpha1.BackendRef{
		"no node":    {Slot: uint32(slotLocal)},
		"slot 0":     {Node: node},
		"wide slot":  {Node: node, Slot: math.MaxUint16 + 1},
		"empty":      {},
		"wider slot": {Node: node, Slot: math.MaxUint32},
	} {
		t.Run(name, func(t *testing.T) {
			s := &workerv1alpha1.ClaimSpec{Handoff: workerv1alpha1.Handoff_HANDOFF_TAP,
				Destinations: []*workerv1alpha1.Destination{{Target: &workerv1alpha1.Destination_Backend{Backend: ref}}}}
			wantRefusal(t, e.request(gwSA, key(vpcA, backendLocalUID), 1, s), codes.InvalidArgument,
				workerv1alpha1.ReasonMalformedSpec)
		})
	}
	if recs, _ := e.store.List(); len(recs) != 0 {
		t.Fatalf("refused calls recorded %v", recs)
	}
}

// TestBackendLocalResolution resolves the gateway's claim on a backend's own
// VPCAttachment: the backend on this node resolves to Local, as its
// attachment, with the bindings that named it. Two Bound bindings of one
// backend, such as one per VIP, are not a conflict.
func TestBackendLocalResolution(t *testing.T) {
	e := newEnv(t)
	withBackends(e)
	e.src.SetBackendBinding(bindingOf("bind-local-v4", node, vpcA, backendAddr, backendPort, true))
	e.start()

	e.mustOK(e.request(gwSA, key(vpcA, backendLocalUID), 1, gatewaySpec(slotLocal)))
	st := e.waitReady(mkey(vpcA, backendLocalUID), 1)
	if ds := st.GetDestinations(); len(ds) != 1 || ds[0].GetMode() != workerv1alpha1.Mode_MODE_LOCAL ||
		!ds[0].GetResolved() || !ds[0].GetProgrammed() {
		t.Fatalf("destinations = %v, want one programmed Local backend", ds)
	}
	got := destinationsOf(e.local.Desired(vpcA), mkey(vpcA, backendLocalUID))
	if len(got) != 1 {
		t.Fatalf("Local destinations = %+v, want the backend", got)
	}
	d := got[0]
	if d.ID != module.DestinationID(backendDest(node, uint32(slotLocal))) || d.Mode != workerv1alpha1.Mode_MODE_LOCAL ||
		d.VPC != vpcA || d.Node != node || d.Locator != locA || d.HostInterface != backendTap ||
		!slices.Equal(d.Addresses, []netip.Addr{backendAddr}) || d.Shard != nil {
		t.Fatalf("Local destination = %+v, want the backend's VPCAttachment", d)
	}
	want := module.BackendTarget{Slot: slotLocal, Address: backendAddr, Port: backendPort,
		Bindings: []string{"bind-local", "bind-local-v4"}}
	if d.Backend == nil || d.Backend.Slot != want.Slot || d.Backend.Address != want.Address ||
		d.Backend.Port != want.Port || !slices.Equal(d.Backend.Bindings, want.Bindings) {
		t.Fatalf("backend target = %+v, want %+v", d.Backend, want)
	}
	if rows := e.host.Rows(vpcA); len(rows) != 1 {
		t.Fatalf("rows = %v, want the backend's", rowIDs(rows))
	}
}

// TestBackendFabricResolution resolves a backend on another node to Fabric
// toward that node's locator.
func TestBackendFabricResolution(t *testing.T) {
	e := newEnv(t)
	withBackends(e)
	e.start()

	s := &workerv1alpha1.ClaimSpec{Handoff: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR,
		Destinations: []*workerv1alpha1.Destination{backendDest(otherNode, uint32(slotRemote))}}
	e.mustOK(e.request(otherSA, key(vpcA, svcA), 1, s))
	e.waitReady(mkey(vpcA, svcA), 1)
	got := destinationsOf(e.fabric.Desired(vpcA), mkey(vpcA, svcA))
	if len(got) != 1 || got[0].Mode != workerv1alpha1.Mode_MODE_FABRIC || got[0].Locator != locB ||
		got[0].Node != otherNode || got[0].Backend == nil || got[0].Backend.Address != backendRemoteAddr ||
		!slices.Equal(got[0].Addresses, []netip.Addr{backendRemoteAddr}) {
		t.Fatalf("Fabric destinations = %+v, want the remote backend toward %s", got, locB)
	}

	// A caller without fabric.srv6 may not claim a backend on another node.
	wantRefusal(t, e.request(gwSA, key(vpcA, backendLocalUID), 1, &workerv1alpha1.ClaimSpec{
		Handoff:      workerv1alpha1.Handoff_HANDOFF_TAP,
		Destinations: []*workerv1alpha1.Destination{backendDest(otherNode, uint32(slotRemote))},
	}), codes.PermissionDenied, workerv1alpha1.ReasonCapabilityNotAllowed)
}

// TestBackendNotBound reports BackendNotBound for a slot no Bound binding
// names: none at all, one not Bound, and one that stops counting, as a
// binding being deleted does, or is deleted.
func TestBackendNotBound(t *testing.T) {
	e := newEnv(t)
	withBackends(e)
	e.src.SetBackendBinding(bindingOf("bind-unbound", node, vpcA, backendAddr, backendPort+1, false))
	e.start()

	// No binding names the slot.
	free := slotLocal + 1
	for free == slotRemote || free == srv6.BackendSlot(backendAddr, backendPort+1) || free == 0 {
		free++
	}
	e.mustOK(e.request(gwSA, key(vpcA, backendLocalUID), 1, gatewaySpec(free)))
	e.resolvedReason(mkey(vpcA, backendLocalUID), 1, workerv1alpha1.ReasonBackendNotBound)

	// A binding that is not Bound.
	e.mustOK(e.update(gwSA, key(vpcA, backendLocalUID), 2,
		gatewaySpec(srv6.BackendSlot(backendAddr, backendPort+1))))
	e.resolvedReason(mkey(vpcA, backendLocalUID), 2, workerv1alpha1.ReasonBackendNotBound)

	// A Bound binding that stops counting, then is deleted.
	e.mustOK(e.update(gwSA, key(vpcA, backendLocalUID), 3, gatewaySpec(slotLocal)))
	e.waitReady(mkey(vpcA, backendLocalUID), 3)
	e.src.SetBackendBinding(bindingOf("bind-local", node, vpcA, backendAddr, backendPort, false))
	e.w.Changed(vpcA)
	e.resolvedReason(mkey(vpcA, backendLocalUID), 3, workerv1alpha1.ReasonBackendNotBound)
	e.src.DeleteBackendBinding("bind-local")
	e.w.Changed(vpcA)
	e.resolvedReason(mkey(vpcA, backendLocalUID), 3, workerv1alpha1.ReasonBackendNotBound)
	e.idle()
	if rows := e.host.Rows(vpcA); len(rows) != 0 {
		t.Fatalf("rows = %v, want the unbound backend's removed", rowIDs(rows))
	}

	// Bound again, it resolves again.
	e.src.SetBackendBinding(bindingOf("bind-local", node, vpcA, backendAddr, backendPort, true))
	e.w.Changed(vpcA)
	e.waitReady(mkey(vpcA, backendLocalUID), 3)
}

// collidingBackend returns a backend address and port other than addr:port
// that hashes to the same slot.
func collidingBackend(t *testing.T, addr netip.Addr, port uint16) (netip.Addr, uint16) {
	t.Helper()
	slot := srv6.BackendSlot(addr, port)
	a := netip.MustParseAddr("2001:db8:20::1")
	for range 64 {
		for p := 1; p <= math.MaxUint16; p++ {
			if (a != addr || uint16(p) != port) && srv6.BackendSlot(a, uint16(p)) == slot {
				return a, uint16(p)
			}
		}
		a = a.Next()
	}
	t.Fatal("no colliding backend found")
	return netip.Addr{}, 0
}

// TestBackendSlotConflict reports BackendSlotConflict while two Bound
// bindings of one VPC name different backends with the same slot, and
// resolves once one goes.
func TestBackendSlotConflict(t *testing.T) {
	e := newEnv(t)
	withBackends(e)
	addr, port := collidingBackend(t, backendAddr, backendPort)
	e.src.SetBackendBinding(bindingOf("bind-collide", node, vpcA, addr, port, true))
	e.start()

	e.mustOK(e.request(gwSA, key(vpcA, backendLocalUID), 1, gatewaySpec(slotLocal)))
	e.resolvedReason(mkey(vpcA, backendLocalUID), 1, workerv1alpha1.ReasonBackendSlotConflict)
	if rows := e.host.Rows(vpcA); len(rows) != 0 {
		t.Fatalf("rows = %v, want none for a conflicting slot", rowIDs(rows))
	}

	// A binding that is not Bound does not conflict.
	e.src.SetBackendBinding(bindingOf("bind-collide", node, vpcA, addr, port, false))
	e.w.Changed(vpcA)
	e.waitReady(mkey(vpcA, backendLocalUID), 1)
}

// TestBackendVPC refuses a backend bound only in another VPC, and reports
// VPCNotAuthorized once a claimed backend's binding moves to another VPC.
// Two VPCs may bind the same backend address on one node, which hashes to
// the same slot; only the claim's VPC's binding counts, and it is no
// conflict.
func TestBackendVPC(t *testing.T) {
	e := newEnv(t)
	withBackends(e)
	e.src.SetAttachment(sources.Attachment{UID: "backend-b", Kind: sources.KindVPCAttachment, VPC: vpcB,
		Node: node, Admitted: true, Addresses: []netip.Addr{backendAddr}, HostInterface: "tapBackendB"})
	e.src.SetBackendBinding(bindingOf("bind-b", node, vpcB, backendAddr, backendPort, true))
	e.start()

	// Both VPCs' claims resolve to their own attachment.
	e.mustOK(e.request(gwSA, key(vpcA, backendLocalUID), 1, gatewaySpec(slotLocal)))
	e.mustOK(e.request(gwSA, key(vpcB, "backend-b"), 1, gatewaySpec(slotLocal)))
	e.waitReady(mkey(vpcA, backendLocalUID), 1)
	e.waitReady(mkey(vpcB, "backend-b"), 1)
	if d := destinationsOf(e.local.Desired(vpcB), mkey(vpcB, "backend-b")); len(d) != 1 ||
		d[0].HostInterface != "tapBackendB" || d[0].VPC != vpcB {
		t.Fatalf("vpcB destinations = %+v, want vpcB's own TAP", d)
	}

	// A slot bound only in another VPC is refused at admission.
	e.src.DeleteBackendBinding("bind-local")
	wantRefusal(t, e.request(gwSA, key(vpcA, svcA2), 1, gatewaySpec(slotLocal)), codes.PermissionDenied,
		workerv1alpha1.ReasonVPCNotAuthorized)

	// The claimed backend's binding left vpcA: it no longer resolves.
	e.w.Changed(vpcA)
	e.resolvedReason(mkey(vpcA, backendLocalUID), 1, workerv1alpha1.ReasonVPCNotAuthorized)

	// A binding in the claim's VPC whose address no VPCAttachment of the VPC
	// on the node holds names no destination.
	e.src.SetBackendBinding(bindingOf("bind-local", node, vpcA, backendAddr, backendPort, true))
	e.src.SetAttachment(sources.Attachment{UID: backendLocalUID, Kind: sources.KindVPCAttachment, VPC: vpcA,
		Node: node, Admitted: true, HostInterface: backendTap})
	e.w.Changed(vpcA)
	e.resolvedReason(mkey(vpcA, backendLocalUID), 1, workerv1alpha1.ReasonDestinationNotFound)
}

// TestBackendModeUnavailable reports ModeUnavailable when a backend resolves
// to the mode the preference excludes, either way, and never falls back.
func TestBackendModeUnavailable(t *testing.T) {
	e := newEnv(t)
	withBackends(e)
	e.start()

	fabricOnly := &workerv1alpha1.ClaimSpec{Handoff: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR,
		Mode:         workerv1alpha1.Mode_MODE_FABRIC,
		Destinations: []*workerv1alpha1.Destination{backendDest(node, uint32(slotLocal))}}
	e.mustOK(e.request(otherSA, key(vpcA, svcA), 1, fabricOnly))
	e.resolvedReason(mkey(vpcA, svcA), 1, workerv1alpha1.ReasonModeUnavailable)

	localOnly := &workerv1alpha1.ClaimSpec{Handoff: workerv1alpha1.Handoff_HANDOFF_VETH_PAIR,
		Mode:         workerv1alpha1.Mode_MODE_LOCAL,
		Destinations: []*workerv1alpha1.Destination{backendDest(otherNode, uint32(slotRemote))}}
	e.mustOK(e.request(otherSA, key(vpcA, svcA2), 1, localOnly))
	e.resolvedReason(mkey(vpcA, svcA2), 1, workerv1alpha1.ReasonModeUnavailable)
	if st := e.status(mkey(vpcA, svcA2)); st.GetDestinations()[0].GetMode() != workerv1alpha1.Mode_MODE_FABRIC {
		t.Fatalf("destination status = %v, want the Fabric mode it resolves to", st.GetDestinations())
	}
	e.idle()
	if rows := e.host.Rows(vpcA); len(rows) != 0 {
		t.Fatalf("rows = %v, want none", rowIDs(rows))
	}
}

// tapModule is a Local module that reports a TAP for every local.tap claim,
// as the Local module reports each TAP lt_tap authorizes.
type tapModule struct {
	*fake.Module
	mu   sync.Mutex
	taps map[module.ClaimKey][]string
}

func (m *tapModule) Plan(ctx context.Context, scope module.Scope, desired []module.Claim) (module.Change, error) {
	m.mu.Lock()
	for _, c := range desired {
		if c.Handoff != workerv1alpha1.Handoff_HANDOFF_TAP {
			continue
		}
		m.taps[c.Key] = nil
		for _, d := range c.Destinations {
			m.taps[c.Key] = append(m.taps[c.Key], d.HostInterface)
		}
	}
	m.mu.Unlock()
	return m.Module.Plan(ctx, scope, desired)
}

func (m *tapModule) HandoffInterfaces(scope module.Scope) map[module.ClaimKey][]module.HandoffInterface {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[module.ClaimKey][]module.HandoffInterface{}
	for k, names := range m.taps {
		if k.VPC != scope.VPC {
			continue
		}
		for i, n := range names {
			out[k] = append(out[k], module.HandoffInterface{Role: workerv1alpha1.HandoffRoleTap, Name: n,
				Ifindex: int32(40 + i)})
		}
	}
	return out
}

// TestBackendTapHandoffInterface reports the backend's TAP in the gateway
// claim's status, which the gateway keys its datapath on.
func TestBackendTapHandoffInterface(t *testing.T) {
	e := newEnv(t)
	withBackends(e)
	tm := &tapModule{taps: map[module.ClaimKey][]string{}}
	e.modules = func(h *fake.Host) []module.Module {
		tm.Module = fake.New("local", workerv1alpha1.Mode_MODE_LOCAL, h)
		e.local = tm.Module
		return []module.Module{tm, fake.New("fabric", workerv1alpha1.Mode_MODE_FABRIC, h)}
	}
	e.start()
	e.mustOK(e.request(gwSA, key(vpcA, backendLocalUID), 1, gatewaySpec(slotLocal)))
	st := e.waitReady(mkey(vpcA, backendLocalUID), 1)
	got := st.GetHandoffInterfaces()
	if len(got) != 1 || got[0].GetRole() != workerv1alpha1.HandoffRoleTap || got[0].GetName() != backendTap ||
		got[0].GetIfindex() != 40 {
		t.Fatalf("handoff interfaces = %v, want the backend's TAP", got)
	}
}
