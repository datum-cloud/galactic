// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package module is the boundary between Worker's reconciliation and the
// delivery modules that program the host: Local (#1435) for destinations on
// this node and Fabric (#1436) for destinations on other nodes.
//
// Worker resolves every destination, splits the claims of one VPC scope by
// mode and hands each module the complete desired state of the scope for its
// mode. A module never reads requests or decides authorization.
package module

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/internal/ownership"
)

// Scope is one VPC on this node: the unit of ownership and reconciliation.
type Scope struct {
	// VPC is the base62 VPC identifier.
	VPC string
}

// Name is the scope's name in the ownership fence.
func (s Scope) Name() string { return ownership.VPCScope(s.VPC) }

// ClaimKey names a claim. The owner is not part of it: one attachment has
// one owner, so node, VPC and attachment UID identify the claim.
type ClaimKey struct {
	Node          string
	VPC           string
	AttachmentUID string
}

func (k ClaimKey) String() string { return k.Node + "/" + k.VPC + "/" + k.AttachmentUID }

// Destination is one resolved destination.
type Destination struct {
	// ID identifies the destination within its claim, independent of its
	// position in the spec. DestinationID computes it.
	ID string
	// Ref is the destination as the client named it.
	Ref *workerv1alpha1.Destination
	// Mode is MODE_LOCAL or MODE_FABRIC.
	Mode workerv1alpha1.Mode
	// VPC is the destination's VPC, from its trusted source.
	VPC string
	// Node is the node the destination is on.
	Node string
	// Locator is the SRv6 locator of the destination's node.
	Locator netip.Prefix
	// Addresses are the destination's addresses, from its trusted source.
	// They are empty when the attachment records none, such as for a guest
	// that manages its own addressing.
	Addresses []netip.Addr
	// HostInterface is the host-side link of the destination's attachment,
	// from its trusted source, which a Local destination is delivered
	// through. It is empty until CNI has attached it.
	HostInterface string
}

// DestinationID is the identity of a destination within a claim.
func DestinationID(d *workerv1alpha1.Destination) string {
	switch t := d.GetTarget().(type) {
	case *workerv1alpha1.Destination_Attachment:
		return "attachment/" + t.Attachment.GetUid()
	case *workerv1alpha1.Destination_Shard:
		return fmt.Sprintf("shard/%s/%d", t.Shard.GetGroup(), t.Shard.GetIndex())
	case *workerv1alpha1.Destination_Backend:
		return fmt.Sprintf("backend/%s/%d", t.Backend.GetNode(), t.Backend.GetSlot())
	default:
		return ""
	}
}

// Claim is the desired state of one claim, restricted to the destinations a
// module programs.
type Claim struct {
	Key        ClaimKey
	Owner      string
	Generation uint64
	Handoff    workerv1alpha1.Handoff
	// OwnerPod is the UID of the pod the owner last called from, which a
	// routed link's pod end is created in.
	OwnerPod string
	// Addresses are the addresses of the claim's own attachment, from its
	// trusted source: for a routed link, the sources its pod end may use.
	Addresses []netip.Addr
	// Destinations are the claim's resolved destinations for the module's
	// mode, each with an available capability.
	Destinations []Destination
}

// DestinationState is what a module read back for one destination.
type DestinationState struct {
	// Generation is the claim generation the programmed state belongs to.
	Generation uint64
	// Programmed is true when the module's writes for the destination are on
	// the host, confirmed by read-back.
	Programmed bool
	// Ready is true when observed state, which the module did not write,
	// shows the handoff can carry traffic. It equals ForwardReady and
	// ReturnReady both being true.
	Ready bool
	// ForwardReady is true when traffic from the handoff can reach the
	// destination.
	ForwardReady bool
	// ReturnReady is true when traffic from the destination can come back to
	// the handoff.
	ReturnReady bool
	// Reason explains Programmed or Ready being false, with a contract
	// reason such as HandoffInterfaceMissing.
	Reason  string
	Message string
}

// State is a module's read-back for a scope, by claim and destination ID.
// A claim with no programmed state for any destination is absent.
type State map[ClaimKey]map[string]DestinationState

// Change is a module's prepared change for a scope.
type Change interface {
	// Empty reports that applying the change would write nothing.
	Empty() bool
}

// Capability is the state of one capability a module serves.
type Capability struct {
	Name      string
	Available bool
	// Reason is a contract reason when unavailable, such as
	// DatapathNotLoaded or HookUnsupported.
	Reason  string
	Message string
}

// Module programs the host for one delivery mode.
//
// Plan and Read must not write. Apply runs inside the scope's fence commit
// (internal/ownership): it must finish every write before it returns,
// must not call the fence, and must leave the host matching desired even
// when the host held rows from an earlier incarnation or a partial commit,
// because Worker calls it with the complete desired state of the scope.
type Module interface {
	// Name names the module, such as "local" or "fabric".
	Name() string
	// Mode is the destination mode the module programs.
	Mode() workerv1alpha1.Mode
	// Capabilities reports the capabilities the module serves.
	Capabilities() []Capability
	// Plan prepares the change that makes the scope match desired.
	Plan(ctx context.Context, scope Scope, desired []Claim) (Change, error)
	// Apply writes a change Plan prepared.
	Apply(ctx context.Context, scope Scope, change Change) error
	// Read reads the scope's programmed and observed state from the host.
	Read(ctx context.Context, scope Scope) (State, error)
}

// HandoffInterface is an interface a module created for a claim's handoff,
// reported to the claim's owner.
type HandoffInterface struct {
	// Role is one of the workerv1alpha1.HandoffRole* values.
	Role    string
	Name    string
	Ifindex int32
	// LinkLocal is a routed link host end's IPv6 link-local address, the
	// pod's next hop through the link. It is invalid for other roles and
	// until the kernel assigns it.
	LinkLocal netip.Addr
}

// HandoffReporter is implemented by a module that creates interfaces for a
// claim's handoff. Worker reports them in the claim's status.
type HandoffReporter interface {
	// HandoffInterfaces returns the interfaces the module has created for
	// each claim of scope, as of its last Read.
	HandoffInterfaces(scope Scope) map[ClaimKey][]HandoffInterface
}

// Registry is the set of modules Worker runs and the capability status it
// reports.
type Registry struct {
	modules []Module
}

// NewRegistry returns a registry over modules. Two modules for one mode are
// refused.
func NewRegistry(modules ...Module) (*Registry, error) {
	seen := map[workerv1alpha1.Mode]string{}
	for _, m := range modules {
		if other, ok := seen[m.Mode()]; ok {
			return nil, fmt.Errorf("module: %s and %s both serve %s", other, m.Name(), m.Mode())
		}
		seen[m.Mode()] = m.Name()
	}
	return &Registry{modules: slices.Clone(modules)}, nil
}

// Modules returns the registered modules.
func (r *Registry) Modules() []Module { return slices.Clone(r.modules) }

// ForMode returns the module serving mode.
func (r *Registry) ForMode(mode workerv1alpha1.Mode) (Module, bool) {
	for _, m := range r.modules {
		if m.Mode() == mode {
			return m, true
		}
	}
	return nil, false
}

// Capabilities returns one row per contract capability, in contract order.
// A capability no running module serves is Unavailable with
// ModuleNotRunning.
func (r *Registry) Capabilities() []Capability {
	served := map[string]Capability{}
	for _, m := range r.modules {
		for _, c := range m.Capabilities() {
			served[c.Name] = c
		}
	}
	out := make([]Capability, 0, len(workerv1alpha1.Capabilities))
	for _, name := range workerv1alpha1.Capabilities {
		c, ok := served[name]
		if !ok {
			c = Capability{Name: name, Reason: workerv1alpha1.ReasonModuleNotRunning,
				Message: "no running module serves " + name}
		}
		out = append(out, c)
	}
	return out
}

// Capability returns the status of one capability.
func (r *Registry) Capability(name string) Capability {
	for _, c := range r.Capabilities() {
		if c.Name == name {
			return c
		}
	}
	return Capability{Name: name, Reason: workerv1alpha1.ReasonModuleNotRunning}
}

// RequiredCapability is the capability a destination of mode needs for a
// claim with handoff: the handoff's Local capability for a Local
// destination, fabric.srv6 for a Fabric one.
func RequiredCapability(handoff workerv1alpha1.Handoff, mode workerv1alpha1.Mode) string {
	if mode == workerv1alpha1.Mode_MODE_FABRIC {
		return workerv1alpha1.CapabilityFabricSRv6
	}
	return workerv1alpha1.HandoffCapability(handoff)
}
