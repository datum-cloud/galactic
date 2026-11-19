// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sources reads the facts Worker takes only from trusted sources,
// never from a request (docs/worker/contract.md, "Trusted sources"): an
// attachment's VPC, node and admission, a node's physical locator, an
// egress shard's node and SID, and the backend a load-balancer slot names.
package sources

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/nodelocator"
	"go.datum.net/galactic/internal/plumbing/srv6"
)

// Attachment kinds.
const (
	KindVPCAttachment  = "VPCAttachment"
	KindEdgeAttachment = "EdgeAttachment"
	// KindEgressShard marks the record Worker builds for a claim whose
	// attachment is an EgressShard.
	KindEgressShard = "EgressShard"
)

// Attachment is the trusted record of an attachment.
type Attachment struct {
	UID  string
	Kind string
	// VPC is the base62 VPC identifier the attachment's authority recorded.
	VPC string
	// Node is the node the attachment lives on.
	Node string
	// Admitted is false for an attachment being deleted, and for an
	// EdgeAttachment whose Admitted condition is not True.
	Admitted bool
	// Addresses are the attachment's interface addresses from its spec,
	// without their prefix lengths. A VPCAttachment whose guest manages its
	// own addressing records none, and neither does an EdgeAttachment.
	Addresses []netip.Addr
	// HostInterface is the host-side link CNI created for a VPCAttachment,
	// as its status records: the TAP or host veth. It is empty for an
	// attachment not yet attached and for an EdgeAttachment.
	HostInterface string
}

// EgressShard is the trusted record of an egress translation shard: its
// identity from status, which galactic-nat writes for the identity its
// datapath translates with, and its node from spec.targetRef.
type EgressShard struct {
	UID  string
	Name string
	// Node is the node the shard runs on.
	Node string
	// SID is the shard SID its datapath is programmed with
	// (status.shardSID), or the zero address while it has none. Its Block
	// and Node-ID are the shard's own locator, which admission keeps
	// distinct from every BGPRouter's.
	SID netip.Addr
	// Ready is true while the shard is not being deleted, reports a SID,
	// and its Programmed and Ready conditions are True: the evidence the
	// installer's group candidates use.
	Ready bool
	// Draining echoes spec.drain.
	Draining bool
}

// BackendBinding is the trusted record of a ServiceVIPBinding: what
// galactic-router wrote for one backend of a service on one node, and
// whether that node confirmed it.
type BackendBinding struct {
	Name string
	// Node is the backend's node (spec.targetRef).
	Node string
	// VPCRef is spec.vpcRef, copied from the owning NetworkService: a VPC's
	// status.vpc, the base62 identifier VPCAttachment.status.vpc also
	// records, so it compares directly with an attachment's VPC.
	VPCRef string
	// BackendAddress is the backend's own IPv6 address.
	BackendAddress netip.Addr
	// BackendPort is the backend's own port; for a port-preserving range
	// binding, the range's first port, as galactic-router keys its rows.
	BackendPort uint16
	// Bound is true while the binding is not being deleted, its source
	// authority, if it has one, is enforced, and its Bound condition is True
	// for its current generation: the evidence the gateway trusts.
	Bound bool
}

// Sources answers Worker's trusted-source lookups.
type Sources interface {
	// Attachment returns the attachment with uid, and false when none
	// exists.
	Attachment(ctx context.Context, uid string) (Attachment, bool, error)
	// Locator returns node's SRv6 locator, or the zero prefix while it has
	// none.
	Locator(ctx context.Context, node string) (netip.Prefix, error)
	// EgressShard returns the EgressShard named name, and false when none
	// exists.
	EgressShard(ctx context.Context, name string) (EgressShard, bool, error)
	// EgressShardByUID returns the EgressShard with uid, and false when
	// none exists.
	EgressShardByUID(ctx context.Context, uid string) (EgressShard, bool, error)
	// VPCAttachments returns the admitted VPCAttachments of vpc on node.
	VPCAttachments(ctx context.Context, vpc, node string) ([]Attachment, error)
	// BackendBindings returns the ServiceVIPBindings for node whose IPv6
	// backend address and port hash to slot (srv6.BackendSlot), Bound or
	// not, sorted by name.
	BackendBindings(ctx context.Context, node string, slot uint16) ([]BackendBinding, error)
}

// uidIndex indexes attachments and EgressShards by metadata.uid.
const uidIndex = "metadata.uid"

// vpcIndex indexes VPCAttachments by status.vpc.
const vpcIndex = "status.vpc"

// bindingNodeIndex indexes ServiceVIPBindings by spec.targetRef.name.
const bindingNodeIndex = "spec.targetRef.name"

// bindingNode is the bindingNodeIndex value of a ServiceVIPBinding.
func bindingNode(o client.Object) []string {
	if b, ok := o.(*bgpv1alpha1.ServiceVIPBinding); ok && b.Spec.TargetRef.Name != "" {
		return []string{b.Spec.TargetRef.Name}
	}
	return nil
}

// RegisterIndexes adds the field indexes Kube needs to a cache.
func RegisterIndexes(ctx context.Context, idx client.FieldIndexer) error {
	byUID := func(o client.Object) []string { return []string{string(o.GetUID())} }
	if err := idx.IndexField(ctx, &cloudv1alpha1.VPCAttachment{}, uidIndex, byUID); err != nil {
		return fmt.Errorf("sources: index VPCAttachment: %w", err)
	}
	if err := idx.IndexField(ctx, &galacticv1alpha1.EdgeAttachment{}, uidIndex, byUID); err != nil {
		return fmt.Errorf("sources: index EdgeAttachment: %w", err)
	}
	if err := idx.IndexField(ctx, &bgpv1alpha1.EgressShard{}, uidIndex, byUID); err != nil {
		return fmt.Errorf("sources: index EgressShard: %w", err)
	}
	byVPC := func(o client.Object) []string {
		if a, ok := o.(*cloudv1alpha1.VPCAttachment); ok && a.Status.VPC != "" {
			return []string{a.Status.VPC}
		}
		return nil
	}
	if err := idx.IndexField(ctx, &cloudv1alpha1.VPCAttachment{}, vpcIndex, byVPC); err != nil {
		return fmt.Errorf("sources: index VPCAttachment by VPC: %w", err)
	}
	if err := idx.IndexField(ctx, &bgpv1alpha1.ServiceVIPBinding{}, bindingNodeIndex, bindingNode); err != nil {
		return fmt.Errorf("sources: index ServiceVIPBinding by node: %w", err)
	}
	return nil
}

// Kube reads trusted sources through a controller-runtime cache whose
// indexes RegisterIndexes added.
type Kube struct {
	Reader client.Reader
	// Namespace is where BGPRouters and EgressShards live.
	Namespace string
	// GatewayNamespace is the gateway namespace, where galactic-router
	// writes the ServiceVIPBindings of the gateway's services.
	GatewayNamespace string
}

// Attachment implements Sources.
func (k Kube) Attachment(ctx context.Context, uid string) (Attachment, bool, error) {
	var vas cloudv1alpha1.VPCAttachmentList
	if err := k.Reader.List(ctx, &vas, client.MatchingFields{uidIndex: uid}); err != nil {
		return Attachment{}, false, fmt.Errorf("sources: list VPCAttachments: %w", err)
	}
	if len(vas.Items) == 1 {
		a := vas.Items[0]
		return Attachment{UID: uid, Kind: KindVPCAttachment, VPC: a.Status.VPC, Node: a.Status.Node,
			Admitted: a.DeletionTimestamp.IsZero(), Addresses: interfaceAddresses(a.Spec.Interface.Addresses),
			HostInterface: a.Status.HostInterface}, true, nil
	}
	var eas galacticv1alpha1.EdgeAttachmentList
	if err := k.Reader.List(ctx, &eas, client.MatchingFields{uidIndex: uid}); err != nil {
		return Attachment{}, false, fmt.Errorf("sources: list EdgeAttachments: %w", err)
	}
	if len(eas.Items) == 1 {
		a := eas.Items[0]
		admitted := a.DeletionTimestamp.IsZero() &&
			meta.IsStatusConditionTrue(a.Status.Conditions, galacticv1alpha1.EdgeAttachmentAdmitted)
		return Attachment{UID: uid, Kind: KindEdgeAttachment, VPC: a.Status.VPC, Node: a.Status.NodeName,
			Admitted: admitted}, true, nil
	}
	return Attachment{}, false, nil
}

// interfaceAddresses returns the addresses of CIDR-notation interface
// addresses, skipping any that do not parse. Admission validates them, so a
// skipped one is a value admission would refuse.
func interfaceAddresses(in []cloudv1alpha1.IPAddress) []netip.Addr {
	var out []netip.Addr
	for _, a := range in {
		if p, err := netip.ParsePrefix(string(a)); err == nil {
			out = append(out, p.Addr().Unmap())
		} else if addr, err := netip.ParseAddr(string(a)); err == nil {
			out = append(out, addr.Unmap())
		}
	}
	return out
}

// Locator implements Sources.
func (k Kube) Locator(ctx context.Context, node string) (netip.Prefix, error) {
	return nodelocator.Prefix(ctx, k.Reader, k.Namespace, node)
}

// EgressShard implements Sources.
func (k Kube) EgressShard(ctx context.Context, name string) (EgressShard, bool, error) {
	var es bgpv1alpha1.EgressShard
	err := k.Reader.Get(ctx, client.ObjectKey{Namespace: k.Namespace, Name: name}, &es)
	if apierrors.IsNotFound(err) {
		return EgressShard{}, false, nil
	}
	if err != nil {
		return EgressShard{}, false, fmt.Errorf("sources: get EgressShard %s: %w", name, err)
	}
	return egressShard(&es), true, nil
}

// EgressShardByUID implements Sources.
func (k Kube) EgressShardByUID(ctx context.Context, uid string) (EgressShard, bool, error) {
	var list bgpv1alpha1.EgressShardList
	if err := k.Reader.List(ctx, &list, client.InNamespace(k.Namespace),
		client.MatchingFields{uidIndex: uid}); err != nil {
		return EgressShard{}, false, fmt.Errorf("sources: list EgressShards: %w", err)
	}
	if len(list.Items) != 1 {
		return EgressShard{}, false, nil
	}
	return egressShard(&list.Items[0]), true, nil
}

// egressShard is the trusted record of es.
func egressShard(es *bgpv1alpha1.EgressShard) EgressShard {
	out := EgressShard{UID: string(es.UID), Name: es.Name, Node: es.Spec.TargetRef.Name, Draining: es.Spec.Drain}
	if sid, err := netip.ParseAddr(es.Status.ShardSID); err == nil && sid.Is6() && !sid.Is4In6() {
		out.SID = sid
	}
	out.Ready = es.DeletionTimestamp.IsZero() && out.SID.IsValid() &&
		meta.IsStatusConditionTrue(es.Status.Conditions, bgpv1alpha1.ConditionTypeProgrammed) &&
		meta.IsStatusConditionTrue(es.Status.Conditions, bgpv1alpha1.ConditionTypeReady)
	return out
}

// VPCAttachments implements Sources.
func (k Kube) VPCAttachments(ctx context.Context, vpc, node string) ([]Attachment, error) {
	if vpc == "" {
		return nil, nil
	}
	var vas cloudv1alpha1.VPCAttachmentList
	if err := k.Reader.List(ctx, &vas, client.MatchingFields{vpcIndex: vpc}); err != nil {
		return nil, fmt.Errorf("sources: list VPCAttachments of %s: %w", vpc, err)
	}
	var out []Attachment
	for i := range vas.Items {
		a := &vas.Items[i]
		if a.Status.VPC != vpc || a.Status.Node != node || !a.DeletionTimestamp.IsZero() {
			continue
		}
		out = append(out, Attachment{UID: string(a.UID), Kind: KindVPCAttachment, VPC: vpc, Node: node,
			Admitted: true, Addresses: interfaceAddresses(a.Spec.Interface.Addresses),
			HostInterface: a.Status.HostInterface})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out, nil
}

// BackendBindings implements Sources.
func (k Kube) BackendBindings(ctx context.Context, node string, slot uint16) ([]BackendBinding, error) {
	if node == "" || k.GatewayNamespace == "" {
		return nil, nil
	}
	var list bgpv1alpha1.ServiceVIPBindingList
	if err := k.Reader.List(ctx, &list, client.InNamespace(k.GatewayNamespace),
		client.MatchingFields{bindingNodeIndex: node}); err != nil {
		return nil, fmt.Errorf("sources: list ServiceVIPBindings of %s: %w", node, err)
	}
	var out []BackendBinding
	for i := range list.Items {
		b, ok := backendBinding(&list.Items[i])
		if ok && b.Node == node && srv6.BackendSlot(b.BackendAddress, b.BackendPort) == slot {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// backendBinding is the trusted record of b, and false for a binding whose
// backend address is not an IPv6 address, for which galactic-router writes
// no row.
func backendBinding(b *bgpv1alpha1.ServiceVIPBinding) (BackendBinding, bool) {
	addr, err := netip.ParseAddr(b.Spec.BackendAddress)
	if err != nil {
		return BackendBinding{}, false
	}
	addr = addr.Unmap()
	if !addr.Is6() {
		return BackendBinding{}, false
	}
	port := uint16(b.Spec.BackendPort) //nolint:gosec // kubebuilder-validated 1-65535
	if b.Spec.PortRange != nil {
		port = uint16(b.Spec.PortRange.Start) //nolint:gosec // kubebuilder-validated 1-65535
	}
	bound := meta.FindStatusCondition(b.Status.Conditions, bgpv1alpha1.ConditionTypeBound)
	return BackendBinding{Name: b.Name, Node: b.Spec.TargetRef.Name, VPCRef: b.Spec.VPCRef,
		BackendAddress: addr, BackendPort: port,
		Bound: b.DeletionTimestamp.IsZero() && (b.Spec.SourceRef == nil || b.Status.SourceAuthorityEnforced) &&
			bound != nil && bound.Status == metav1.ConditionTrue && bound.ObservedGeneration == b.Generation}, true
}

// vpcOf is the VPC scope a change to obj requeues: an attachment's VPC, and
// a ServiceVIPBinding's vpcRef, the scope of every backend destination it
// can resolve. It is "" for any other object.
func vpcOf(obj any) string {
	if t, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
		obj = t.Obj
	}
	switch o := obj.(type) {
	case *cloudv1alpha1.VPCAttachment:
		return o.Status.VPC
	case *galacticv1alpha1.EdgeAttachment:
		return o.Status.VPC
	case *bgpv1alpha1.ServiceVIPBinding:
		return o.Spec.VPCRef
	}
	return ""
}

// Watch calls changed with a VPC identifier whenever an attachment or a
// ServiceVIPBinding in that VPC changes, and with "" when a BGPRouter changes, which can move any
// destination between Local and Fabric. Duplicate events are expected;
// Worker's queue coalesces them.
func Watch(ctx context.Context, c cache.Cache, changed func(vpc string)) error {
	notify := func(obj any) {
		if v := vpcOf(obj); v != "" {
			changed(v)
		}
	}
	for _, obj := range []client.Object{&cloudv1alpha1.VPCAttachment{}, &galacticv1alpha1.EdgeAttachment{},
		&bgpv1alpha1.ServiceVIPBinding{}} {
		inf, err := c.GetInformer(ctx, obj)
		if err != nil {
			return fmt.Errorf("sources: informer: %w", err)
		}
		if _, err := inf.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
			AddFunc:    notify,
			UpdateFunc: func(oldObj, newObj any) { notify(oldObj); notify(newObj) },
			DeleteFunc: notify,
		}); err != nil {
			return fmt.Errorf("sources: handler: %w", err)
		}
	}
	// A BGPRouter can move any destination between Local and Fabric, and
	// an EgressShard any shard destination.
	all := func(any) { changed("") }
	for _, obj := range []client.Object{&bgpv1alpha1.BGPRouter{}, &bgpv1alpha1.EgressShard{}} {
		inf, err := c.GetInformer(ctx, obj)
		if err != nil {
			return fmt.Errorf("sources: informer: %w", err)
		}
		if _, err := inf.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
			AddFunc: all, UpdateFunc: func(_, n any) { all(n) }, DeleteFunc: all,
		}); err != nil {
			return fmt.Errorf("sources: handler: %w", err)
		}
	}
	return nil
}

// AddToScheme adds every type Kube reads to a scheme.
func AddToScheme(s *runtime.Scheme) error {
	for _, add := range []func(*runtime.Scheme) error{
		cloudv1alpha1.AddToScheme, galacticv1alpha1.AddToScheme, bgpv1alpha1.AddToScheme,
	} {
		if err := add(s); err != nil {
			return err
		}
	}
	return nil
}

// Static is an in-memory Sources for tests and for nodes without an API
// server.
type Static struct {
	mu          sync.Mutex
	attachments map[string]Attachment
	locators    map[string]netip.Prefix
	shards      map[string]EgressShard
	bindings    map[string]BackendBinding
}

// NewStatic returns an empty Static.
func NewStatic() *Static {
	return &Static{attachments: map[string]Attachment{}, locators: map[string]netip.Prefix{},
		shards: map[string]EgressShard{}, bindings: map[string]BackendBinding{}}
}

// SetBackendBinding adds or replaces a ServiceVIPBinding's record, by name.
func (s *Static) SetBackendBinding(b BackendBinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindings[b.Name] = b
}

// DeleteBackendBinding removes the ServiceVIPBinding named name.
func (s *Static) DeleteBackendBinding(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.bindings, name)
}

// BackendBindings implements Sources.
func (s *Static) BackendBindings(_ context.Context, node string, slot uint16) ([]BackendBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []BackendBinding
	for _, b := range s.bindings {
		if b.Node == node && srv6.BackendSlot(b.BackendAddress, b.BackendPort) == slot {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// SetEgressShard adds or replaces an EgressShard, by name.
func (s *Static) SetEgressShard(e EgressShard) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shards[e.Name] = e
}

// DeleteEgressShard removes the EgressShard named name.
func (s *Static) DeleteEgressShard(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.shards, name)
}

// EgressShard implements Sources.
func (s *Static) EgressShard(_ context.Context, name string) (EgressShard, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.shards[name]
	return e, ok, nil
}

// EgressShardByUID implements Sources.
func (s *Static) EgressShardByUID(_ context.Context, uid string) (EgressShard, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.shards {
		if e.UID == uid {
			return e, true, nil
		}
	}
	return EgressShard{}, false, nil
}

// VPCAttachments implements Sources.
func (s *Static) VPCAttachments(_ context.Context, vpc, node string) ([]Attachment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Attachment
	for _, a := range s.attachments {
		if a.Kind != KindEdgeAttachment && a.VPC == vpc && a.Node == node && a.Admitted {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out, nil
}

// SetAttachment adds or replaces an attachment.
func (s *Static) SetAttachment(a Attachment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attachments[a.UID] = a
}

// DeleteAttachment removes an attachment.
func (s *Static) DeleteAttachment(uid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.attachments, uid)
}

// SetLocator sets a node's locator.
func (s *Static) SetLocator(node string, p netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.locators[node] = p
}

// Attachment implements Sources.
func (s *Static) Attachment(_ context.Context, uid string) (Attachment, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.attachments[uid]
	return a, ok, nil
}

// Locator implements Sources.
func (s *Static) Locator(_ context.Context, node string) (netip.Prefix, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.locators[node], nil
}
