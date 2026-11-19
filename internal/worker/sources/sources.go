// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sources reads the facts Worker takes only from trusted sources,
// never from a request (docs/worker/contract.md, "Trusted sources"): an
// attachment's VPC, node and admission, and a node's physical locator.
package sources

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/nodelocator"
)

// Attachment kinds.
const (
	KindVPCAttachment  = "VPCAttachment"
	KindEdgeAttachment = "EdgeAttachment"
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
}

// Sources answers Worker's trusted-source lookups.
type Sources interface {
	// Attachment returns the attachment with uid, and false when none
	// exists.
	Attachment(ctx context.Context, uid string) (Attachment, bool, error)
	// Locator returns node's SRv6 locator, or the zero prefix while it has
	// none.
	Locator(ctx context.Context, node string) (netip.Prefix, error)
}

// uidIndex indexes attachments by metadata.uid.
const uidIndex = "metadata.uid"

// RegisterIndexes adds the field indexes Kube needs to a cache.
func RegisterIndexes(ctx context.Context, idx client.FieldIndexer) error {
	byUID := func(o client.Object) []string { return []string{string(o.GetUID())} }
	if err := idx.IndexField(ctx, &cloudv1alpha1.VPCAttachment{}, uidIndex, byUID); err != nil {
		return fmt.Errorf("sources: index VPCAttachment: %w", err)
	}
	if err := idx.IndexField(ctx, &galacticv1alpha1.EdgeAttachment{}, uidIndex, byUID); err != nil {
		return fmt.Errorf("sources: index EdgeAttachment: %w", err)
	}
	return nil
}

// Kube reads trusted sources through a controller-runtime cache whose
// indexes RegisterIndexes added.
type Kube struct {
	Reader client.Reader
	// Namespace is where BGPRouters live.
	Namespace string
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
			Admitted: a.DeletionTimestamp.IsZero(), Addresses: interfaceAddresses(a.Spec.Interface.Addresses)}, true, nil
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

// Watch calls changed with a VPC identifier whenever an attachment in that
// VPC changes, and with "" when a BGPRouter changes, which can move any
// destination between Local and Fabric. Duplicate events are expected;
// Worker's queue coalesces them.
func Watch(ctx context.Context, c cache.Cache, changed func(vpc string)) error {
	vpcOf := func(obj any) string {
		if t, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
			obj = t.Obj
		}
		switch o := obj.(type) {
		case *cloudv1alpha1.VPCAttachment:
			return o.Status.VPC
		case *galacticv1alpha1.EdgeAttachment:
			return o.Status.VPC
		}
		return ""
	}
	notify := func(obj any) {
		if v := vpcOf(obj); v != "" {
			changed(v)
		}
	}
	for _, obj := range []client.Object{&cloudv1alpha1.VPCAttachment{}, &galacticv1alpha1.EdgeAttachment{}} {
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
	inf, err := c.GetInformer(ctx, &bgpv1alpha1.BGPRouter{})
	if err != nil {
		return fmt.Errorf("sources: informer: %w", err)
	}
	all := func(any) { changed("") }
	if _, err := inf.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc: all, UpdateFunc: func(_, n any) { all(n) }, DeleteFunc: all,
	}); err != nil {
		return fmt.Errorf("sources: handler: %w", err)
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
}

// NewStatic returns an empty Static.
func NewStatic() *Static {
	return &Static{attachments: map[string]Attachment{}, locators: map[string]netip.Prefix{}}
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
