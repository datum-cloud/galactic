// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cache wraps a controller-runtime cache.Cache over the VPC
// and VPCAttachment resources. The reconciler queries it on three hot
// paths:
//
//  1. Originate: find the local VPCAttachment for a (vpcHex, attachHex)
//     from CNI Register and read its serviceSID/RT/RD from status.
//  2. Receive: given an inbound BGP UPDATE with route-target list, find
//     all local VPCAttachments matching at least one of those RTs.
//  3. Status changes: subscribe to add/update/delete events that drive
//     OnAttachmentStatusChange.
//
// VPCs and VPCAttachments are joined by Spec.VPC.{Name,Namespace}; the
// reconciler always sees the joined view and does not have to do its
// own cross-resource resolution.
package cache

import (
	"context"
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"

	galacticv1alpha "go.datum.net/galactic/pkg/apis/v1alpha"
)

// AttachmentInfo is the subset of (VPC, VPCAttachment) the reconciler
// uses. Returned by value so the reconciler gets a stable snapshot.
type AttachmentInfo struct {
	VPCHex             string
	AttachHex          string
	ServiceSID         string
	RouteTarget        string
	RouteDistinguisher string
	PodPrefixes        []string // CIDR strings, from Spec.Interface.Addresses
	Ready              bool     // true iff all three status fields are non-empty
	Namespace          string
	Name               string
}

// EventType is the kind of change observed.
type EventType int

const (
	EventAdd EventType = iota
	EventUpdate
	EventDelete
)

// Event is delivered on the channel returned by Events. Current holds
// the post-change snapshot; for deletes it carries the last known state
// from the controller-runtime tombstone.
type Event struct {
	Type    EventType
	Current AttachmentInfo
}

type attachKey struct{ vpcHex, attachHex string }
type vpcRef struct{ namespace, name string }

// VPCAttachments wraps the joined informers.
type VPCAttachments struct {
	cache ctrlcache.Cache

	syncedMu sync.RWMutex
	synced   bool

	mu sync.RWMutex
	// vpcByRef maps Spec.VPC reference -> VPC.Status.Identifier. Used
	// by attachment-event handlers to resolve VPCHex.
	vpcByRef map[vpcRef]string
	// attsByVPCRef maps a VPC reference to the set of attachments
	// pointing at it; needed when a VPC's status flips so we can
	// re-emit attachment events for everything underneath.
	attsByVPCRef map[vpcRef]map[attachKey]*galacticv1alpha.VPCAttachment
	// byKey is the joined snapshot keyed by (vpcHex, attachHex).
	byKey map[attachKey]AttachmentInfo
	// byRT indexes byKey by the joined attachment's RouteTarget.
	byRT map[string]map[attachKey]struct{}

	eventCh chan Event
}

// New constructs a VPCAttachments cache backed by the given REST config.
// Call Start before any other method.
func New(cfg *rest.Config) (*VPCAttachments, error) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(galacticv1alpha.AddToScheme(scheme))

	c, err := ctrlcache.New(cfg, ctrlcache.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("controller-runtime cache: %w", err)
	}

	return &VPCAttachments{
		cache:        c,
		vpcByRef:     map[vpcRef]string{},
		attsByVPCRef: map[vpcRef]map[attachKey]*galacticv1alpha.VPCAttachment{},
		byKey:        map[attachKey]AttachmentInfo{},
		byRT:         map[string]map[attachKey]struct{}{},
		eventCh:      make(chan Event, 256),
	}, nil
}

// Start launches both informers and waits for initial sync. Returns
// when the cache is ready to serve queries; the cache continues running
// until ctx is canceled.
func (v *VPCAttachments) Start(ctx context.Context) error {
	vpcInformer, err := v.cache.GetInformer(ctx, &galacticv1alpha.VPC{})
	if err != nil {
		return fmt.Errorf("get VPC informer: %w", err)
	}
	if _, err := vpcInformer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { v.onVPC(obj, false) },
		UpdateFunc: func(_, obj interface{}) { v.onVPC(obj, false) },
		DeleteFunc: func(obj interface{}) { v.onVPC(obj, true) },
	}); err != nil {
		return fmt.Errorf("add VPC handler: %w", err)
	}

	attInformer, err := v.cache.GetInformer(ctx, &galacticv1alpha.VPCAttachment{})
	if err != nil {
		return fmt.Errorf("get VPCAttachment informer: %w", err)
	}
	if _, err := attInformer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { v.onAttachment(obj, EventAdd) },
		UpdateFunc: func(_, obj interface{}) { v.onAttachment(obj, EventUpdate) },
		DeleteFunc: func(obj interface{}) { v.onAttachment(obj, EventDelete) },
	}); err != nil {
		return fmt.Errorf("add VPCAttachment handler: %w", err)
	}

	go func() {
		if err := v.cache.Start(ctx); err != nil && ctx.Err() == nil {
			panic(fmt.Errorf("cache.Start: %w", err))
		}
	}()

	if !v.cache.WaitForCacheSync(ctx) {
		return fmt.Errorf("cache failed to sync")
	}
	v.syncedMu.Lock()
	v.synced = true
	v.syncedMu.Unlock()
	return nil
}

// Synced reports whether the informer cache has completed its initial
// list/watch sync. Used by /healthz to gate readiness.
func (v *VPCAttachments) Synced() bool {
	v.syncedMu.RLock()
	defer v.syncedMu.RUnlock()
	return v.synced
}

// Events returns the channel of joined-attachment changes.
func (v *VPCAttachments) Events() <-chan Event { return v.eventCh }

// Lookup returns the cached attachment info for (vpcHex, attachHex).
// ok=false if no such attachment is known to be ready.
func (v *VPCAttachments) Lookup(vpcHex, attachHex string) (AttachmentInfo, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	info, ok := v.byKey[attachKey{vpcHex, attachHex}]
	return info, ok
}

// LookupByName resolves the attachment info from a (namespace, name)
// pair. The CNI Register call delivers (vpcHex, attachHex) directly so
// this is rarely used at runtime; tests use it.
func (v *VPCAttachments) LookupByName(namespace, name string) (AttachmentInfo, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, info := range v.byKey {
		if info.Namespace == namespace && info.Name == name {
			return info, true
		}
	}
	return AttachmentInfo{}, false
}

// FindByRT returns every cached attachment whose RouteTarget matches
// the given RT string. Used by OnReceivedRoute to identify which local
// VRFs should receive the kernel egress route.
func (v *VPCAttachments) FindByRT(rt string) []AttachmentInfo {
	v.mu.RLock()
	defer v.mu.RUnlock()
	keys, ok := v.byRT[rt]
	if !ok {
		return nil
	}
	out := make([]AttachmentInfo, 0, len(keys))
	for k := range keys {
		if info, ok := v.byKey[k]; ok {
			out = append(out, info)
		}
	}
	return out
}

func (v *VPCAttachments) onVPC(obj interface{}, isDelete bool) {
	if t, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
		obj = t.Obj
	}
	vpc, ok := obj.(*galacticv1alpha.VPC)
	if !ok {
		return
	}
	ref := vpcRef{namespace: vpc.Namespace, name: vpc.Name}

	v.mu.Lock()
	previousHex := v.vpcByRef[ref]
	newHex := vpc.Status.Identifier
	if isDelete {
		delete(v.vpcByRef, ref)
		newHex = ""
	} else {
		v.vpcByRef[ref] = newHex
	}
	// Re-join every attachment that points at this VPC. Status changes
	// on the parent VPC are not directly observable from the
	// attachment side; this fan-out is how they reach the reconciler.
	dependents := v.attsByVPCRef[ref]
	v.mu.Unlock()

	if previousHex != newHex {
		for _, att := range dependents {
			// EventUpdate so the reconciler can re-evaluate readiness
			// and trigger originate/teardown as appropriate.
			v.handleAttachmentChange(att, EventUpdate)
		}
	}
}

func (v *VPCAttachments) onAttachment(obj interface{}, kind EventType) {
	if t, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
		obj = t.Obj
	}
	att, ok := obj.(*galacticv1alpha.VPCAttachment)
	if !ok {
		return
	}
	v.handleAttachmentChange(att, kind)
}

func (v *VPCAttachments) handleAttachmentChange(att *galacticv1alpha.VPCAttachment, kind EventType) {
	ref := vpcRef{namespace: att.Spec.VPC.Namespace, name: att.Spec.VPC.Name}

	v.mu.Lock()

	// Track attachment-by-VPC-ref so VPC status changes can fan out
	// to dependents.
	if kind == EventDelete {
		if set, ok := v.attsByVPCRef[ref]; ok {
			delete(set, attachKey{vpcHex: v.vpcByRef[ref], attachHex: att.Status.Identifier})
			if len(set) == 0 {
				delete(v.attsByVPCRef, ref)
			}
		}
	} else {
		set, ok := v.attsByVPCRef[ref]
		if !ok {
			set = map[attachKey]*galacticv1alpha.VPCAttachment{}
			v.attsByVPCRef[ref] = set
		}
		set[attachKey{vpcHex: v.vpcByRef[ref], attachHex: att.Status.Identifier}] = att
	}

	vpcHex := v.vpcByRef[ref]
	info := infoFromJoined(vpcHex, att)
	key := attachKey{info.VPCHex, info.AttachHex}

	if kind == EventDelete {
		if prev, found := v.byKey[key]; found {
			if set, ok := v.byRT[prev.RouteTarget]; ok {
				delete(set, key)
				if len(set) == 0 {
					delete(v.byRT, prev.RouteTarget)
				}
			}
			delete(v.byKey, key)
			info = prev // emit the last-known state with the delete event
		}
	} else {
		// Re-wire byRT if RT changed (rare).
		if prev, found := v.byKey[key]; found && prev.RouteTarget != info.RouteTarget {
			if set, ok := v.byRT[prev.RouteTarget]; ok {
				delete(set, key)
				if len(set) == 0 {
					delete(v.byRT, prev.RouteTarget)
				}
			}
		}
		// Only index ready attachments — partial-status entries
		// would mislead FindByRT into matching attachments that
		// can't yet be programmed.
		if info.Ready {
			v.byKey[key] = info
			set, ok := v.byRT[info.RouteTarget]
			if !ok {
				set = map[attachKey]struct{}{}
				v.byRT[info.RouteTarget] = set
			}
			set[key] = struct{}{}
		} else {
			// Drop a stale ready entry if the attachment regressed to
			// not-ready.
			if prev, found := v.byKey[key]; found {
				if set, ok := v.byRT[prev.RouteTarget]; ok {
					delete(set, key)
					if len(set) == 0 {
						delete(v.byRT, prev.RouteTarget)
					}
				}
				delete(v.byKey, key)
			}
		}
	}
	v.mu.Unlock()

	select {
	case v.eventCh <- Event{Type: kind, Current: info}:
	default:
	}
}

func infoFromJoined(vpcHex string, att *galacticv1alpha.VPCAttachment) AttachmentInfo {
	info := AttachmentInfo{
		VPCHex:             vpcHex,
		AttachHex:          att.Status.Identifier,
		ServiceSID:         att.Status.ServiceSID,
		RouteTarget:        att.Status.RouteTarget,
		RouteDistinguisher: att.Status.RouteDistinguisher,
		PodPrefixes:        append([]string(nil), att.Spec.Interface.Addresses...),
		Namespace:          att.Namespace,
		Name:               att.Name,
	}
	info.Ready = att.Status.Ready &&
		info.VPCHex != "" &&
		info.AttachHex != "" &&
		info.ServiceSID != "" &&
		info.RouteTarget != "" &&
		info.RouteDistinguisher != ""
	return info
}
