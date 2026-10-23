// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package route

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/admission"
)

// Reasons a claim is refused or an accepted holder revoked, beyond
// admission's own.
const (
	ReasonAccepted          = "Accepted"
	ReasonWaiting           = "WaitingForFencing"
	ReasonAttachmentMissing = "AttachmentNotFound"
	ReasonAttachmentNotLive = "AttachmentNotLive"
	ReasonInstanceMissing   = "InstanceNotFound"
	ReasonLeaseNotHeld      = "LeaseNotHeld"
	ReasonPrefixConflict    = "PrefixConflict"
	ReasonInvalidPrefix     = "InvalidPrefix"
	ReasonIndexRebuilt      = "IndexRebuilt"
	ReasonRevoked           = "Revoked"
)

// PrefixReachability is the capability a route needs from its service and
// provider.
const PrefixReachability = "PrefixReachability"

// Refusal is why a holder may not forward a route's prefix.
type Refusal struct {
	Reason, Message string
}

func refuse(reason, format string, args ...any) *Refusal {
	return &Refusal{Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// Holder is the claim being checked: the attachment and the instance lease
// epoch a route names.
type Holder struct {
	Attachment    string
	PodUID        string
	Instance      string
	InstanceEpoch int64
	// AttachmentUID, when set, must be the attachment's UID: an accepted
	// holder is the attachment object it was accepted for, never one
	// recreated under its name.
	AttachmentUID string
	// InstanceIncarnation, when set, must be the lease's incarnation.
	InstanceIncarnation string
}

// HolderOfClaim is the holder a route's claim names.
func HolderOfClaim(c *galacticv1alpha1.EdgeRouteClaim) Holder {
	return Holder{Attachment: c.Attachment, PodUID: c.HolderPodUID, Instance: c.HolderInstance,
		InstanceEpoch: c.InstanceEpoch}
}

// HolderOfAccepted is the holder a route's status accepted.
func HolderOfAccepted(a *galacticv1alpha1.EdgeRouteHolder) Holder {
	return Holder{Attachment: a.Attachment, Instance: a.Instance, InstanceEpoch: a.InstanceEpoch,
		AttachmentUID: a.AttachmentUID, InstanceIncarnation: a.InstanceIncarnation}
}

// Authorized is what a successful Check read.
type Authorized struct {
	Attachment *galacticv1alpha1.EdgeAttachment
	Service    *galacticv1alpha1.EdgeService
	Instance   *galacticv1alpha1.EdgeInstance
	Prefix     netip.Prefix
	Address    netip.Addr
	// NotAfter is the wall-clock instant the grant stops authorizing, its
	// validUntil less the cell's maximum skew, or zero for none.
	NotAfter time.Time
}

// Check decides from reader whether h may forward rt's prefix now: the
// attachment is the claiming pod's, admitted, allocated, ready and neither
// draining nor deleted; its service grants the route's VPC, the prefix and
// PrefixReachability to the route's provider, which is approved and
// implements it, and has not expired; and the instance is the pod's, on the
// attachment's node, holding its lease at h's epoch. reader must read from
// the API server, so a revocation recorded before the call is seen.
func Check(ctx context.Context, reader client.Reader, rt *galacticv1alpha1.EdgeRoute, h Holder, now time.Time,
	maxSkew time.Duration) (*Authorized, *Refusal, error) {
	return check(ctx, reader, rt, h, now, maxSkew, true)
}

// CheckAuthority is Check without the lease: whether the holder is still
// authorized, whatever its instance's lease says. An expired lease stops
// forwarding at the node and is renewed or reacquired by the provider; it
// does not revoke an accepted route.
func CheckAuthority(ctx context.Context, reader client.Reader, rt *galacticv1alpha1.EdgeRoute, h Holder, now time.Time,
	maxSkew time.Duration) (*Authorized, *Refusal, error) {
	return check(ctx, reader, rt, h, now, maxSkew, false)
}

func check(ctx context.Context, reader client.Reader, rt *galacticv1alpha1.EdgeRoute, h Holder, now time.Time,
	maxSkew time.Duration, lease bool) (*Authorized, *Refusal, error) {
	prefix, err := netip.ParsePrefix(rt.Spec.Prefix)
	if err != nil || prefix != prefix.Masked() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return nil, refuse(ReasonInvalidPrefix, "prefix %q is not a masked IPv6 prefix", rt.Spec.Prefix), nil
	}
	att, addr, ref, err := checkAttachment(ctx, reader, rt, h, prefix)
	if ref != nil || err != nil {
		return nil, ref, err
	}
	svc, notAfter, ref, err := checkGrant(ctx, reader, rt, att, prefix, now, maxSkew)
	if ref != nil || err != nil {
		return nil, ref, err
	}
	if ref, err := checkProvider(ctx, reader, rt); ref != nil || err != nil {
		return nil, ref, err
	}
	inst, ref, err := checkInstance(ctx, reader, rt, h, att, lease)
	if ref != nil || err != nil {
		return nil, ref, err
	}
	return &Authorized{Attachment: att, Service: svc, Instance: inst, Prefix: prefix, Address: addr,
		NotAfter: notAfter}, nil, nil
}

// checkAttachment reads the holder's attachment: the claiming pod's, of the
// route's provider, admitted, allocated, ready and live, with an address
// outside the prefix.
func checkAttachment(ctx context.Context, reader client.Reader, rt *galacticv1alpha1.EdgeRoute, h Holder,
	prefix netip.Prefix) (*galacticv1alpha1.EdgeAttachment, netip.Addr, *Refusal, error) {
	var att galacticv1alpha1.EdgeAttachment
	switch err := reader.Get(ctx, client.ObjectKey{Namespace: rt.Namespace, Name: h.Attachment}, &att); {
	case apierrors.IsNotFound(err):
		return nil, netip.Addr{}, refuse(ReasonAttachmentMissing, "EdgeAttachment %s does not exist", h.Attachment), nil
	case err != nil:
		return nil, netip.Addr{}, nil, err
	case h.AttachmentUID != "" && string(att.UID) != h.AttachmentUID:
		return nil, netip.Addr{}, refuse(ReasonAttachmentMissing, "EdgeAttachment %s was replaced", h.Attachment), nil
	case h.PodUID != "" && att.Spec.PodUID != h.PodUID:
		return nil, netip.Addr{}, refuse(string(admission.IdentityMismatch), "EdgeAttachment %s is pod %s's, not %s",
			att.Name, att.Spec.PodUID, h.PodUID), nil
	case att.Spec.InstanceRef.Name != h.Instance:
		return nil, netip.Addr{}, refuse(string(admission.IdentityMismatch),
			"EdgeAttachment %s belongs to instance %s, not %s", att.Name, att.Spec.InstanceRef.Name, h.Instance), nil
	case att.Spec.ProviderRef != rt.Spec.ProviderRef:
		return nil, netip.Addr{}, refuse(string(admission.IdentityMismatch), "EdgeAttachment %s runs provider %q, not %q",
			att.Name, att.Spec.ProviderRef.Name, rt.Spec.ProviderRef.Name), nil
	case !live(&att):
		return nil, netip.Addr{}, refuse(ReasonAttachmentNotLive,
			"EdgeAttachment %s is not admitted, allocated and ready, or is draining", att.Name), nil
	}
	addr, err := netip.ParseAddr(att.Status.Address)
	if err != nil {
		return nil, netip.Addr{}, refuse(ReasonAttachmentNotLive, "EdgeAttachment %s has no address", att.Name), nil
	}
	if prefix.Contains(addr) {
		return nil, netip.Addr{}, refuse(ReasonInvalidPrefix, "prefix %s contains the attachment's own address",
			prefix), nil
	}
	return &att, addr, nil, nil
}

// live reports whether the attachment is admitted, allocated, ready, placed
// and neither draining nor deleted.
func live(att *galacticv1alpha1.EdgeAttachment) bool {
	c := att.Status.Conditions
	return att.DeletionTimestamp.IsZero() &&
		!meta.IsStatusConditionTrue(c, galacticv1alpha1.EdgeAttachmentDraining) &&
		meta.IsStatusConditionTrue(c, galacticv1alpha1.EdgeAttachmentAdmitted) &&
		meta.IsStatusConditionTrue(c, galacticv1alpha1.EdgeAttachmentAllocated) &&
		meta.IsStatusConditionTrue(c, galacticv1alpha1.EdgeAttachmentReady) &&
		att.Status.NodeName != "" && att.Status.VPC != ""
}

// checkGrant reads the attachment's service: still the one admitted, granting
// the route's VPC, provider, PrefixReachability and the prefix, and not
// expired. It returns the grant's ceiling, validUntil less maxSkew, or zero.
func checkGrant(ctx context.Context, reader client.Reader, rt *galacticv1alpha1.EdgeRoute,
	att *galacticv1alpha1.EdgeAttachment, prefix netip.Prefix, now time.Time, maxSkew time.Duration,
) (*galacticv1alpha1.EdgeService, time.Time, *Refusal, error) {
	ref := att.Spec.ServiceRef
	var svc galacticv1alpha1.EdgeService
	switch err := reader.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &svc); {
	case apierrors.IsNotFound(err):
		return nil, time.Time{}, refuse(string(admission.GrantRevoked), "EdgeService %s/%s no longer exists",
			ref.Namespace, ref.Name), nil
	case err != nil:
		return nil, time.Time{}, nil, err
	case string(svc.UID) != ref.UID || !svc.DeletionTimestamp.IsZero():
		return nil, time.Time{}, refuse(string(admission.GrantRevoked),
			"EdgeService %s/%s was replaced or is being deleted", ref.Namespace, ref.Name), nil
	case svc.Spec.VPCRef.UID != rt.Spec.VPCUID:
		return nil, time.Time{}, refuse(string(admission.VPCNotGranted), "EdgeService %s/%s grants VPC %s, not %s",
			ref.Namespace, ref.Name, svc.Spec.VPCRef.UID, rt.Spec.VPCUID), nil
	case svc.Spec.ProviderRef != rt.Spec.ProviderRef:
		return nil, time.Time{}, refuse(string(admission.ProviderNotGranted),
			"EdgeService %s/%s grants provider %q, not %q", ref.Namespace, ref.Name, svc.Spec.ProviderRef.Name,
			rt.Spec.ProviderRef.Name), nil
	case !slices.Contains(svc.Spec.Capabilities, PrefixReachability):
		return nil, time.Time{}, refuse(string(admission.CapabilityNotGranted), "EdgeService %s/%s does not grant %s",
			ref.Namespace, ref.Name, PrefixReachability), nil
	}
	grant, err := admission.GrantFromAPI(&svc)
	if err != nil {
		return nil, time.Time{}, refuse(string(admission.InvalidRequest), "%v", err), nil
	}
	if !slices.ContainsFunc(grant.Prefixes, func(g netip.Prefix) bool {
		return g.Addr().BitLen() == prefix.Addr().BitLen() && g.Bits() <= prefix.Bits() && g.Contains(prefix.Addr())
	}) {
		return nil, time.Time{}, refuse(string(admission.PrefixNotGranted), "EdgeService %s/%s does not grant %s",
			ref.Namespace, ref.Name, prefix), nil
	}
	var notAfter time.Time
	if !grant.ValidUntil.IsZero() {
		notAfter = grant.ValidUntil.Add(-maxSkew)
		if !now.Before(notAfter) {
			return nil, time.Time{}, refuse(string(admission.GrantExpired), "EdgeService %s/%s expired",
				ref.Namespace, ref.Name), nil
		}
	}
	return &svc, notAfter, nil, nil
}

// checkProvider reads the route's provider: approved and implementing
// PrefixReachability.
func checkProvider(ctx context.Context, reader client.Reader, rt *galacticv1alpha1.EdgeRoute) (*Refusal, error) {
	var provider galacticv1alpha1.EdgeProvider
	switch err := reader.Get(ctx, client.ObjectKey{Name: rt.Spec.ProviderRef.Name}, &provider); {
	case apierrors.IsNotFound(err):
		return refuse(string(admission.UnknownProvider), "EdgeProvider %s does not exist", rt.Spec.ProviderRef.Name), nil
	case err != nil:
		return nil, err
	case !provider.Status.Approved || !provider.DeletionTimestamp.IsZero():
		return refuse(string(admission.ProviderNotApproved), "EdgeProvider %s is not approved", provider.Name), nil
	case !slices.ContainsFunc(provider.Spec.Capabilities, func(c galacticv1alpha1.EdgeCapability) bool {
		return c.Name == PrefixReachability
	}):
		return refuse(string(admission.UnsupportedCapability), "EdgeProvider %s does not implement %s",
			provider.Name, PrefixReachability), nil
	}
	return nil, nil
}

// checkInstance reads the holder's instance: the attachment's pod on the
// attachment's node and, when lease is set, holding its lease at the
// holder's incarnation and epoch.
func checkInstance(ctx context.Context, reader client.Reader, rt *galacticv1alpha1.EdgeRoute, h Holder,
	att *galacticv1alpha1.EdgeAttachment, lease bool) (*galacticv1alpha1.EdgeInstance, *Refusal, error) {
	var inst galacticv1alpha1.EdgeInstance
	switch err := reader.Get(ctx, client.ObjectKey{Namespace: rt.Namespace, Name: h.Instance}, &inst); {
	case apierrors.IsNotFound(err):
		return nil, refuse(ReasonInstanceMissing, "EdgeInstance %s does not exist", h.Instance), nil
	case err != nil:
		return nil, nil, err
	case inst.Spec.PodUID != att.Spec.PodUID || inst.Spec.NodeName != att.Status.NodeName:
		return nil, refuse(string(admission.IdentityMismatch), "EdgeInstance %s is not pod %s on node %s",
			inst.Name, att.Spec.PodUID, att.Status.NodeName), nil
	}
	l := inst.Status.Lease
	switch {
	case !lease:
	case l == nil || l.Holder == "" || l.Released || l.Epoch != h.InstanceEpoch:
		return nil, refuse(ReasonLeaseNotHeld, "EdgeInstance %s does not hold its lease at epoch %d",
			inst.Name, h.InstanceEpoch), nil
	case h.InstanceIncarnation != "" && l.Incarnation != h.InstanceIncarnation:
		return nil, refuse(ReasonLeaseNotHeld, "EdgeInstance %s's lease was recreated", inst.Name), nil
	}
	return &inst, nil, nil
}
