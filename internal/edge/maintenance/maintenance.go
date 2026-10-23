// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package maintenance keeps a node's garbage collection off the shared state
// Galactic Edge attachments use: a VPC's canonical host VRF, its
// BGPVRFInstance and its uSID datapath rows.
//
// An edge attachment joins its VPC's canonical host VRF, which ordinary
// workloads create, so the state outlives the last workload while an edge
// attachment still uses it. A VPC is in use while either holds:
//
//   - the API has an EdgeAttachment on the node for the VPC that its node has
//     not reported Released, which covers an attachment still being prepared;
//   - the host has a link galactic-edge stamped for the VPC, which covers an
//     attachment whose object is gone or unreadable but whose host state is
//     not yet released.
//
// Reclaim decides again under the VPC's write fence (internal/edge/ownership),
// which galactic-edge holds while it programs, so a reclaim decided from an
// earlier view cannot remove state an attachment programmed since.
package maintenance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/edge/ownership"
)

// ErrInUse is returned by Reclaim when an edge attachment uses the VPC.
var ErrInUse = errors.New("maintenance: an edge attachment uses the VPC on this node")

// listTimeout bounds the API read Reclaim makes with the scope's lock held.
const listTimeout = 10 * time.Second

// Guard reports and protects the VPCs edge attachments use on one node.
type Guard struct {
	// Reader lists EdgeAttachments. It must read the API server, not an
	// informer cache, so an attachment admitted just before a reclaim is
	// seen.
	Reader client.Reader
	// NodeName is this node.
	NodeName string
	// Ownership is the node's write fence, shared with galactic-edge.
	Ownership *ownership.Authority
	// HostLinks lists the links galactic-edge stamped on the host.
	HostLinks func() ([]hostattach.ObservedAttachment, error)
}

// NewGuard returns a guard over the node's shared write-fence directory,
// which must already exist, reading host links from the caller's network
// namespace, which must be the host's.
func NewGuard(reader client.Reader, nodeName, ownershipDir string) (*Guard, error) {
	auth, err := ownership.Open(ownershipDir)
	if err != nil {
		return nil, fmt.Errorf("edge write fence: %w", err)
	}
	return &Guard{
		Reader: reader, NodeName: nodeName, Ownership: auth,
		HostLinks: hostattach.ListHost,
	}, nil
}

// Unavailable stands in for a Guard that could not be built. It knows of no
// VPC, so garbage collection reclaims nothing that edge attachments could use
// and reports Err on every pass.
type Unavailable struct{ Err error }

// VPCs returns u.Err.
func (u Unavailable) VPCs(context.Context) (map[string]struct{}, error) { return nil, u.Err }

// Reclaim returns u.Err and runs nothing.
func (u Unavailable) Reclaim(context.Context, string, func() error) error { return u.Err }

// VPCs returns every VPC an edge attachment uses on the node, as base62
// identifiers without zero padding. An error means the answer is unknown, and
// callers must reclaim nothing.
func (g *Guard) VPCs(ctx context.Context) (map[string]struct{}, error) {
	vpcs := map[string]struct{}{}
	var list galacticv1alpha1.EdgeAttachmentList
	switch err := g.Reader.List(ctx, &list); {
	case meta.IsNoMatchError(err):
		// The EdgeAttachment CRD is not installed, so no attachment exists.
	case err != nil:
		return nil, fmt.Errorf("list EdgeAttachments: %w", err)
	}
	for _, att := range list.Items {
		s := att.Status
		if s.NodeName != g.NodeName || s.VPC == "" ||
			meta.IsStatusConditionTrue(s.Conditions, galacticv1alpha1.EdgeAttachmentReleased) {
			continue
		}
		vpcs[canonical(s.VPC)] = struct{}{}
	}
	links, err := g.HostLinks()
	if err != nil {
		return nil, fmt.Errorf("list edge attachment links: %w", err)
	}
	for _, l := range links {
		if vpc, _, ok := hostattach.ParseLinkID(l.ID); ok {
			vpcs[canonical(vpc)] = struct{}{}
		}
	}
	return vpcs, nil
}

// canonical drops the zero padding of a VRF interface name from a base62 VPC
// identifier, the form garbage collection reads VPCs in, exactly as the VPC's
// write-fence scope does.
func canonical(vpc string) string {
	return strings.TrimPrefix(ownership.VPCScope(vpc), "vpc-")
}

// Reclaim runs reclaim, which removes vpc's shared state, with vpc's write
// fence held, after confirming under the fence that no edge attachment uses
// vpc. It returns an error wrapping ErrInUse, and runs nothing, when one does,
// and runs nothing while ownership of vpc moves between galactic-edge
// processes. The write makes every ticket galactic-edge holds for vpc stale,
// so a change it prepared before the reclaim is refused and prepared again.
func (g *Guard) Reclaim(ctx context.Context, vpc string, reclaim func() error) error {
	return g.Ownership.Exclusive(ownership.VPCScope(vpc), func() error {
		ctx, cancel := context.WithTimeout(ctx, listTimeout)
		defer cancel()
		vpcs, err := g.VPCs(ctx)
		if err != nil {
			return err
		}
		if _, inUse := vpcs[canonical(vpc)]; inUse {
			return fmt.Errorf("%w: VPC %s", ErrInUse, vpc)
		}
		return nil
	}, reclaim)
}
