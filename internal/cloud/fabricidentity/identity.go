/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Package fabricidentity allocates the identity the fabric knows a network by.
//
// The platform's address service allocates prefixes, not integers. Rather than
// build a second allocator with the same uniqueness and concurrency problems
// already solved there, an identity is allocated as a block from a pool that is
// never routed, and the integer is the block's index within that pool. A /32
// root handing out /64s yields exactly 2^32 allocations whose distinguishing
// bits are exactly the 32 the fabric uses.
//
// That buys uniqueness, exhaustion accounting, quota and an audit trail, and
// costs address space that is never routed and never reachable.
package fabricidentity

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"

	ipamv1alpha1 "go.miloapis.com/ipam/pkg/apis/ipam/v1alpha1"
	"go.miloapis.com/ipam/pkg/ipamerrors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// BlockBits is the size of the block an identity is read out of. The pool
	// roots a /32 and hands out /64s, so the bits between them are the block's
	// index within the pool, and there are exactly 2^32 of them.
	BlockBits = 64

	// RootBits is where the pool's own prefix stops and the index begins.
	// Reading the index from a fixed offset rather than from the pool's CIDR
	// means the identity does not depend on an object this would otherwise have
	// to read on every allocation. A pool rooted longer than a /32 leaves the
	// leading bits of every index at zero, which is still unique within the one
	// pool the platform allocates from.
	RootBits = 32
)

// Request names one network's claim on the identifier space.
type Request struct {
	// ClassName is the IPClass that hands out identities.
	ClassName string

	// Namespace is the namespace in the platform's own tenancy the claim is
	// written to.
	Namespace string

	// NetworkNamespace and NetworkName identify the network the identity is
	// for. The claim is named from the pair, so an identity is a permanent
	// property of that name in that namespace.
	//
	// A network deleted and recreated under the same name in the same namespace
	// therefore inherits the identity it had before. That is deliberate: the
	// alternative is releasing identifiers back to the pool, where the
	// allocator could hand one to any network at all. A Route Target still
	// installed in a remote location's import policy would then merge an
	// unrelated network into a dead one's routes. Inheritance is confined to
	// one namespace and one name; reissue is not confined to anything.
	NetworkNamespace string
	NetworkName      string
}

// maxClaimNameLength is the ceiling on an object name in Kubernetes, which is
// all an IPClaim name is.
const maxClaimNameLength = 253

// ClaimName is the name the request's claim is held under.
//
// The delimiter is a dot rather than a dash because a namespace is a DNS label
// and cannot contain one, so the first dot after the prefix always ends the
// namespace. A dash would be ambiguous: namespace "a-b" with name "c" and
// namespace "a" with name "b-c" would collide.
//
// Uniqueness rests on the API server refusing a namespace containing a dot. A
// network name may contain one, and that is fine: the split is taken at the
// first dot, which is always the namespace boundary.
func ClaimName(networkNamespace, networkName string) string {
	name := fmt.Sprintf("fabric-identity.%s.%s", networkNamespace, networkName)
	if len(name) <= maxClaimNameLength {
		return name
	}

	sum := sha256.Sum256([]byte(networkNamespace + "/" + networkName))
	suffix := "." + hex.EncodeToString(sum[:])[:16]
	return name[:maxClaimNameLength-len(suffix)] + suffix
}

// Claim holds one block of the identifier space and reads the identity out of
// it.
//
// IPAM binds on create and refuses a duplicate name, so the read comes first.
// That is what makes the allocation idempotent without this recording anything
// of its own: the claim is the record.
func Claim(ctx context.Context, ipamClient client.Client, request Request) (int64, error) {
	ipClaim := &ipamv1alpha1.IPClaim{}
	ipClaim.Namespace = request.Namespace
	ipClaim.Name = ClaimName(request.NetworkNamespace, request.NetworkName)
	ipClaim.Spec = ipamv1alpha1.IPClaimSpec{
		ClassName: request.ClassName,

		// The class already fixes the family, but the server bounds a claim's
		// prefix length from the family on the claim alone, before it resolves
		// the class at all. Left unset, a /64 is read as an IPv4 length and
		// refused, so every allocation fails.
		IPFamily: ipamv1alpha1.IPv6,

		Target:       ipamv1alpha1.TargetBlock,
		PrefixLength: ptr.To(int32(BlockBits)),

		// An identity is never given back. A Route Target still installed in a
		// remote location's import policy would silently merge a new network
		// into a dead one's routes, so holding the block forever is the safe
		// failure and reissuing it is not a failure anything can see.
		ReclaimPolicy: ipamv1alpha1.ReclaimRetain,
	}

	existing := &ipamv1alpha1.IPClaim{}
	getErr := ipamClient.Get(ctx, client.ObjectKeyFromObject(ipClaim), existing)
	if getErr != nil && !apierrors.IsNotFound(getErr) {
		return 0, fmt.Errorf("read the identity claim %q: %w", ipClaim.Name, getErr)
	}

	if getErr == nil {
		ipClaim = existing
	} else if createErr := ipamClient.Create(ctx, ipClaim); createErr != nil {
		// An allocation retained by an earlier claim of this name is this
		// network's own identity, kept precisely so it could not be handed to
		// another network. Adopt it rather than treating it as a failure.
		if allocationName, retained := ipamerrors.RetainedAllocation(createErr); retained {
			return adopt(ctx, ipamClient, request.Namespace, allocationName)
		}

		// The create can still lose a race with another writer, so ask again
		// before calling this a failure to allocate.
		raced := &ipamv1alpha1.IPClaim{}
		if err := ipamClient.Get(ctx, client.ObjectKeyFromObject(ipClaim), raced); err != nil {
			return 0, fmt.Errorf("claim a fabric identity: %w", createErr)
		}
		ipClaim = raced
	}

	if ipClaim.Status.AllocatedCIDR == "" {
		return 0, fmt.Errorf("the identity space allocated nothing for this network (phase %q)", ipClaim.Status.Phase)
	}

	return FromBlock(ipClaim.Status.AllocatedCIDR)
}

// adopt reads the identity out of an allocation this network already holds.
// The allocation outlives the claim that made it, which is what retention is
// for, so the block it names is the same one this network has always had.
func adopt(ctx context.Context, ipamClient client.Client, namespace, allocationName string) (int64, error) {
	allocation := &ipamv1alpha1.IPAllocation{}
	if err := ipamClient.Get(ctx,
		client.ObjectKey{Namespace: namespace, Name: allocationName}, allocation); err != nil {
		return 0, fmt.Errorf("read the retained allocation %q: %w", allocationName, err)
	}
	if allocation.Status.AllocatedCIDR == "" {
		return 0, fmt.Errorf("the retained allocation %q holds no block", allocationName)
	}
	return FromBlock(allocation.Status.AllocatedCIDR)
}

// FromBlock reads the identity out of the block the identifier space handed
// out. The block's index within the pool is the identity, and the index is the
// 32 bits between the pool's root and the block, which is exactly the width
// that survives into the Route Target.
func FromBlock(cidr string) (int64, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return 0, &UnusableError{message: fmt.Sprintf(
			"the identity space answered with %q, which is not a prefix", cidr)}
	}

	address := prefix.Addr()
	if !address.Is6() || address.Is4In6() {
		return 0, &UnusableError{message: fmt.Sprintf(
			"the identity space answered with %q; identifiers are read out of an IPv6 space", cidr)}
	}

	// Shorter than a /64 and two networks could be handed blocks that share an
	// index; longer and one block's index is not the whole of it.
	if prefix.Bits() != BlockBits {
		return 0, &UnusableError{message: fmt.Sprintf(
			"the identity space answered with %q; identifiers are read out of a /%d", cidr, BlockBits)}
	}

	octets := address.As16()
	identity := int64(binary.BigEndian.Uint32(octets[RootBits/8 : BlockBits/8]))
	if identity == 0 {
		return 0, &UnusableError{message: fmt.Sprintf(
			"the identity space answered with %q, whose index is zero; zero is what a network holding no identity reads as, so the pool must not hand out its first block", cidr)}
	}
	return identity, nil
}

// UnusableError says the identity space answered, and its answer cannot be
// turned into an identity. Retrying reaches the same block, so this is a wait
// on an operator rather than on the service.
type UnusableError struct {
	message string
}

func (e *UnusableError) Error() string { return e.message }
