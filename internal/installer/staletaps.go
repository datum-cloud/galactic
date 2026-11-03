// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	bgpv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
	"go.datum.net/galactic/internal/cni/tap"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/attachreg"
	"go.datum.net/galactic/internal/plumbing/ebpf/ifindexvrfmap"
	"go.datum.net/galactic/internal/plumbing/ebpf/metrics"
	"go.datum.net/galactic/internal/plumbing/intf"
	"go.datum.net/galactic/internal/plumbing/nldump"
	"go.datum.net/galactic/internal/plumbing/vrf"
)

// Removing tenant taps that outlived their attachment.
//
// A tap is deleted by its sandbox's CNI DEL, or by galactic-router's GC while
// the attachment's BGPAdvertisement still records the tap's dead container
// (internal/gc reclaimHostLinks). When the DEL never ran and the
// advertisement is gone too, nothing else looks at the tap again. It stays
// enslaved to its VPC's VRF with a route for a prefix no live attachment owns,
// keeps its traffic policy row with no binding, so every decision on it counts
// as an unattributed drop, and holds its ifindex and map rows for the node's
// lifetime.
//
// galactic-cni removes such a tap, together with the eBPF rows CNI DEL would
// have removed (attachreg.UnregisterInterface). Only a veth can share a
// host link's name, and a veth's host end goes with its peer's namespace, so
// only a tap can be left behind.
//
// A tap is a candidate only while all of these hold:
//   - its name is a tenant host link's and its alias carries an owner stamp
//     or a host-only port stamp, with or without an owner, so an ADD created
//     or adopted it;
//   - no file descriptor holds it, enabled or disabled queue alike, so no VMM
//     is using it;
//   - no BGPAdvertisement names its attachment, so the router's GC is not the
//     one to judge it;
//   - no VPCAttachment carries its (VPC, attachment) identity, so no workload
//     can be given it again, while the cluster lists at least one
//     VPCAttachment that does carry an identity.
//
// A candidate is removed only when the previous pass read every input and found it too, with the
// same ifindex and owner stamp. A workload's ADD can create its tap between
// this pass's reads, before its VMM opens the tap; by the next pass its
// VPCAttachment is listed or its VMM holds the tap. The removal decides again
// under the node's VRF lock, which every ADD holds while it creates, adopts and
// stamps a host link.

// staleTap is a tap one pass found to be a candidate.
type staleTap struct {
	name               string
	index              int
	alias              string
	vpc, vpcAttachment string
}

// staleTapReclaimer carries candidates from one pass to the next. The zero
// value is ready to use.
type staleTapReclaimer struct {
	mu      sync.Mutex
	pending map[string]staleTap
}

// staleTapPassResult counts one pass.
type staleTapPassResult struct {
	// Reclaimed is how many taps the pass removed.
	Reclaimed int
	// Pending is how many candidates await the next pass: first sightings,
	// and confirmed ones whose removal failed.
	Pending int
	// Complete is set when the pass read every link, advertisement and
	// attachment, so Pending is a full count.
	Complete bool
}

// The kernel, map and API calls a pass makes, indirected so unprivileged tests
// can substitute fabricated state.
var (
	staleTapListLinksFn  = nldump.LinkList
	staleTapLinkByNameFn = netlink.LinkByName
	staleTapVRFLockedFn  = vrf.Locked
	staleTapUnregisterFn = func(ifindex uint32) error { return attachreg.UnregisterInterface(attach.PinDir, ifindex) }
	staleTapDeleteFn     = tap.Delete
)

// errNoIdentifiedAttachments fails a pass that finds candidates while the
// cluster lists no VPCAttachment carrying an identity.
var errNoIdentifiedAttachments = errors.New(
	"no VPCAttachment in the cluster carries an identity; keeping every tap")

// reclaim runs one pass for nodeName, whose BGPAdvertisements are in
// namespace.
func (r *staleTapReclaimer) reclaim(
	ctx context.Context, k8s client.Client, namespace, nodeName string,
) (staleTapPassResult, error) {
	var result staleTapPassResult
	links, err := staleTapListLinksFn()
	if err != nil {
		return result, fmt.Errorf("list links: %w", err)
	}
	var found []staleTap
	for _, l := range links {
		if t, ok := detachedTenantTap(l); ok {
			found = append(found, t)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(found) == 0 {
		r.pending = nil
		result.Complete = true
		return result, nil
	}

	// A pass that cannot read its inputs removes nothing and forgets its
	// candidates, so a removal always follows two consecutive passes that read
	// everything.
	advertised, err := advertisedAttachments(ctx, k8s, namespace)
	if err != nil {
		r.pending = nil
		return result, err
	}
	var unadvertised []staleTap
	for _, t := range found {
		if !advertised(t.vpc, t.vpcAttachment) {
			unadvertised = append(unadvertised, t)
		}
	}
	if len(unadvertised) == 0 {
		r.pending = nil
		result.Complete = true
		return result, nil
	}
	attached, err := identifiedAttachments(ctx, k8s)
	if err != nil {
		r.pending = nil
		return result, err
	}
	if len(attached) == 0 {
		// A node with unadvertised tenant taps in a cluster with no
		// identified VPCAttachment at all says more about where attachments
		// are read from than about the taps, so it is not taken as proof.
		r.pending = nil
		return result, errNoIdentifiedAttachments
	}
	result.Complete = true

	next := map[string]staleTap{}
	var errs []error
	for _, t := range unadvertised {
		if _, ok := attached[attachmentKey(t.vpc, t.vpcAttachment)]; ok {
			continue
		}
		if prev, ok := r.pending[t.name]; !ok || prev != t {
			// First sighting, or the tap changed since: the next pass confirms.
			next[t.name] = t
			continue
		}
		removed, err := removeStaleTap(t, nodeName)
		if err != nil {
			errs = append(errs, err)
			next[t.name] = t
			continue
		}
		if removed {
			result.Reclaimed++
		}
	}
	r.pending = next
	result.Pending = len(next)
	return result, errors.Join(errs...)
}

// detachedTenantTap reports l as a candidate when it is a stamped tenant tap
// no file descriptor holds.
func detachedTenantTap(l netlink.Link) (staleTap, bool) {
	tt, ok := l.(*netlink.Tuntap)
	if !ok || tt.Mode != netlink.TUNTAP_MODE_TAP || tt.Queues != 0 || tt.DisabledQueues != 0 {
		return staleTap{}, false
	}
	attrs := l.Attrs()
	vpc, vpcAttachment, ok := intf.ParseInterfaceNameHost(attrs.Name)
	if !ok || !stampedByADD(attrs.Alias) {
		return staleTap{}, false
	}
	return staleTap{name: attrs.Name, index: attrs.Index, alias: attrs.Alias,
		vpc: vpc, vpcAttachment: vpcAttachment}, true
}

// stampedByADD reports whether alias is an owner, or a well-formed host-only
// port stamp with or without one.
func stampedByADD(alias string) bool {
	if ifindexvrfmap.AliasOwner(alias) != "" {
		return true
	}
	_, hostOnly, err := ifindexvrfmap.ParseHostOnlyAlias(alias)
	return hostOnly && err == nil
}

// removeStaleTap removes t's eBPF interface rows and then t itself, under the
// VRF lock, after confirming it is still the same detached tap. It reports
// whether t was removed; a tap that is gone or has changed is left alone. The
// rows go first, since nothing resolves the ifindex once the tap is gone, and
// a failure to remove them keeps the tap for the next pass to retry.
func removeStaleTap(t staleTap, nodeName string) (bool, error) {
	var removed bool
	err := staleTapVRFLockedFn(func() error {
		cur, err := staleTapLinkByNameFn(t.name)
		if err != nil {
			var notFound netlink.LinkNotFoundError
			if errors.As(err, &notFound) {
				return nil
			}
			return fmt.Errorf("find tap %q: %w", t.name, err)
		}
		if again, ok := detachedTenantTap(cur); !ok || again != t {
			slog.Info("Kept a stale tap candidate that changed since it was listed",
				"name", t.name, "owner", cur.Attrs().Alias)
			return nil
		}
		if err := staleTapUnregisterFn(uint32(t.index)); err != nil { //nolint:gosec // a kernel ifindex
			return fmt.Errorf("remove eBPF state of tap %q: %w", t.name, err)
		}
		if err := staleTapDeleteFn(t.vpc, t.vpcAttachment, ifindexvrfmap.AliasOwner(t.alias)); err != nil {
			return fmt.Errorf("delete tap %q: %w", t.name, err)
		}
		removed = true
		return nil
	})
	if removed {
		slog.Info("Removed a tenant tap that outlived its VPCAttachment and BGPAdvertisement",
			"name", t.name, "ifindex", t.index, "owner", ifindexvrfmap.AliasOwner(t.alias),
			"vpc", t.vpc, "vpcAttachment", t.vpcAttachment, "node", nodeName)
	}
	return removed, err
}

// advertisedAttachments lists every BGPAdvertisement in namespace and returns
// a test for whether any of them, on any node and under either name form,
// names (vpc, vpcAttachment).
func advertisedAttachments(
	ctx context.Context, k8s client.Client, namespace string,
) (func(vpc, vpcAttachment string) bool, error) {
	list := &bgpv1alpha1.BGPAdvertisementList{}
	if err := k8s.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPAdvertisements: %w", err)
	}
	names := make([]string, 0, len(list.Items))
	for _, adv := range list.Items {
		names = append(names, adv.Name)
	}
	return func(vpc, vpcAttachment string) bool {
		// The current form encodes both segments; names written before that
		// encoding carry the raw base62 values.
		prefixes := []string{crdnames.BGPAdvertisementName(vpc, vpcAttachment, ""), vpc + "-" + vpcAttachment + "-"}
		for _, name := range names {
			for _, p := range prefixes {
				if strings.HasPrefix(name, p) {
					return true
				}
			}
		}
		return false
	}, nil
}

// identifiedAttachments returns the (VPC, attachment) identity of every
// VPCAttachment in the cluster whose status carries one. An attachment without
// one cannot have been given to a workload yet, since its network definition
// is built from that identity.
func identifiedAttachments(ctx context.Context, k8s client.Client) (map[string]struct{}, error) {
	list := &cloudv1alpha1.VPCAttachmentList{}
	if err := k8s.List(ctx, list); err != nil {
		return nil, fmt.Errorf("list VPCAttachments: %w", err)
	}
	keys := make(map[string]struct{}, len(list.Items))
	for _, a := range list.Items {
		if a.Status.VPC == "" || a.Status.VPCAttachment == "" {
			continue
		}
		keys[attachmentKey(a.Status.VPC, a.Status.VPCAttachment)] = struct{}{}
	}
	return keys, nil
}

// attachmentKey is the comparable form of a base62 (VPC, attachment) pair.
// Interface names zero-pad each identifier and the API does not, so leading
// zeros are dropped.
func attachmentKey(vpc, vpcAttachment string) string {
	return unpadBase62(vpc) + "/" + unpadBase62(vpcAttachment)
}

func unpadBase62(s string) string {
	if t := strings.TrimLeft(s, "0"); t != "" {
		return t
	}
	return "0"
}

// runStaleTapReclaim runs one pass and records it in m. Each removal is
// logged; this adds a line only for a pass that failed.
func runStaleTapReclaim(
	ctx context.Context, r *staleTapReclaimer, k8s client.Client, namespace, nodeName string, m *metrics.HostLinks,
) {
	result, err := r.reclaim(ctx, k8s, namespace, nodeName)
	m.StaleTapPass(result.Reclaimed, result.Pending, result.Complete, err != nil)
	if err != nil {
		slog.Error("Stale tap reclaim failed; a tap that outlived its attachment may remain",
			"reclaimed", result.Reclaimed, "pending", result.Pending, "err", err)
	}
}

// startStaleTapReclaim runs one runStaleTapReclaim pass off Run's goroutine,
// unless a pass already holds sem, in which case that pass covers this tick. A
// pass waits for the node's VRF lock and gets one GC tick interval.
func startStaleTapReclaim(
	ctx context.Context, sem chan struct{}, r *staleTapReclaimer, st ebpfDatapathState, m *metrics.HostLinks,
) {
	if r == nil || st.k8sClient == nil {
		return
	}
	select {
	case sem <- struct{}{}:
		go func() {
			defer func() { <-sem }()
			passCtx, cancel := context.WithTimeout(ctx, ebpfGCSweepInterval)
			defer cancel()
			runStaleTapReclaim(passCtx, r, st.k8sClient, st.namespace, st.nodeName, m)
		}()
	default:
	}
}
