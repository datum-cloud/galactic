// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/sidecarmap"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// Removing what a deleted ingress sidecar pod leaves behind.
//
// The sidecar deliberately leaves its state in place when it exits, so a
// restarted container finds it still serving. A deleted pod takes its network
// namespace with it but leaves two things the host can see: its gateway
// advertisements, and its rows in the node's shared eBPF maps (see
// internal/plumbing/ebpf/sidecarmap). A replacement pod overwrites only what it
// serves again, and on a node no sidecar returns to, nothing overwrites
// anything.
//
// Each advertisement records the host-side end of the pod's primary interface.
// That interface is deleted with the pod, which makes it the host's evidence
// that the sidecar is gone: no other host-visible object carries the pod's
// lifetime, and the host cannot enter the pod's namespace to look (see the
// package comment in sidecarreturn.go).

// sidecarLiveness is what the host can tell about the sidecar that published
// one advertisement.
type sidecarLiveness int

const (
	// sidecarLivenessUnknown covers an advertisement with no usable entry
	// point recorded, and an interface lookup that failed for any reason but
	// absence. Treated as live: nothing is removed on a guess.
	sidecarLivenessUnknown sidecarLiveness = iota
	sidecarLivenessLive
	sidecarLivenessGone
)

// ingressAdvertisement is one of this node's sidecar gateway advertisements,
// with what deleting it safely needs and the liveness of its publisher.
type ingressAdvertisement struct {
	name            string
	uid             types.UID
	resourceVersion string
	liveness        sidecarLiveness
}

// sidecarReapPlan is what one pass removes.
type sidecarReapPlan struct {
	// gone are the advertisements whose sidecar pod is gone.
	gone []ingressAdvertisement
	// sidecarGone is true when every advertisement on this node is gone, so
	// no sidecar on it is live and every sidecar row in the shared maps is a
	// leftover.
	sidecarGone bool
}

// planSidecarReap decides what to remove from this node's ingress
// advertisements.
//
// A gone advertisement is always removed, even beside a live one: a pod that
// has been replaced leaves behind the advertisements of every VPC its
// replacement does not serve.
//
// The map rows are judged for the node as a whole, because nothing in them
// links a row to an advertisement. The sidecar keys its rows on its pod-netns
// table ID and its advertisements on the BGPVRFInstance VRFID, which are
// different numbers for the same VPC. So the rows are leftovers only when no
// advertisement is live or unknown. With no advertisements at all there is no
// evidence either way, as on a node whose sidecar publishes none, and they are
// kept.
func planSidecarReap(advs []ingressAdvertisement) sidecarReapPlan {
	var plan sidecarReapPlan
	for _, a := range advs {
		if a.liveness == sidecarLivenessGone {
			plan.gone = append(plan.gone, a)
		}
	}
	plan.sidecarGone = len(plan.gone) > 0 && len(plan.gone) == len(advs)
	return plan
}

// fingerprint identifies the exact set of gone advertisements, by object
// identity and version, so two passes can tell whether they saw the same one.
func (p sidecarReapPlan) fingerprint() string {
	keys := make([]string, 0, len(p.gone))
	for _, a := range p.gone {
		keys = append(keys, string(a.uid)+"/"+a.resourceVersion)
	}
	slices.Sort(keys)
	return strings.Join(keys, ",")
}

// sidecarReaper removes a deleted sidecar pod's advertisements and map rows.
// The zero value is ready to use.
type sidecarReaper struct {
	mu sync.Mutex
	// pendingRows is the fingerprint of the previous pass's plan when that
	// plan found the whole sidecar gone, and "" otherwise.
	pendingRows string
}

// hostLinkByIndexFn and pruneSidecarRowsFn indirect the netlink lookup and the
// pinned-map writes reap makes, so tests need neither a real interface nor a
// loaded datapath.
var (
	hostLinkByIndexFn  = netlink.LinkByIndex
	pruneSidecarRowsFn = func() (int, error) { return pruneAllSidecarRows(attach.PinDir) }
)

// reap runs one pass. Advertisements whose sidecar is gone are deleted at once.
// The map rows are removed only once two passes in a row find the whole
// sidecar gone, with the same advertisements at the same versions.
//
// The second pass is what makes removing rows safe while a replacement pod
// starts. That pod writes its rows first and then republishes each
// advertisement with its own interface, so a single pass can land between the
// two and see only the old pod's interface. By the next pass the republish has
// changed the advertisement, and the fingerprint with it.
//
// The rows are removed before the advertisements, because deleting the
// advertisements removes the evidence: if the prune fails, the next pass sees
// the same plan and retries.
func (r *sidecarReaper) reap(ctx context.Context, k8s client.Client, namespace, nodeName string) error {
	advs, err := ingressAdvertisements(ctx, k8s, namespace, nodeName)
	if err != nil {
		return err
	}
	plan := planSidecarReap(advs)

	r.mu.Lock()
	defer r.mu.Unlock()

	gone := plan.gone
	if plan.sidecarGone {
		fp := plan.fingerprint()
		if r.pendingRows != fp {
			// First sighting. Keep the advertisements as the evidence the
			// next pass confirms against.
			r.pendingRows = fp
			return nil
		}
		removed, err := pruneSidecarRowsFn()
		if err != nil {
			return fmt.Errorf("remove a deleted ingress sidecar's eBPF map rows: %w", err)
		}
		if removed > 0 {
			slog.Info("Removed a deleted ingress sidecar's rows from the shared eBPF maps", "removed", removed)
		}
	}
	r.pendingRows = ""

	var errs []error
	for _, a := range gone {
		if err := deleteIngressAdvertisement(ctx, k8s, namespace, a); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ingressAdvertisements returns this node's sidecar gateway advertisements
// with the liveness of the pod that published each. Selected the same way
// sidecarGatewayEndpoints selects them, but keeping the ones it skips, since
// an advertisement with no usable entry point still counts as unknown.
func ingressAdvertisements(
	ctx context.Context, k8s client.Client, namespace, nodeName string,
) ([]ingressAdvertisement, error) {
	list := &bgpv1alpha1.BGPAdvertisementList{}
	if err := k8s.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list BGPAdvertisements in namespace %s: %w", namespace, err)
	}

	segment := crdnames.IngressAdvertisementSegment()
	var out []ingressAdvertisement
	for i := range list.Items {
		a := &list.Items[i]
		if a.Spec.RouterRef.Name != nodeName || !isIngressAdvertisementName(a.Name, nodeName, segment) {
			continue
		}
		out = append(out, ingressAdvertisement{
			name:            a.Name,
			uid:             a.UID,
			resourceVersion: a.ResourceVersion,
			liveness:        sidecarLivenessOf(a.Annotations),
		})
	}
	return out, nil
}

// sidecarLivenessOf reads the host-side interface an advertisement records and
// reports whether it still exists.
//
// Only a veth counts as the pod's interface. The kernel hands out interface
// indexes in increasing order and reuses one only after wrapping, so an index
// that now names some other kind of link has been reused, and the pod is gone.
func sidecarLivenessOf(annotations map[string]string) sidecarLiveness {
	ifindex, _, ok := ingressEntryPointAnnotations(annotations)
	if !ok {
		return sidecarLivenessUnknown
	}
	link, err := hostLinkByIndexFn(ifindex)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return sidecarLivenessGone
		}
		slog.Debug("Could not look up an ingress sidecar's host-side interface", "ifindex", ifindex, "err", err)
		return sidecarLivenessUnknown
	}
	if link.Type() != "veth" {
		return sidecarLivenessGone
	}
	return sidecarLivenessLive
}

// deleteIngressAdvertisement deletes a only if it is still the object this
// pass judged. A sidecar republishing it in the meantime has changed its
// version, and the delete then fails its precondition and leaves it alone.
func deleteIngressAdvertisement(
	ctx context.Context, k8s client.Client, namespace string, a ingressAdvertisement,
) error {
	adv := &bgpv1alpha1.BGPAdvertisement{}
	adv.Name = a.name
	adv.Namespace = namespace
	err := k8s.Delete(ctx, adv, client.Preconditions{UID: &a.uid, ResourceVersion: &a.resourceVersion})
	switch {
	case err == nil:
		slog.Info("Deleted the gateway advertisement of a deleted ingress sidecar pod", "advertisement", a.name)
		return nil
	case apierrors.IsNotFound(err), apierrors.IsConflict(err):
		return nil
	default:
		return fmt.Errorf("delete gateway advertisement %s: %w", a.name, err)
	}
}

// pruneAllSidecarRows removes every ingress sidecar row from the shared eBPF
// maps pinned under pinDir. A datapath that is not loaded has no rows to
// remove.
func pruneAllSidecarRows(pinDir string) (int, error) {
	maps, closer, err := sidecarmap.OpenPinned(pinDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	defer func() { _ = closer.Close() }()

	result, err := sidecarmap.Prune(maps, nil)
	return result.Total(), err
}
